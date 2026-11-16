"""The verified close contract of the Frida bridge handle.

Scripts unload first, the session detaches second, and a spawned target that
never ran is resumed last -- close may not strand a paused process. An
attached target is already running and is never resumed by close. Every
step's failure lands in the returned report instead of being swallowed.
"""

from __future__ import annotations

from typing import Any

from codevanta.analysis.frida_bridge import FridaSession


class _FakeScript:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.unloads = 0

    def unload(self) -> None:
        self.unloads += 1
        if self.fail:
            raise RuntimeError("script is gone")


class _FakeSession:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.detaches = 0

    def detach(self) -> None:
        self.detaches += 1
        if self.fail:
            raise RuntimeError("already detached")


class _FakeDevice:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.resumed: list[int] = []

    def resume(self, pid: int) -> None:
        self.resumed.append(pid)
        if self.fail:
            raise RuntimeError("process exited meanwhile")


def _handle(
    *,
    spawned_pid: int | None,
    script: Any = None,
    session_fail: bool = False,
    device: Any = None,
) -> tuple[FridaSession, _FakeSession, _FakeDevice | None]:
    frida_session = _FakeSession(fail=session_fail)
    real_device = device if device is not None else _FakeDevice()
    handle = FridaSession(
        target=spawned_pid if spawned_pid is not None else 1234,
        mode="spawn" if spawned_pid is not None else "attach",
        device_id=None,
        module_device=real_device,
        module_session=frida_session,
        spawned_pid=spawned_pid,
    )
    handle._script = script
    return handle, frida_session, real_device


def _load_script(handle: FridaSession, script: Any) -> None:
    handle._script = script


def test_close_resumes_a_still_paused_spawned_target() -> None:
    handle, session, device = _handle(spawned_pid=42)
    script = _FakeScript()
    _load_script(handle, script)

    report = handle.close()

    assert script.unloads == 1
    assert session.detaches == 1
    assert device is not None and device.resumed == [42]
    assert report["unloaded"] is True
    assert report["detached"] is True
    assert report["resumed_spawn"] is True
    assert report["warnings"] == []


def test_close_never_resumes_an_attached_target() -> None:
    handle, session, device = _handle(spawned_pid=None)
    _load_script(handle, _FakeScript())

    report = handle.close()

    assert device is not None and device.resumed == []
    assert report["resumed_spawn"] is False
    assert "already running" in report["note"]


def test_close_records_step_failures_instead_of_swallowing() -> None:
    handle, _, _ = _handle(spawned_pid=7, session_fail=True)
    _load_script(handle, _FakeScript(fail=True))
    failing_device = _FakeDevice(fail=True)
    handle._device = failing_device

    report = handle.close()

    assert report["unloaded"] is False
    assert report["detached"] is False
    assert report["resumed_spawn"] is False
    assert any("script unload failed" in warning for warning in report["warnings"])
    assert any("session detach failed" in warning for warning in report["warnings"])
    assert any("resuming the paused spawned pid 7 failed" in w for w in report["warnings"])


def test_close_is_idempotent_and_reports_the_same_outcome() -> None:
    handle, _, _ = _handle(spawned_pid=9)
    _load_script(handle, _FakeScript())

    first = handle.close()
    second = handle.close()

    assert second == first


def test_close_of_a_resumed_spawn_does_not_resume_again() -> None:
    handle, _, device = _handle(spawned_pid=5)
    handle.resumed = True

    report = handle.close()

    assert device is not None and device.resumed == []
    assert report["resumed_spawn"] is False
