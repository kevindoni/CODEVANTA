# CODEVANTA Desktop — proposal & mockups

Status: **DESIGN** (belum diimplementasi). Mockup: [`mockup-dashboard.png`](mockup-dashboard.png), [`mockup-compare.png`](mockup-compare.png) (sumber HTML disertakan).

## Kenapa bisa cepat

Semua yang dibutuhkan aplikasi desktop sudah ada: dashboard loopback dengan 20
route JSON, 55 tool MCP, session store, dan bridge report. Shell desktop cukup
membungkusnya dalam jendela native — tanpa menulis ulang UI.

## Opsi yang direkomendasikan: pywebview

```
pip install pywebview
codevanta desktop   # perintah baru: nyalakan server loopback + jendela pywebview
```

- Window native (Edge WebView2 di Windows) menampilkan dashboard yang sudah ada.
- Offline penuh, satu dependensi kecil, UX = dashboard hari ini dalam frame aplikasi.
- Titik penyuluhan: ikon tray, dialog open-file native, auto-pilih port bebas.

## Alternatif

| Opsi | Plus | Minus |
|------|------|-------|
| PySide6 (native) | Widget asli, menu/menu bar OS | UI ditulis ulang dari nol |
| Tauri/Electron | Ekosistem frontend | Bundle besar, dua bahasa |

## Cakupan implementasi yang disarankan (phase 13)

1. `codevanta desktop` command (pywebview + server loopback yang sudah ada).
2. Menu native: Open HAR/metadata/session; drag-and-drop file ke jendela.
3. Route GUI tambahan: /live (frida/lldb/rizin), /desktop-status.
4. Packaging: PyInstaller one-file + ikon; release sebagai artefak GitHub Release.

Mockup adalah desain target; layout mengikuti token visual dashboard yang ada
(`#0b0d14` latar, aksen `#7aa2f7`, monospace untuk data).
