"""CODEVANTA analysis core: loader, disassembler, strings, functions."""

from .disassembler import Disassembler, DisassemblyError, DisassemblyResult
from .functions import FunctionCandidate, discover_functions
from .loader import (
    BinaryInfo,
    BinaryLoader,
    BinaryLoadError,
    ExportInfo,
    ImportInfo,
    SectionInfo,
    SymbolInfo,
)
from .strings import StringExtractor, StringResult

__all__ = [
    "BinaryInfo",
    "BinaryLoader",
    "BinaryLoadError",
    "Disassembler",
    "DisassemblyError",
    "DisassemblyResult",
    "ExportInfo",
    "FunctionCandidate",
    "ImportInfo",
    "SectionInfo",
    "StringExtractor",
    "StringResult",
    "SymbolInfo",
    "discover_functions",
]
