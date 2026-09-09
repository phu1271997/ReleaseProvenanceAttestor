"""Windows compatibility for GenLayer Test Direct Mode stdin injection."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


_MESSAGE_FILES: list[Path] = []


def _windows_message_injector(vm) -> None:
    from genlayer.py import calldata
    from genlayer.py.types import Address

    def address(value):
        return Address(value) if isinstance(value, bytes) else value

    message_data = {
        "contract_address": address(vm._contract_address),
        "sender_address": address(vm.sender),
        "origin_address": address(vm.origin),
        "stack": [],
        "value": vm._value,
        "datetime": vm._datetime,
        "is_init": False,
        "chain_id": vm._chain_id,
        "entry_kind": 0,
        "entry_data": b"",
        "entry_stage_data": None,
    }
    fd, raw_path = tempfile.mkstemp(prefix="gltest-direct-")
    path = Path(raw_path)
    _MESSAGE_FILES.append(path)
    os.write(fd, calldata.encode(message_data))
    os.lseek(fd, 0, os.SEEK_SET)
    vm._original_stdin_fd = os.dup(0)
    os.dup2(fd, 0)
    os.close(fd)


def pytest_configure() -> None:
    if sys.platform == "win32":
        from gltest.direct import loader
        loader._inject_message_to_fd0 = _windows_message_injector


def pytest_sessionfinish() -> None:
    for path in _MESSAGE_FILES:
        try:
            path.unlink(missing_ok=True)
        except PermissionError:
            pass
