"""Qt worker base: runs a service call on QThreadPool, never on the GUI thread."""

from __future__ import annotations

import threading
import traceback
from typing import Callable

from PySide6.QtCore import QObject, QRunnable, Signal

from utils.errors import WezCryptError
from utils.friendly import describe_error
from utils.logging import log_event


class WorkerSignals(QObject):
    progress = Signal(str, object, object)   # stage, done, total (64-bit safe)
    finished = Signal(object)                # result object
    failed = Signal(str, str)                # user message, error category


class TaskWorker(QRunnable):
    """Runs ``fn(progress=..., cancel=...)`` in a pool thread.

    Errors are converted to safe user-facing messages; unexpected exceptions
    are logged by category only (no tracebacks containing data in the UI).
    """

    def __init__(self, fn: Callable[..., object], operation: str) -> None:
        super().__init__()
        self.fn = fn
        self.operation = operation
        self.signals = WorkerSignals()
        self.cancel_event = threading.Event()
        self.setAutoDelete(True)

    def cancel(self) -> None:
        self.cancel_event.set()

    def _progress(self, stage: str, done: int, total: int) -> None:
        self.signals.progress.emit(stage, done, total)

    def run(self) -> None:
        try:
            result = self.fn(progress=self._progress, cancel=self.cancel_event)
        except WezCryptError as exc:
            self.signals.failed.emit(str(exc), exc.error_category)
        except Exception as exc:  # translated for users; no traceback in dialogs
            message, category = describe_error(exc)
            log_event(self.operation, status="failed", error_category=category,
                      detail=type(exc).__name__)
            if category == "unexpected":
                traceback.print_exc()  # stderr only (no console in the packaged app)
            self.signals.failed.emit(message, category)
        else:
            self.signals.finished.emit(result)
