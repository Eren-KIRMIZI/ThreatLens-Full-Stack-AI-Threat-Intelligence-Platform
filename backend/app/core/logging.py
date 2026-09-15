"""Structured, production-friendly logging configuration."""

import logging
import sys

_configured = False

DEFAULT_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

_NAME_TO_LEVEL = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
}


class StructuredLogger(logging.Logger):
    """Logger whose keyword context is rendered onto the message line.

    Enables call sites such as ``logger.error("event", code=..., path=...)``
    without raising, mirroring structlog's key=value style on the stdlib.
    """

    def _log(
        self,
        level: int,
        msg: object,
        args: tuple,
        exc_info: bool | BaseException | None = None,
        extra: dict | None = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        **context: object,
    ) -> None:
        if context:
            rendered = " ".join(f"{key}={value}" for key, value in context.items())
            msg = f"{msg} | {rendered}"
        super()._log(
            level,
            msg,
            args,
            exc_info=exc_info,
            extra=extra,
            stack_info=stack_info,
            stacklevel=stacklevel,
        )


# Register globally before any application logger is created.
logging.setLoggerClass(StructuredLogger)


def setup_logging(log_level: str = "INFO") -> None:
    """Configure the root logger once.

    Uses a single structured stream handler writing to stdout.
    Third-party noise (uvicorn access logs) is muted by default.
    """
    global _configured
    if _configured:
        return
    _configured = True

    level = _NAME_TO_LEVEL.get(log_level.upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(fmt=DEFAULT_FORMAT, datefmt="%Y-%m-%dT%H:%M:%S%z"))
    root.addHandler(handler)

    # Keep uvicorn's per-request access logs quiet unless explicitly raised.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a structured (depth 1) module-scoped logger."""
    return logging.getLogger(name)