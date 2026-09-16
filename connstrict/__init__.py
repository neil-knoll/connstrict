"""connstrict: strict-by-default parsing and validation for connection strings."""

from .parser import ConnectionString, ConnectionStringError, diff, parse

__all__ = ["ConnectionString", "ConnectionStringError", "diff", "parse"]
__version__ = "0.1.0"
