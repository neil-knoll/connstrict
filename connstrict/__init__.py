"""connstrict: strict-by-default parsing and validation for connection strings."""

from .parser import ConnectionString, ConnectionStringError, parse

__all__ = ["ConnectionString", "ConnectionStringError", "parse"]
__version__ = "0.1.0"
