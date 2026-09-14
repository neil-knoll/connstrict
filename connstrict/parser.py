"""Strict-by-default parsing and validation for database connection strings.

Most connection string parsers (including the standard library's urlsplit)
are permissive: an unescaped '@' in a password, a duplicate query parameter,
or stray whitespace from a copy-paste all get silently accepted, and the
resulting host/user/param the caller ends up with is often not the one they
meant. This module treats all of that as an error unless the caller opts
into `lenient=True`, in which case the same issues become warnings and the
parser recovers with the same heuristic a permissive parser would use.
"""

from __future__ import annotations

import dataclasses
from urllib.parse import quote, unquote

KNOWN_SCHEMES = {
    "postgres",
    "postgresql",
    "mysql",
    "mongodb",
    "mongodb+srv",
    "redis",
    "rediss",
    "amqp",
    "amqps",
    "sqlserver",
}

# Characters that must be percent-encoded inside a username or password,
# because the parser also uses them as structural separators.
RESERVED_USERINFO_CHARS = set(":/?#[]@")

# Params that are conventionally required for a given scheme because leaving
# them off means driver-default behavior that's silently wrong for
# production use, not because the driver itself demands them.
REQUIRED_PARAMS: dict[str, tuple[str, ...]] = {
    "postgres": ("sslmode",),
    "postgresql": ("sslmode",),
}


class ConnectionStringError(ValueError):
    """Raised when a connection string fails validation."""

    def __init__(self, issues: list[str]) -> None:
        self.issues = list(issues)
        super().__init__("; ".join(self.issues))


@dataclasses.dataclass
class ConnectionString:
    scheme: str
    username: str | None
    password: str | None
    host: str
    port: int | None
    database: str | None
    params: dict[str, str]
    raw: str
    warnings: list[str] = dataclasses.field(default_factory=list)

    def normalized(self) -> str:
        """Rebuild a canonical, correctly percent-encoded connection string."""
        authority = ""
        if self.username is not None:
            authority += quote(self.username, safe="")
            if self.password is not None:
                authority += ":" + quote(self.password, safe="")
            authority += "@"

        host = self.host
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        authority += host

        if self.port is not None:
            authority += f":{self.port}"

        path = f"/{quote(self.database, safe='')}" if self.database else ""

        query = ""
        if self.params:
            query = "?" + "&".join(
                f"{quote(k, safe='')}={quote(v, safe='')}"
                for k, v in self.params.items()
            )

        return f"{self.scheme}://{authority}{path}{query}"


def _fatal(issues: list[str], message: str) -> None:
    raise ConnectionStringError(issues + [message])


def parse(raw: str, *, lenient: bool = False) -> ConnectionString:
    """Parse and validate a connection string.

    Every irregularity found (unescaped separators, duplicate query keys,
    stray whitespace, an unrecognized scheme, ...) is collected. If the
    string parses at all, `lenient=False` (the default) turns that list
    into a raised ConnectionStringError; `lenient=True` recovers the same
    way a permissive parser would and reports the list as `.warnings`.
    A handful of things (no scheme, no host) can't be recovered from and
    always raise, regardless of `lenient`.
    """
    issues: list[str] = []
    text = raw

    if text != text.strip():
        issues.append("connection string has leading or trailing whitespace")
        text = text.strip()

    if "://" not in text:
        _fatal(issues, "missing '://' scheme separator")

    scheme, _, rest = text.partition("://")
    scheme = scheme.lower()
    if scheme not in KNOWN_SCHEMES:
        issues.append(f"unrecognized scheme '{scheme}'")

    authority_end = len(rest)
    for sep in ("/", "?", "#"):
        idx = rest.find(sep)
        if idx != -1:
            authority_end = min(authority_end, idx)
    authority = rest[:authority_end]
    tail = rest[authority_end:]

    at_count = authority.count("@")
    if at_count == 0:
        userinfo, hostport = None, authority
    else:
        if at_count > 1:
            issues.append(
                "authority contains multiple unescaped '@' characters; "
                "percent-encode the one in the password as %40"
            )
        userinfo, _, hostport = authority.rpartition("@")

    username = password = None
    if userinfo is not None:
        if ":" in userinfo:
            username_raw, _, password_raw = userinfo.partition(":")
        else:
            username_raw, password_raw = userinfo, None

        for label, value in (("username", username_raw), ("password", password_raw)):
            if value is None:
                continue
            for ch in value:
                if ch in RESERVED_USERINFO_CHARS:
                    issues.append(
                        f"{label} contains an unescaped '{ch}' character; "
                        f"percent-encode it as %{ord(ch):02X}"
                    )
                    break

        username = unquote(username_raw)
        password = unquote(password_raw) if password_raw is not None else None

    if hostport.startswith("["):
        end = hostport.find("]")
        if end == -1:
            _fatal(issues, "unterminated IPv6 address literal in host")
        host = hostport[1:end]
        remainder = hostport[end + 1 :]
        if remainder.startswith(":"):
            port_str: str | None = remainder[1:]
        elif remainder == "":
            port_str = None
        else:
            _fatal(issues, "unexpected characters after IPv6 host literal")
    elif ":" in hostport:
        host, _, port_str = hostport.rpartition(":")
    else:
        host, port_str = hostport, None

    if not host:
        _fatal(issues, "connection string is missing a host")

    port: int | None = None
    if port_str:
        if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
            issues.append(f"port '{port_str}' is not a valid port number 1-65535")
        else:
            port = int(port_str)

    fragment: str | None = None
    path_part = tail
    hash_idx = path_part.find("#")
    if hash_idx != -1:
        fragment = path_part[hash_idx + 1 :]
        path_part = path_part[:hash_idx]

    query_part: str | None = None
    q_idx = path_part.find("?")
    if q_idx != -1:
        query_part = path_part[q_idx + 1 :]
        path_part = path_part[:q_idx]

    if fragment is not None:
        issues.append("connection string contains a '#' fragment, which most drivers ignore")

    database: str | None = None
    if path_part not in ("", "/"):
        segment = path_part[1:] if path_part.startswith("/") else path_part
        if "/" in segment:
            issues.append("database path contains an extra '/' segment")
        database = unquote(segment)

    params: dict[str, str] = {}
    if query_part:
        for pair in query_part.split("&"):
            if pair == "":
                issues.append("query string has an empty parameter (stray '&')")
                continue
            key, sep, value = pair.partition("=")
            if sep == "":
                issues.append(f"query parameter '{pair}' has no '=value'")
            key = unquote(key)
            value = unquote(value)
            if key in params:
                issues.append(f"duplicate query parameter '{key}'")
            params[key] = value

    for required in REQUIRED_PARAMS.get(scheme, ()):
        if required not in params:
            issues.append(
                f"scheme '{scheme}' requires a '{required}' parameter, "
                "since without one drivers silently fall back to an insecure default"
            )

    if issues and not lenient:
        raise ConnectionStringError(issues)

    return ConnectionString(
        scheme=scheme,
        username=username,
        password=password,
        host=host,
        port=port,
        database=database,
        params=params,
        raw=raw,
        warnings=issues,
    )
