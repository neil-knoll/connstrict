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
    advisories: list[str] = dataclasses.field(default_factory=list)
    style: str = "url"

    def _normalized_keyvalue(self) -> str:
        def quoted(value: str) -> str:
            # Always quoting is unambiguous for both ADO.NET and ODBC readers,
            # and avoids guessing which characters each one treats as special.
            return '"' + value.replace('"', '""') + '"'

        server = self.host if self.port is None else f"{self.host},{self.port}"
        parts = [("Server", server)]
        if self.database:
            parts.append(("Database", self.database))
        if self.username is not None:
            parts.append(("User ID", self.username))
        if self.password is not None:
            parts.append(("Password", self.password))
        parts.extend(self.params.items())
        return ";".join(f"{k}={quoted(v)}" for k, v in parts)

    def normalized(self) -> str:
        """Rebuild a canonical, correctly percent-encoded connection string."""
        if self.style == "keyvalue":
            return self._normalized_keyvalue()

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


def diff(a: ConnectionString, b: ConnectionString) -> list[str]:
    """Describe every field where two parsed connection strings disagree.

    Compares the parsed fields rather than the raw text, so cosmetic
    differences like percent-encoding, param order, or a trailing slash
    don't show up as drift - only changes that would actually change what
    a driver connects to or with.
    """
    lines: list[str] = []

    def note(field: str, left: object, right: object) -> None:
        if left != right:
            lines.append(f"{field}: {left!r} -> {right!r}")

    note("scheme", a.scheme, b.scheme)
    note("username", a.username, b.username)
    note("password", a.password, b.password)
    note("host", a.host, b.host)
    note("port", a.port, b.port)
    note("database", a.database, b.database)

    for key in sorted(set(a.params) | set(b.params)):
        left = a.params.get(key)
        right = b.params.get(key)
        if left == right:
            continue
        left_repr = repr(left) if key in a.params else "(absent)"
        right_repr = repr(right) if key in b.params else "(absent)"
        lines.append(f"param '{key}': {left_repr} -> {right_repr}")

    return lines


def _fatal(issues: list[str], message: str) -> None:
    raise ConnectionStringError(issues + [message])


def _looks_like_env_reference(value: str) -> bool:
    """Whether a value is a placeholder pointing at an env var, not a secret.

    Covers the styles people actually paste into connection strings:
    ``${DB_PASSWORD}`` and ``$DB_PASSWORD`` (shell/docker-compose) and
    ``<DB_PASSWORD>`` (generic template). Deliberately skips Windows-style
    ``%DB_PASSWORD%``: '%' is already percent-encoding syntax in this parser,
    so a literal '%' in userinfo has already been mangled by `unquote` by
    the time this check runs, making that style unreliable to detect here.
    """
    if value.startswith("${") and value.endswith("}"):
        return True
    if value.startswith("<") and value.endswith(">") and len(value) > 2:
        return True
    if value.startswith("$"):
        name = value[1:]
        return bool(name) and all(ch.isalnum() or ch == "_" for ch in name)
    return False


def _check_port(port_str: str | None, issues: list[str]) -> int | None:
    if not port_str:
        return None
    if not port_str.isdigit() or not (1 <= int(port_str) <= 65535):
        issues.append(f"port '{port_str}' is not a valid port number 1-65535")
        return None
    return int(port_str)


def _read_value(text: str, i: int, issues: list[str]) -> tuple[str, int]:
    """Read one value starting at `i`; return it and the index after its ';'.

    Quoted values ('...', "..." or ODBC-style {...}) may contain ';' and
    escape the closing character by doubling it.
    """
    n = len(text)
    while i < n and text[i] in " \t":
        i += 1

    if i < n and text[i] in "\"'{":
        closer = "}" if text[i] == "{" else text[i]
        i += 1
        buf: list[str] = []
        while True:
            if i >= n:
                issues.append("unterminated quoted value")
                return "".join(buf), n
            ch = text[i]
            if ch == closer:
                if i + 1 < n and text[i + 1] == closer:
                    buf.append(closer)
                    i += 2
                    continue
                i += 1
                break
            buf.append(ch)
            i += 1
        while i < n and text[i] in " \t":
            i += 1
        if i < n and text[i] != ";":
            issues.append("unexpected text after a quoted value")
            while i < n and text[i] != ";":
                i += 1
        return "".join(buf), i + 1

    end = text.find(";", i)
    if end == -1:
        end = n
    return text[i:end].strip(), end + 1


def _split_keyvalue(text: str, issues: list[str]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    n = len(text)
    i = 0
    while i < n:
        j = i
        while j < n and text[j] not in "=;":
            j += 1
        key = text[i:j].strip()

        if j >= n or text[j] == ";":
            if key:
                issues.append(f"segment '{key}' has no '=value'")
                pairs.append((key, ""))
            elif j < n:
                issues.append("connection string has an empty segment (stray ';')")
            i = j + 1
            continue

        value, i = _read_value(text, j + 1, issues)
        if not key:
            issues.append("connection string has a value with no key before '='")
            continue
        pairs.append((key, value))
    return pairs


# ADO.NET and ODBC each have their own spellings for the same handful of
# settings; fold them so a diff between a SqlClient string and an ODBC one
# compares host to host.
_KEY_ALIASES = {
    "server": "host",
    "data source": "host",
    "address": "host",
    "addr": "host",
    "network address": "host",
    "host": "host",
    "port": "port",
    "database": "database",
    "initial catalog": "database",
    "user id": "username",
    "uid": "username",
    "user": "username",
    "username": "username",
    "password": "password",
    "pwd": "password",
}


def _parse_keyvalue(
    raw: str, text: str, issues: list[str], lenient: bool
) -> ConnectionString:
    """Parse an ADO.NET / ODBC style ``Key=Value;Key=Value`` string."""
    fields: dict[str, str] = {}
    params: dict[str, str] = {}
    seen: set[str] = set()

    for key, value in _split_keyvalue(text, issues):
        folded = " ".join(key.lower().split())
        if folded in seen:
            issues.append(f"duplicate key '{key}'")
        seen.add(folded)
        canonical = _KEY_ALIASES.get(folded)
        if canonical is None:
            params[key] = value
        else:
            fields[canonical] = value

    server = fields.get("host", "")
    if server.lower().startswith("tcp:"):
        server = server[4:]
    port_str = fields.get("port")
    if "," in server:
        server, _, port_str = server.rpartition(",")
        port_str = port_str.strip()
    host = server.strip()
    if not host:
        _fatal(issues, "connection string is missing a host")
    port = _check_port(port_str, issues)

    password = fields.get("password")
    advisories: list[str] = []
    if password and not _looks_like_env_reference(password):
        advisories.append(
            "password looks like a plaintext credential; consider "
            "referencing an environment variable instead, e.g. "
            "${DB_PASSWORD}"
        )

    if issues and not lenient:
        raise ConnectionStringError(issues)

    return ConnectionString(
        scheme="",
        username=fields.get("username"),
        password=password,
        host=host,
        port=port,
        database=fields.get("database") or None,
        params=params,
        raw=raw,
        warnings=issues,
        advisories=advisories,
        style="keyvalue",
    )


def parse(raw: str, *, lenient: bool = False) -> ConnectionString:
    """Parse and validate a connection string.

    Strings without '://' but with '=' are read as ADO.NET / ODBC
    ``Key=Value;`` style instead of URLs.

    Every irregularity found (unescaped separators, duplicate query keys,
    stray whitespace, an unrecognized scheme, ...) is collected. If the
    string parses at all, `lenient=False` (the default) turns that list
    into a raised ConnectionStringError; `lenient=True` recovers the same
    way a permissive parser would and reports the list as `.warnings`.
    A handful of things (no scheme, no host) can't be recovered from and
    always raise, regardless of `lenient`.
    """
    issues: list[str] = []
    advisories: list[str] = []
    text = raw

    if text != text.strip():
        issues.append("connection string has leading or trailing whitespace")
        text = text.strip()

    if "://" not in text:
        if "=" in text:
            return _parse_keyvalue(raw, text, issues, lenient)
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

        if password and not _looks_like_env_reference(password):
            advisories.append(
                "password looks like a plaintext credential; consider "
                "referencing an environment variable instead, e.g. "
                "${DB_PASSWORD}"
            )

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

    port = _check_port(port_str, issues)

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
        advisories=advisories,
    )
