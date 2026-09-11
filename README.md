# connstrict

A command line tool that validates and normalizes database connection
strings. It parses the `scheme://user:pass@host:port/database?param=value`
shape used by Postgres, MySQL, MongoDB, Redis, and similar drivers, and it
is strict about it by default.

## The problem

Connection strings pass through a lot of hands before they run: they get
typed into a `.env` file, pasted into a CI variable, copied out of a
provisioning script's output. Most parsers, including Python's own
`urllib.parse`, are permissive about the result. An unescaped `@` in a
password gets silently treated as the host separator. A duplicate query
parameter silently keeps whichever one the parser saw last. Trailing
whitespace from a copy-paste is silently trimmed or silently kept,
depending on the library. None of that raises an error - it just means
the host, user, or setting your code ends up using isn't the one anybody
intended, and you find out from a failed connection or, worse, a
connection to the wrong place.

`connstrict` treats all of that as a hard error unless you ask it not to.

## Usage

Check a connection string:

```
$ connstrict "postgresql://app_user:s3cret@db.internal:5432/orders?sslmode=require"
ok
postgresql://app_user:s3cret@db.internal:5432/orders?sslmode=require
```

An unescaped `@` inside the password is rejected by default, because the
parser can't tell where the password ends and the host begins:

```
$ connstrict "postgresql://app_user:p@ss@db.internal/orders"
connstrict: error: authority contains multiple unescaped '@' characters; percent-encode the one in the password as %40
```

Pass `--lenient` to fall back to the same last-`@`-wins guess a permissive
parser would make, with the ambiguity reported as a warning instead of an
error:

```
$ connstrict --lenient "postgresql://app_user:p@ss@db.internal/orders"
connstrict: warning: authority contains multiple unescaped '@' characters; percent-encode the one in the password as %40
ok
postgresql://app_user:p%40ss@db.internal/orders
```

A duplicate query parameter is also a strict error, since it's ambiguous
which value the caller meant to keep:

```
$ connstrict "mysql://root@localhost/app?ssl-mode=REQUIRED&ssl-mode=DISABLED"
connstrict: error: duplicate query parameter 'ssl-mode'
```

Read from stdin instead of an argument (handy for checking a value already
sitting in an environment variable, without putting it on the process's
command line where it would show up in `ps`):

```
$ echo "$DATABASE_URL" | connstrict
```

Use `--quiet` in scripts to get just the normalized string on success and
nothing on stdout on failure:

```
$ connstrict --quiet "$DATABASE_URL" || exit 1
```

Exit codes: `0` on success, `1` when the string fails validation, `2` when
no connection string was given at all.

## What it checks

- a recognized scheme (`postgres`, `postgresql`, `mysql`, `mongodb`,
  `mongodb+srv`, `redis`, `rediss`, `amqp`, `amqps`, `sqlserver`)
- no leading or trailing whitespace
- a host is present
- the port, if given, is a number between 1 and 65535
- the username and password don't contain an unescaped separator
  character (`@`, `:`, `/`, `?`, `#`)
- no duplicate query parameters
- no stray fragment (`#...`), which most drivers ignore silently

Every one of these is an error by default and a warning under `--lenient`.

## Installing

No third-party dependencies; standard library only.

```
pip install .
```

## Library use

```python
from connstrict import parse, ConnectionStringError

try:
    conn = parse(raw)
except ConnectionStringError as exc:
    for issue in exc.issues:
        print(issue)
```

## License

MIT, see `LICENSE`.
