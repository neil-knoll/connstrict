import pytest

from connstrict.parser import ConnectionStringError, parse


def test_well_formed_string_has_no_warnings():
    result = parse("postgresql://app_user:secret@db.internal:5432/orders?sslmode=require")
    assert result.scheme == "postgresql"
    assert result.username == "app_user"
    assert result.password == "secret"
    assert result.host == "db.internal"
    assert result.port == 5432
    assert result.database == "orders"
    assert result.params == {"sslmode": "require"}
    assert result.warnings == []


def test_scheme_is_case_folded_and_not_flagged():
    result = parse("POSTGRESQL://db.internal/orders")
    assert result.scheme == "postgresql"
    assert result.warnings == []


def test_minimal_string_with_no_userinfo_or_port():
    result = parse("redis://cache.internal/0")
    assert result.username is None
    assert result.password is None
    assert result.port is None
    assert result.database == "0"


def test_username_without_password():
    result = parse("mysql://root@localhost/app")
    assert result.username == "root"
    assert result.password is None


@pytest.mark.parametrize("missing", ["missing scheme entirely", "no-scheme-here"])
def test_missing_scheme_separator_always_raises(missing):
    with pytest.raises(ConnectionStringError, match="scheme separator"):
        parse(missing, lenient=True)


def test_missing_host_always_raises_even_when_lenient():
    with pytest.raises(ConnectionStringError, match="missing a host"):
        parse("postgresql://:5432/db", lenient=True)


def test_unterminated_ipv6_literal_always_raises():
    with pytest.raises(ConnectionStringError, match="unterminated IPv6"):
        parse("postgresql://[::1:5432/db", lenient=True)


def test_junk_after_ipv6_literal_always_raises():
    with pytest.raises(ConnectionStringError, match="after IPv6 host literal"):
        parse("postgresql://[::1]junk/db", lenient=True)


def test_ipv6_literal_parses_host_and_port():
    result = parse("postgresql://[::1]:5432/db")
    assert result.host == "::1"
    assert result.port == 5432


def test_ipv6_literal_without_port():
    result = parse("postgresql://[::1]/db")
    assert result.host == "::1"
    assert result.port is None


def test_leading_or_trailing_whitespace_is_strict_error():
    with pytest.raises(ConnectionStringError, match="whitespace"):
        parse(" postgresql://db.internal/orders")


def test_leading_or_trailing_whitespace_is_stripped_when_lenient():
    result = parse(" postgresql://db.internal/orders \n", lenient=True)
    assert result.host == "db.internal"
    assert any("whitespace" in w for w in result.warnings)


def test_unrecognized_scheme_is_strict_error():
    with pytest.raises(ConnectionStringError, match="unrecognized scheme"):
        parse("oracle://db.internal/orders")


def test_unrecognized_scheme_is_warning_when_lenient():
    result = parse("oracle://db.internal/orders", lenient=True)
    assert result.scheme == "oracle"
    assert any("unrecognized scheme" in w for w in result.warnings)


def test_multiple_at_signs_is_strict_error():
    with pytest.raises(ConnectionStringError, match="multiple unescaped '@'"):
        parse("postgresql://app_user:p@ss@db.internal/orders")


def test_multiple_at_signs_last_wins_when_lenient():
    result = parse("postgresql://app_user:p@ss@db.internal/orders", lenient=True)
    assert result.username == "app_user"
    assert result.password == "p@ss"
    assert result.host == "db.internal"
    assert any("multiple unescaped" in w for w in result.warnings)


def test_unescaped_char_in_username_is_strict_error():
    with pytest.raises(ConnectionStringError, match="username contains an unescaped"):
        parse("postgresql://user[1]:pass@db.internal/orders")


def test_unescaped_char_in_username_is_warning_when_lenient():
    result = parse("postgresql://user[1]:pass@db.internal/orders", lenient=True)
    assert result.username == "user[1]"
    assert any("username contains an unescaped" in w for w in result.warnings)


def test_percent_encoded_userinfo_round_trips():
    result = parse("postgresql://app_user:p%40ss@db.internal/orders")
    assert result.password == "p@ss"
    assert result.warnings == []


def test_invalid_port_text_is_strict_error():
    with pytest.raises(ConnectionStringError, match="not a valid port number"):
        parse("postgresql://db.internal:notaport/orders")


def test_invalid_port_out_of_range_is_strict_error():
    with pytest.raises(ConnectionStringError, match="not a valid port number"):
        parse("postgresql://db.internal:70000/orders")


def test_invalid_port_is_dropped_to_none_when_lenient():
    result = parse("postgresql://db.internal:notaport/orders", lenient=True)
    assert result.port is None
    assert any("not a valid port number" in w for w in result.warnings)


def test_port_with_leading_zero_parses_fine():
    result = parse("postgresql://db.internal:0080/orders")
    assert result.port == 80
    assert result.warnings == []


def test_fragment_is_strict_error():
    with pytest.raises(ConnectionStringError, match="fragment"):
        parse("postgresql://db.internal/orders#note")


def test_fragment_is_dropped_when_lenient():
    result = parse("postgresql://db.internal/orders#note", lenient=True)
    assert result.database == "orders"
    assert any("fragment" in w for w in result.warnings)


def test_extra_path_segment_is_strict_error():
    with pytest.raises(ConnectionStringError, match="extra '/' segment"):
        parse("postgresql://db.internal/orders/extra")


def test_extra_path_segment_is_kept_verbatim_when_lenient():
    result = parse("postgresql://db.internal/orders/extra", lenient=True)
    assert result.database == "orders/extra"
    assert any("extra '/' segment" in w for w in result.warnings)


def test_empty_database_path_is_none():
    result = parse("postgresql://db.internal/")
    assert result.database is None
    result = parse("postgresql://db.internal")
    assert result.database is None


def test_stray_ampersand_is_strict_error():
    with pytest.raises(ConnectionStringError, match="stray '&'"):
        parse("postgresql://db.internal/orders?a=1&&b=2")


def test_stray_ampersand_params_recovered_when_lenient():
    result = parse("postgresql://db.internal/orders?a=1&&b=2", lenient=True)
    assert result.params == {"a": "1", "b": "2"}
    assert any("stray '&'" in w for w in result.warnings)


def test_param_without_equals_is_strict_error():
    with pytest.raises(ConnectionStringError, match="no '=value'"):
        parse("postgresql://db.internal/orders?flag")


def test_param_without_equals_becomes_empty_string_when_lenient():
    result = parse("postgresql://db.internal/orders?flag", lenient=True)
    assert result.params == {"flag": ""}
    assert any("no '=value'" in w for w in result.warnings)


def test_duplicate_query_parameter_is_strict_error():
    with pytest.raises(ConnectionStringError, match="duplicate query parameter"):
        parse("mysql://root@localhost/app?ssl-mode=REQUIRED&ssl-mode=DISABLED")


def test_duplicate_query_parameter_last_value_wins_when_lenient():
    result = parse(
        "mysql://root@localhost/app?ssl-mode=REQUIRED&ssl-mode=DISABLED", lenient=True
    )
    assert result.params == {"ssl-mode": "DISABLED"}
    assert any("duplicate query parameter" in w for w in result.warnings)


def test_multiple_issues_are_all_collected():
    with pytest.raises(ConnectionStringError) as excinfo:
        parse(" oracle://user[x]:pass@db.internal/o/extra?a=1&a=2")
    issues = excinfo.value.issues
    assert any("whitespace" in i for i in issues)
    assert any("unrecognized scheme" in i for i in issues)
    assert any("unescaped" in i for i in issues)
    assert any("extra '/' segment" in i for i in issues)
    assert any("duplicate query parameter" in i for i in issues)


def test_normalized_percent_encodes_special_characters():
    result = parse("postgresql://app_user:p@ss@db.internal/orders", lenient=True)
    assert result.normalized() == "postgresql://app_user:p%40ss@db.internal/orders"


def test_normalized_wraps_ipv6_host_in_brackets():
    result = parse("postgresql://[::1]:5432/db")
    assert result.normalized() == "postgresql://[::1]:5432/db"


def test_normalized_omits_absent_parts():
    result = parse("redis://cache.internal")
    assert result.normalized() == "redis://cache.internal"
