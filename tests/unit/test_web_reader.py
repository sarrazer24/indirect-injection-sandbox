from injection_sandbox.tools.web_reader import WebFixtureReader


def make_reader(tmp_path, *, max_bytes=20_000):
    (tmp_path / "research.html").write_text(
        "<html><body><p>Synthetic research page</p></body></html>",
        encoding="utf-8",
    )
    return WebFixtureReader(
        fixtures_root=tmp_path,
        approved_fixtures={"research_page": "research.html"},
        max_bytes=max_bytes,
    )


def test_reads_approved_fixture(tmp_path):
    result = make_reader(tmp_path).read("research_page")

    assert result.success is True
    assert "Synthetic research page" in result.content


def test_rejects_unapproved_fixture_id(tmp_path):
    result = make_reader(tmp_path).read("unknown_page")

    assert result.success is False
    assert result.error == "Fixture ID is not approved."


def test_rejects_path_escape(tmp_path):
    outside_file = tmp_path.parent / f"{tmp_path.name}_outside.html"
    outside_file.write_text("Synthetic outside content", encoding="utf-8")

    try:
        reader = WebFixtureReader(
            fixtures_root=tmp_path,
            approved_fixtures={"outside": f"../{outside_file.name}"},
        )
        result = reader.read("outside")

        assert result.success is False
        assert result.error == "Fixture path escapes the approved directory."
    finally:
        outside_file.unlink(missing_ok=True)


def test_rejects_oversized_fixture(tmp_path):
    reader = make_reader(tmp_path, max_bytes=10)

    result = reader.read("research_page")

    assert result.success is False
    assert result.error == "Fixture exceeds the maximum allowed size."


def test_rejects_invalid_utf8(tmp_path):
    (tmp_path / "invalid.html").write_bytes(b"\xff\xfe")
    reader = WebFixtureReader(
        fixtures_root=tmp_path,
        approved_fixtures={"invalid": "invalid.html"},
    )

    result = reader.read("invalid")

    assert result.success is False
    assert result.error == "Fixture is not valid UTF-8 text."
