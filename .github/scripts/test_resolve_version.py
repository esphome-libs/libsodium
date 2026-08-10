"""Tests for resolve_version.py.

Network is mocked at the urllib.request.urlopen layer; the git call is mocked
via subprocess.run. No real network or subprocess call is made.
"""

from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from typing import Any, Callable, Iterator

import pytest

import resolve_version as rv


# --------------------------------------------------------------------------
# Test helpers
# --------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, data: Any) -> None:
        self._data = json.dumps(data).encode("utf-8")

    def read(self) -> bytes:
        return self._data

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def sequence_urlopen(responses: list[Any]) -> Callable[..., FakeResponse]:
    """Build a fake urlopen returning one item from responses per call.

    Each item is either JSON-serializable data, or an Exception instance to
    raise instead.
    """
    it: Iterator[Any] = iter(responses)

    def fake_urlopen(request: urllib.request.Request, *args: object, **kwargs: object) -> FakeResponse:
        item = next(it)
        if isinstance(item, Exception):
            raise item
        return FakeResponse(item)

    return fake_urlopen


def capturing_urlopen(
    sink: list[urllib.request.Request], data: Any = None
) -> Callable[..., FakeResponse]:
    def fake_urlopen(request: urllib.request.Request, *args: object, **kwargs: object) -> FakeResponse:
        sink.append(request)
        return FakeResponse(data if data is not None else [])

    return fake_urlopen


def tag(name: str, sha: str) -> dict[str, Any]:
    return {"name": name, "commit": {"sha": sha}}


def release(tag_name: str, draft: bool = False) -> dict[str, Any]:
    return {"tag_name": tag_name, "draft": draft}


# --------------------------------------------------------------------------
# Pure logic: parse_tag
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tag_name,expected",
    [
        ("1.0.21-RELEASE", (1, 0, 21)),
        ("1.0.18-FINAL", (1, 0, 18)),
        ("1.0.22", (1, 0, 22)),
        ("v1.0.22", None),
        ("not-a-version", None),
        ("1.0.22-BETA", None),
    ],
)
def test_parse_tag(tag_name: str, expected: tuple[int, int, int] | None) -> None:
    assert rv.parse_tag(tag_name) == expected


# --------------------------------------------------------------------------
# Pure logic: encode_minor
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "version,expected",
    [
        # Every libsodium release so far has been 1.0.x, so these three are the
        # cases with real historical evidence behind them.
        ((1, 0, 18), 10018),
        ((1, 0, 20), 10020),
        ((1, 0, 21), 10021),
        # No libsodium release has ever had a non-zero minor, so nothing above
        # exercises the minor term at all. These pin down the encoding as a
        # zero-padded concatenation of the three fields (1.1.0 -> 1|01|00), so
        # a future libsodium 1.1.x cannot silently collide with a 1.0.x port
        # version.
        ((1, 1, 0), 10100),
        ((1, 2, 3), 10203),
        ((1, 10, 21), 11021),
        ((2, 0, 0), 20000),
    ],
)
def test_encode_minor(version: tuple[int, int, int], expected: int) -> None:
    assert rv.encode_minor(version) == expected


def test_format_version() -> None:
    assert rv.format_version((1, 0, 21)) == "1.0.21"


# --------------------------------------------------------------------------
# Pure logic: tags_for_commit
# --------------------------------------------------------------------------


def test_tags_for_commit_matches_only_pinned_sha() -> None:
    tags = [
        tag("1.0.21-RELEASE", "abc123"),
        tag("1.0.20-RELEASE", "def456"),
        {"name": "no-commit-field"},
    ]
    assert rv.tags_for_commit(tags, "abc123") == ["1.0.21-RELEASE"]


def test_tags_for_commit_no_match() -> None:
    tags = [tag("1.0.20-RELEASE", "def456")]
    assert rv.tags_for_commit(tags, "abc123") == []


# --------------------------------------------------------------------------
# Pure logic: resolve_upstream_version
# --------------------------------------------------------------------------


def test_resolve_upstream_version_single_tag() -> None:
    assert rv.resolve_upstream_version(["1.0.21-RELEASE"], "abc123") == (1, 0, 21)


def test_resolve_upstream_version_final_suffix() -> None:
    assert rv.resolve_upstream_version(["1.0.18-FINAL"], "abc123") == (1, 0, 18)


def test_resolve_upstream_version_bare() -> None:
    assert rv.resolve_upstream_version(["1.0.22"], "abc123") == (1, 0, 22)


def test_resolve_upstream_version_duplicate_tags_collapse() -> None:
    # The 1.0.22 commit carries both "1.0.22" and "1.0.22-RELEASE".
    assert rv.resolve_upstream_version(["1.0.22", "1.0.22-RELEASE"], "abc123") == (1, 0, 22)


def test_resolve_upstream_version_ignores_non_version_tags() -> None:
    assert rv.resolve_upstream_version(["not-a-release", "1.0.21-RELEASE"], "abc123") == (1, 0, 21)


def test_resolve_upstream_version_no_match_raises() -> None:
    with pytest.raises(rv.VersionError, match="carries no release tag"):
        rv.resolve_upstream_version([], "abc123")


def test_resolve_upstream_version_no_match_after_filtering_junk_raises() -> None:
    with pytest.raises(rv.VersionError, match="carries no release tag"):
        rv.resolve_upstream_version(["not-a-release"], "abc123")


def test_resolve_upstream_version_conflicting_tags_raises() -> None:
    with pytest.raises(rv.VersionError, match="conflicting release tags"):
        rv.resolve_upstream_version(["1.0.21-RELEASE", "1.0.22"], "abc123")


# --------------------------------------------------------------------------
# Pure logic: non_draft_tag_names
# --------------------------------------------------------------------------


def test_non_draft_tag_names_excludes_drafts() -> None:
    releases = [
        release("1.10021.0", draft=False),
        release("1.10021.1", draft=True),
        {"tag_name": "1.10021.2"},  # no "draft" key -> defaults to False -> kept
    ]
    assert rv.non_draft_tag_names(releases) == ["1.10021.0", "1.10021.2"]


def test_non_draft_tag_names_keeps_prereleases() -> None:
    # Prereleases are not drafts, and must be kept.
    releases = [{"tag_name": "1.10021.0", "draft": False, "prerelease": True}]
    assert rv.non_draft_tag_names(releases) == ["1.10021.0"]


# --------------------------------------------------------------------------
# Pure logic: select_patch
# --------------------------------------------------------------------------


def test_select_patch_continues_from_newest() -> None:
    tags = ["1.10021.0", "1.10021.1"]
    assert rv.select_patch(tags, 10021) == 2


def test_select_patch_restarts_at_zero_for_new_minor() -> None:
    tags = ["1.10021.0", "1.10021.1"]
    assert rv.select_patch(tags, 10022) == 0


def test_select_patch_ignores_drafts_upstream_of_call() -> None:
    # non_draft_tag_names is expected to already have filtered drafts out;
    # select_patch itself just has to ignore tags of other minors.
    tags = ["1.10020.9", "1.10021.1"]
    assert rv.select_patch(tags, 10021) == 2


def test_select_patch_no_matches_returns_zero() -> None:
    assert rv.select_patch([], 10021) == 0
    assert rv.select_patch(["not-a-port-tag"], 10021) == 0


def test_select_patch_numeric_not_lexical_sort() -> None:
    # 10 must beat 7: a lexical sort would wrongly pick "9" over "10".
    tags = ["1.10021.7", "1.10021.10", "1.10021.9"]
    assert rv.select_patch(tags, 10021) == 11


# --------------------------------------------------------------------------
# get_pinned_sha (subprocess)
# --------------------------------------------------------------------------


def test_get_pinned_sha_success(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=["git"], returncode=0, stdout="abc123\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert rv.get_pinned_sha() == "abc123"


def test_get_pinned_sha_failure_with_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(returncode=128, cmd=["git"], stderr="fatal: bad revision\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(rv.VersionError, match="fatal: bad revision"):
        rv.get_pinned_sha()


def test_get_pinned_sha_failure_without_stderr(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(returncode=128, cmd=["git"], stderr=None)

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(rv.VersionError):
        rv.get_pinned_sha()


# --------------------------------------------------------------------------
# build_headers / http_get_json
# --------------------------------------------------------------------------


def test_build_headers_with_token() -> None:
    headers = rv.build_headers("secret-token")
    assert headers["Accept"] == "application/vnd.github+json"
    assert headers["Authorization"] == "Bearer secret-token"


def test_build_headers_without_token() -> None:
    headers = rv.build_headers(None)
    assert headers["Accept"] == "application/vnd.github+json"
    assert "Authorization" not in headers


def test_http_get_json_sends_auth_header_when_token_set(monkeypatch: pytest.MonkeyPatch) -> None:
    sink: list[urllib.request.Request] = []
    monkeypatch.setattr(urllib.request, "urlopen", capturing_urlopen(sink, data={"ok": True}))
    result = rv.http_get_json("https://api.github.com/x", "my-token")
    assert result == {"ok": True}
    assert sink[0].get_header("Authorization") == "Bearer my-token"


def test_http_get_json_no_auth_header_when_token_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    sink: list[urllib.request.Request] = []
    monkeypatch.setattr(urllib.request, "urlopen", capturing_urlopen(sink, data={"ok": True}))
    rv.http_get_json("https://api.github.com/x", None)
    assert sink[0].get_header("Authorization") is None


def test_http_get_json_raises_version_error_on_url_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        urllib.request, "urlopen", sequence_urlopen([urllib.error.URLError("boom")])
    )
    with pytest.raises(rv.VersionError, match="Request to .* failed"):
        rv.http_get_json("https://api.github.com/x", None)


# --------------------------------------------------------------------------
# paginate
# --------------------------------------------------------------------------


def test_paginate_stops_on_short_page(monkeypatch: pytest.MonkeyPatch) -> None:
    full_page = [{"name": str(i)} for i in range(rv.PER_PAGE)]
    short_page = [{"name": "last"}]
    monkeypatch.setattr(urllib.request, "urlopen", sequence_urlopen([full_page, short_page]))
    result = rv.paginate("https://api.github.com/repos/x/tags", None)
    assert len(result) == rv.PER_PAGE + 1
    assert result[-1]["name"] == "last"


def test_paginate_single_short_page(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(urllib.request, "urlopen", sequence_urlopen([[{"name": "only"}]]))
    result = rv.paginate("https://api.github.com/repos/x/tags", None)
    assert result == [{"name": "only"}]


def test_paginate_appends_query_with_ampersand_when_base_has_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sink: list[urllib.request.Request] = []
    monkeypatch.setattr(urllib.request, "urlopen", capturing_urlopen(sink, data=[]))
    rv.paginate("https://api.github.com/repos/x/tags?foo=bar", None)
    assert "foo=bar&per_page=100&page=1" in sink[0].full_url


def test_paginate_appends_query_with_question_mark_when_base_has_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sink: list[urllib.request.Request] = []
    monkeypatch.setattr(urllib.request, "urlopen", capturing_urlopen(sink, data=[]))
    rv.paginate("https://api.github.com/repos/x/tags", None)
    assert "?per_page=100&page=1" in sink[0].full_url


# --------------------------------------------------------------------------
# fetch_libsodium_tags / fetch_releases
# --------------------------------------------------------------------------


def test_fetch_libsodium_tags_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(urllib.request, "urlopen", sequence_urlopen([[tag("1.0.21-RELEASE", "abc")]]))
    result = rv.fetch_libsodium_tags("jedisct1/libsodium", None)
    assert result == [tag("1.0.21-RELEASE", "abc")]


def test_fetch_libsodium_tags_failure_wraps_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        urllib.request, "urlopen", sequence_urlopen([urllib.error.URLError("down")])
    )
    with pytest.raises(rv.VersionError, match="Failed to list jedisct1/libsodium tags"):
        rv.fetch_libsodium_tags("jedisct1/libsodium", None)


def test_fetch_releases_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(urllib.request, "urlopen", sequence_urlopen([[release("1.10021.0")]]))
    result = rv.fetch_releases("esphome-libs/libsodium", None)
    assert result == [release("1.10021.0")]


def test_fetch_releases_failure_wraps_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        urllib.request, "urlopen", sequence_urlopen([urllib.error.URLError("down")])
    )
    with pytest.raises(rv.VersionError, match="Failed to list existing releases"):
        rv.fetch_releases("esphome-libs/libsodium", None)


# --------------------------------------------------------------------------
# resolve_libsodium_version / resolve_port_version (integration of the above)
# --------------------------------------------------------------------------


def test_resolve_libsodium_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "abc\n", ""))
    monkeypatch.setattr(urllib.request, "urlopen", sequence_urlopen([[tag("1.0.21-RELEASE", "abc")]]))
    version, pinned_sha = rv.resolve_libsodium_version("jedisct1/libsodium", None)
    assert version == (1, 0, 21)
    assert pinned_sha == "abc"


def test_resolve_port_version_continues_patch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "abc\n", ""))
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        sequence_urlopen(
            [
                [tag("1.0.21-RELEASE", "abc")],
                [release("1.10021.0"), release("1.10021.1")],
            ]
        ),
    )
    version, version_string = rv.resolve_port_version("jedisct1/libsodium", "esphome-libs/libsodium", None)
    assert version == (1, 0, 21)
    assert version_string == "1.10021.2"


# --------------------------------------------------------------------------
# write_github_output
# --------------------------------------------------------------------------


def test_write_github_output_writes_when_set(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    output_file = tmp_path / "github_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))
    rv.write_github_output("1.10021.2")
    assert output_file.read_text(encoding="utf-8") == "version=1.10021.2\n"


def test_write_github_output_skips_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    # Must not raise even though there is nowhere to write.
    rv.write_github_output("1.10021.2")


# --------------------------------------------------------------------------
# Known-good end-to-end scenarios (verified against the live repo).
# --------------------------------------------------------------------------


def test_e2e_1_0_21_release_with_prior_releases(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "pinned-sha\n", ""))
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        sequence_urlopen(
            [
                [tag("1.0.21-RELEASE", "pinned-sha")],
                [release("1.10021.0"), release("1.10021.1")],
            ]
        ),
    )
    _version, version_string = rv.resolve_port_version("jedisct1/libsodium", "esphome-libs/libsodium", None)
    assert version_string == "1.10021.2"


def test_e2e_1_0_22_dual_tags_no_prior_releases(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "pinned-sha\n", ""))
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        sequence_urlopen(
            [
                [tag("1.0.22", "pinned-sha"), tag("1.0.22-RELEASE", "pinned-sha")],
                [],
            ]
        ),
    )
    _version, version_string = rv.resolve_port_version("jedisct1/libsodium", "esphome-libs/libsodium", None)
    assert version_string == "1.10022.0"


def test_e2e_1_0_18_final_with_prior_releases(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "pinned-sha\n", ""))
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        sequence_urlopen(
            [
                [tag("1.0.18-FINAL", "pinned-sha")],
                [release("1.10018.4")],
            ]
        ),
    )
    _version, version_string = rv.resolve_port_version("jedisct1/libsodium", "esphome-libs/libsodium", None)
    assert version_string == "1.10018.5"


# --------------------------------------------------------------------------
# CLI: run_resolve / run_check / main
# --------------------------------------------------------------------------


def test_run_resolve_prints_and_writes_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    output_file = tmp_path / "github_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "abc\n", ""))
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        sequence_urlopen([[tag("1.0.21-RELEASE", "abc")], [release("1.10021.0")]]),
    )
    rv.run_resolve("jedisct1/libsodium", "esphome-libs/libsodium", None)
    captured = capsys.readouterr()
    assert "libsodium 1.0.21 -> 1.10021.1" in captured.out
    assert output_file.read_text(encoding="utf-8") == "version=1.10021.1\n"


def test_run_check_prints_libsodium_version(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "abc\n", ""))
    monkeypatch.setattr(urllib.request, "urlopen", sequence_urlopen([[tag("1.0.21-RELEASE", "abc")]]))
    rv.run_check("jedisct1/libsodium", None)
    assert capsys.readouterr().out.strip() == "1.0.21"


def test_build_arg_parser_resolve_and_check() -> None:
    parser = rv.build_arg_parser()
    assert parser.parse_args(["resolve"]).command == "resolve"
    assert parser.parse_args(["check"]).command == "check"


def test_main_resolve_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    output_file = tmp_path / "github_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))
    monkeypatch.setenv("GITHUB_REPOSITORY", "esphome-libs/libsodium")
    monkeypatch.setenv("GITHUB_TOKEN", "tok")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "abc\n", ""))
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        sequence_urlopen([[tag("1.0.21-RELEASE", "abc")], [release("1.10021.0")]]),
    )
    exit_code = rv.main(["resolve"])
    assert exit_code == 0
    assert output_file.read_text(encoding="utf-8") == "version=1.10021.1\n"


def test_main_check_success_no_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "abc\n", ""))
    monkeypatch.setattr(urllib.request, "urlopen", sequence_urlopen([[tag("1.0.21-RELEASE", "abc")]]))
    exit_code = rv.main(["check"])
    assert exit_code == 0
    assert capsys.readouterr().out.strip() == "1.0.21"


def test_main_error_path_returns_1_and_prints_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "abc\n", ""))
    # No tags at all -> no release tag on pinned commit -> VersionError.
    monkeypatch.setattr(urllib.request, "urlopen", sequence_urlopen([[]]))
    exit_code = rv.main(["check"])
    assert exit_code == 1
    assert "::error::" in capsys.readouterr().out


def test_main_default_repository_when_env_unset(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    output_file = tmp_path / "github_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, "abc\n", ""))
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        sequence_urlopen([[tag("1.0.21-RELEASE", "abc")], []]),
    )
    exit_code = rv.main(["resolve"])
    assert exit_code == 0
    assert output_file.read_text(encoding="utf-8") == "version=1.10021.0\n"
