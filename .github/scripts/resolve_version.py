#!/usr/bin/env python3
"""Resolve the port version string for a release.

The version scheme is NOT semver:

    1.<libsodium version encoded as MAJOR*10000 + MINOR*100 + PATCH>.<port patch number>

so libsodium 1.0.21 gives 1.10021.N. The minor field is therefore not a semver
minor: it states which libsodium release the submodule is pinned to, and it is
derived here from the submodule rather than hand-edited.

The libsodium version comes from the release tag on the pinned commit, NOT
from the submodule's configure.ac. Between releases upstream sets configure.ac
to the next, unreleased version, so parsing it would claim we ship a libsodium
that does not exist yet. Requiring a release tag means a pin to an untagged
commit fails instead, which is correct: the version scheme has no way to
express "somewhere between two libsodium releases".

The patch counts port releases made against that libsodium version, so it
continues from the newest published release sharing this minor and restarts
at 0 whenever the submodule moves to a new libsodium release.

This module is pure stdlib. The pure logic (tag parsing, version encoding,
patch selection) lives in small functions that take plain data and have no
network or subprocess dependency, so they are trivially unit testable.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any

VersionTuple = tuple[int, int, int]

DEFAULT_LIBSODIUM_REPO: str = "jedisct1/libsodium"
DEFAULT_REPO: str = "esphome-libs/libsodium"
GITHUB_API_ACCEPT: str = "application/vnd.github+json"
PER_PAGE: int = 100

# Upstream tags releases inconsistently: 1.0.21-RELEASE, 1.0.18-FINAL, and
# 1.0.22 all name releases, and one commit can carry several.
TAG_RE: re.Pattern[str] = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-RELEASE|-FINAL)?$")


class VersionError(Exception):
    """Raised when the version cannot be resolved."""


# --------------------------------------------------------------------------
# Pure logic - no network, no subprocess. Easy to unit test directly.
# --------------------------------------------------------------------------


def parse_tag(tag: str) -> VersionTuple | None:
    """Parse a libsodium release tag into a (major, minor, patch) tuple.

    Accepts "1.0.21-RELEASE", "1.0.18-FINAL", and bare "1.0.22" forms.
    Returns None if the tag does not name a release.
    """
    match = TAG_RE.match(tag)
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def tags_for_commit(tags: list[dict[str, Any]], sha: str) -> list[str]:
    """Return the names of every tag whose commit sha equals sha.

    The GitHub tags API's commit.sha is already peeled, which is why it is
    used instead of the git refs API.
    """
    return [tag["name"] for tag in tags if tag.get("commit", {}).get("sha") == sha]


def resolve_upstream_version(tag_names: list[str], pinned_sha: str) -> VersionTuple:
    """Resolve the single libsodium version named by tag_names.

    Raises VersionError if no tag names a release, or if more than one
    distinct version is named (conflicting release tags on one commit).
    """
    versions: set[VersionTuple] = set()
    for name in tag_names:
        parsed = parse_tag(name)
        if parsed is not None:
            versions.add(parsed)

    if not versions:
        raise VersionError(
            f"libsodium submodule is pinned to {pinned_sha}, which carries no "
            "release tag. Pin it to a tagged libsodium release."
        )

    if len(versions) > 1:
        formatted = " ".join(
            f"{major}.{minor}.{patch}"
            for major, minor, patch in sorted(versions)
        )
        raise VersionError(
            f"libsodium commit {pinned_sha} carries conflicting release tags: "
            f"{formatted}"
        )

    return next(iter(versions))


def encode_minor(version: VersionTuple) -> int:
    """Encode a (major, minor, patch) libsodium version into the minor field."""
    major, minor, patch = version
    return major * 10000 + minor * 100 + patch


def non_draft_tag_names(releases: list[dict[str, Any]]) -> list[str]:
    """Return the tag_name of every non-draft release. Prereleases are kept."""
    return [
        release["tag_name"] for release in releases if not release.get("draft", False)
    ]


def select_patch(tag_names: list[str], minor: int) -> int:
    """Select the next port patch number for the given encoded minor.

    Continues from the newest published release sharing this minor, or 0 if
    none do.
    """
    pattern = re.compile(rf"^1\.{minor}\.(\d+)$")
    numbers: list[int] = []
    for name in tag_names:
        match = pattern.match(name)
        if match is not None:
            numbers.append(int(match.group(1)))

    if not numbers:
        return 0
    return max(numbers) + 1


def format_version(version: VersionTuple) -> str:
    major, minor, patch = version
    return f"{major}.{minor}.{patch}"


# --------------------------------------------------------------------------
# I/O: subprocess and network.
# --------------------------------------------------------------------------


def get_pinned_sha() -> str:
    """Return the commit sha the libsodium submodule gitlink is pinned to."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD:libsodium"],
            capture_output=True,
            text=True,
            check=True,
        )
    except subprocess.CalledProcessError as error:
        stderr = error.stderr.strip() if error.stderr else str(error)
        raise VersionError(f"Failed to resolve libsodium submodule pin: {stderr}") from error
    return result.stdout.strip()


def build_headers(token: str | None) -> dict[str, str]:
    headers = {"Accept": GITHUB_API_ACCEPT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def http_get_json(url: str, token: str | None) -> Any:
    request = urllib.request.Request(url, headers=build_headers(token))
    try:
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as error:
        raise VersionError(f"Request to {url} failed: {error}") from error


def paginate(base_url: str, token: str | None) -> list[dict[str, Any]]:
    """Fetch every page of a GitHub list endpoint, per_page=100.

    Follows pages until a short page (fewer than PER_PAGE items) is seen.
    """
    results: list[dict[str, Any]] = []
    page = 1
    while True:
        separator = "&" if "?" in base_url else "?"
        url = f"{base_url}{separator}per_page={PER_PAGE}&page={page}"
        data = http_get_json(url, token)
        results.extend(data)
        if len(data) < PER_PAGE:
            break
        page += 1
    return results


def fetch_libsodium_tags(libsodium_repo: str, token: str | None) -> list[dict[str, Any]]:
    try:
        return paginate(f"https://api.github.com/repos/{libsodium_repo}/tags", token)
    except VersionError as error:
        raise VersionError(f"Failed to list {libsodium_repo} tags: {error}") from error


def fetch_releases(repo: str, token: str | None) -> list[dict[str, Any]]:
    try:
        return paginate(f"https://api.github.com/repos/{repo}/releases", token)
    except VersionError as error:
        raise VersionError(f"Failed to list existing releases: {error}") from error


# --------------------------------------------------------------------------
# High level steps, shared between the two subcommands.
# --------------------------------------------------------------------------


def resolve_libsodium_version(libsodium_repo: str, token: str | None) -> tuple[VersionTuple, str]:
    """Steps 1-3: resolve the libsodium release the submodule is pinned to.

    Returns (version, pinned_sha).
    """
    pinned_sha = get_pinned_sha()
    tags = fetch_libsodium_tags(libsodium_repo, token)
    tag_names = tags_for_commit(tags, pinned_sha)
    version = resolve_upstream_version(tag_names, pinned_sha)
    return version, pinned_sha


def resolve_port_version(libsodium_repo: str, repo: str, token: str | None) -> tuple[VersionTuple, str]:
    """All steps: resolve the libsodium version and the full port version string.

    Returns (libsodium_version, port_version_string).
    """
    version, _pinned_sha = resolve_libsodium_version(libsodium_repo, token)
    minor = encode_minor(version)
    releases = fetch_releases(repo, token)
    release_tags = non_draft_tag_names(releases)
    patch = select_patch(release_tags, minor)
    return version, f"1.{minor}.{patch}"


def write_github_output(version_string: str) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as handle:
        handle.write(f"version={version_string}\n")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def run_resolve(libsodium_repo: str, repo: str, token: str | None) -> None:
    version, version_string = resolve_port_version(libsodium_repo, repo, token)
    print(f"libsodium {format_version(version)} -> {version_string}")
    write_github_output(version_string)


def run_check(libsodium_repo: str, token: str | None) -> None:
    version, _pinned_sha = resolve_libsodium_version(libsodium_repo, token)
    print(format_version(version))


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Resolve the libsodium-esphome port version.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("resolve", help="Resolve the full port version and emit GITHUB_OUTPUT.")
    subparsers.add_parser("check", help="Check that the submodule is pinned to a tagged libsodium release.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN")
    libsodium_repo = DEFAULT_LIBSODIUM_REPO
    repo = os.environ.get("GITHUB_REPOSITORY", DEFAULT_REPO)

    try:
        if args.command == "check":
            run_check(libsodium_repo, token)
        else:
            run_resolve(libsodium_repo, repo, token)
    except VersionError as error:
        print(f"::error::{error}")
        return 1

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
