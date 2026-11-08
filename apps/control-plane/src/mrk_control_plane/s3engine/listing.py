"""Backend-independent ListObjects rollup (prefix/delimiter/max-keys, docs/30 §1.4)."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from .index import prefix_upper_bound


@dataclass(slots=True)
class Entry:
    key: str
    payload: Any = None
    # The source already skipped everything below this key (linked folder walk).
    collapsed: bool = False


@dataclass(slots=True)
class ListPage:
    contents: list[Entry] = field(default_factory=list)
    prefixes: list[str] = field(default_factory=list)
    truncated: bool = False
    next_marker: str | None = None


Source = Callable[[str, bool], Iterator[Entry]]  # (start, inclusive) -> entries in key order


def resume_point(prefix: str, delimiter: str, marker: str) -> tuple[str, bool]:
    """Where to continue after ``marker``; a rolled-up common prefix skips its subtree."""
    if delimiter and marker.startswith(prefix) and marker.endswith(delimiter):
        rest = marker[len(prefix) :]
        if rest and rest.find(delimiter) == len(rest) - len(delimiter):
            upper = prefix_upper_bound(marker)
            if upper is None:
                return marker, False
            return upper, True
    return marker, False


def list_page(
    source: Source, *, prefix: str, delimiter: str, marker: str, max_keys: int
) -> ListPage:
    page = ListPage()
    if max_keys <= 0:
        # S3 answers max-keys=0 with an empty, non-truncated page.
        return page
    start, inclusive = resume_point(prefix, delimiter, marker)
    iterator = source(start, inclusive)
    count = 0
    last: str | None = None
    while True:
        entry = next(iterator, None)
        if entry is None:
            break
        key = entry.key
        if prefix and not key.startswith(prefix):
            if key > prefix:
                break
            continue
        if delimiter:
            index = key.find(delimiter, len(prefix))
            if index >= 0:
                common = key[: index + len(delimiter)]
                if count >= max_keys:
                    page.truncated = True
                    break
                page.prefixes.append(common)
                count += 1
                last = common
                if not entry.collapsed or common != key:
                    upper = prefix_upper_bound(common)
                    if upper is None:
                        break
                    iterator = source(upper, True)
                continue
        if count >= max_keys:
            page.truncated = True
            break
        page.contents.append(entry)
        count += 1
        last = key
    if page.truncated:
        page.next_marker = last
    return page
