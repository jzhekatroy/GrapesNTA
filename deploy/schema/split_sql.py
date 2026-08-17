#!/usr/bin/env python3
"""Split a ClickHouse SQL file into statements.

HTTP interface accepts one statement per request. Native clickhouse-client
has --multiquery; this is the HTTP equivalent. Respects -- line comments,
/* */ block comments, and single-quoted strings (including '').
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


def split_sql(text: str) -> list[str]:
    statements: list[str] = []
    buf: list[str] = []
    i = 0
    n = len(text)
    in_squote = False
    in_line_comment = False
    in_block_comment = False

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_line_comment:
            buf.append(c)
            if c == "\n":
                in_line_comment = False
            i += 1
            continue

        if in_block_comment:
            buf.append(c)
            if c == "*" and nxt == "/":
                buf.append(nxt)
                i += 2
                in_block_comment = False
                continue
            i += 1
            continue

        if in_squote:
            buf.append(c)
            if c == "'" and nxt == "'":
                buf.append(nxt)
                i += 2
                continue
            if c == "'":
                in_squote = False
            i += 1
            continue

        if c == "-" and nxt == "-":
            in_line_comment = True
            buf.append(c)
            i += 1
            continue

        if c == "/" and nxt == "*":
            in_block_comment = True
            buf.append(c)
            i += 1
            continue

        if c == "'":
            in_squote = True
            buf.append(c)
            i += 1
            continue

        if c == ";":
            stmt = _meaningful("".join(buf))
            if stmt:
                statements.append(stmt)
            buf = []
            i += 1
            continue

        buf.append(c)
        i += 1

    tail = _meaningful("".join(buf))
    if tail:
        statements.append(tail)
    return statements


_COMMENT_ONLY = re.compile(
    r"^(?:\s|--[^\n]*\n|/\*.*?\*/)*\s*$",
    re.DOTALL,
)


def _meaningful(chunk: str) -> str:
    text = chunk.strip()
    if not text or _COMMENT_ONLY.match(text):
        return ""
    return text


def write_dir(statements: list[str], dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for existing in dest.glob("*.sql"):
        existing.unlink()
    width = max(3, len(str(len(statements))))
    for idx, stmt in enumerate(statements, start=1):
        (dest / f"{idx:0{width}d}.sql").write_text(stmt + "\n", encoding="utf-8")


def _self_test() -> int:
    sample = """
-- header
DROP TABLE IF EXISTS default.foo;

CREATE VIEW default.foo AS
SELECT
    -- inner comment with a semicolon;
    tuple_state.1 AS name
FROM (SELECT 1)
WHERE s = 'a;b' AND t = 'it''s';
"""
    got = split_sql(sample)
    assert len(got) == 2, got
    assert "DROP TABLE" in got[0], got[0]
    assert "CREATE VIEW" in got[1]
    assert "a;b" in got[1]
    assert "it''s" in got[1]
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", help="SQL file (stdin if omitted)")
    parser.add_argument("--dir", help="write one numbered .sql file per statement")
    parser.add_argument("--test", action="store_true", help="run built-in checks")
    args = parser.parse_args()

    if args.test:
        return _self_test()

    text = Path(args.file).read_text(encoding="utf-8") if args.file else sys.stdin.read()
    statements = split_sql(text)
    if args.dir:
        write_dir(statements, Path(args.dir))
        return 0
    for stmt in statements:
        sys.stdout.write(stmt)
        sys.stdout.write("\n;\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
