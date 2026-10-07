#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


MARKER = "ABK FIDO: allow kernel domain access to the persisted metadata store."
PERMISSIONS = (("dir", "search"), ("file", "open"), ("file", "read"),
               ("file", "write"), ("file", "getattr"))
RULES = tuple(
    f'ksu_allow(db, "kernel", "metadata_file", "{kind}", "{permission}");'
    for kind, permission in PERMISSIONS
)
# Keep offsets intact while ignoring C comments and literals for brace matching.
NON_CODE = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
FUNCTION = re.compile(r'\bvoid\s+apply_kernelsu_rules\s*\(\s*(?:void\s*)?\)\s*\{')
POLICY_DB = re.compile(
    r'(?m)^[ \t]*(?:struct\s+policydb\s*\*\s*)?db\s*=\s*&\s*'
    r'(?:[A-Za-z_]\w*\s*(?:->|\.)\s*)+policydb\s*;'
)


def mask_non_code(text: str) -> str:
    return NON_CODE.sub(
        lambda match: re.sub(r'[^\r\n]', ' ', match.group()), text
    )


def rules_function(text: str) -> tuple[int, int, str]:
    masked = mask_non_code(text)
    functions = list(FUNCTION.finditer(masked))
    if len(functions) != 1:
        raise ValueError("expected one apply_kernelsu_rules() definition")
    start = functions[0].end()
    depth = 1
    for index in range(start, len(masked)):
        if masked[index] == '{':
            depth += 1
        elif masked[index] == '}':
            depth -= 1
            if depth == 0:
                return start, index, masked[start:index]
    raise ValueError("unterminated apply_kernelsu_rules() definition")


def patch_rules(text: str) -> str:
    start, end, masked_body = rules_function(text)
    body = text[start:end]
    if MARKER in text:
        # Both hook stages call this script. Only a complete in-function patch
        # counts as installed; a stale marker must not hide missing permissions.
        uncommented = NON_CODE.sub(
            lambda match: ' ' if match.group().startswith(('//', '/*')) else match.group(),
            body,
        )
        compact = re.sub(r'\s+', '', uncommented)
        if MARKER not in body or any(re.sub(r'\s+', '', rule) not in compact for rule in RULES):
            raise ValueError("ABK FIDO marker exists without complete in-function permissions")
        return text

    assignments = list(POLICY_DB.finditer(masked_body))
    if len(assignments) != 1:
        raise ValueError("expected one policydb initialization in apply_kernelsu_rules()")
    assignment = assignments[0]
    offset = start + assignment.end()
    line_start = text.rfind('\n', 0, start + assignment.start()) + 1
    indent = re.match(r'[ \t]*', text[line_start:]).group() or '    '
    newline = '\r\n' if '\r\n' in text else '\n'
    block = newline.join(indent + line for line in (f'/* {MARKER} */', *RULES))
    return text[:offset] + newline * 2 + block + text[offset:]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: patch_kernelsu_sepolicy_for_abk_fido.py <rules.c>", file=sys.stderr)
        return 1
    path = Path(sys.argv[1])
    with path.open(encoding='utf-8', newline='') as handle:
        original = handle.read()
    try:
        patched = patch_rules(original)
    except ValueError as exc:
        print(f"cannot inject ABK FIDO permissions in {path}: {exc}", file=sys.stderr)
        return 1
    if patched != original:
        with path.open('w', encoding='utf-8', newline='') as handle:
            handle.write(patched)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
