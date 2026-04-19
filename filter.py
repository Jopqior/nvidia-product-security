#!/usr/bin/env python3
"""Generate filtered security bulletin copies under filter/.

The script scans year/security-bulletin directories (e.g., 2024/5510),
copies each bulletin directory into filter/<year>/<bulletin>, and then filters
CVE entries in the bulletin JSON and Markdown files by description keywords.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

MEMORY_SAFETY_TERMS = [
    "buffer overflow",
    "out of bounds",
    "out-of-bounds",
    "oob",
    "memory leak",
    "memory corruption",
    "segmentation fault",
    "null pointer",
    "uninitialized",
    "race condition",
    "heap",
    "stack",
    "invalid read",
    "invalid write",
]

YEAR_RE = re.compile(r"^\d{4}$")
BULLETIN_RE = re.compile(r"^\d+$")
CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
CVE_FILE_RE = re.compile(r"^(CVE-\d{4}-\d+)\.json(?:\.sha256)?$", re.IGNORECASE)


@dataclass
class BulletinResult:
    year: str
    bulletin: str
    total_cves: int
    kept_cves: int


def find_bulletin_dirs(source_root: Path) -> Iterable[Path]:
    for year_dir in sorted(source_root.iterdir()):
        if not year_dir.is_dir() or not YEAR_RE.match(year_dir.name):
            continue
        for bulletin_dir in sorted(year_dir.iterdir()):
            if bulletin_dir.is_dir() and BULLETIN_RE.match(bulletin_dir.name):
                yield bulletin_dir


def get_vuln_description(vulnerability: dict) -> str:
    notes = vulnerability.get("notes")
    if not isinstance(notes, list):
        return ""

    parts: list[str] = []
    for note in notes:
        if not isinstance(note, dict):
            continue
        text = note.get("text")
        if not isinstance(text, str):
            continue
        category = str(note.get("category", "")).lower()
        title = str(note.get("title", "")).lower()
        if category == "summary" or "vulnerability description" in title:
            parts.append(text)

    return " ".join(parts)


def is_memory_safety_related(description: str) -> bool:
    lowered = description.lower()
    return any(term in lowered for term in MEMORY_SAFETY_TERMS)


def filter_json_file(json_path: Path) -> tuple[int, set[str]]:
    with json_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return 0, set()

    filtered_vulns: list[dict] = []
    kept_cves: set[str] = set()

    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        cve = vuln.get("cve")
        if not isinstance(cve, str):
            continue

        description = get_vuln_description(vuln)
        if is_memory_safety_related(description):
            filtered_vulns.append(vuln)
            kept_cves.add(cve.upper())

    data["vulnerabilities"] = filtered_vulns

    with json_path.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=4)
        f.write("\n")

    return len(vulnerabilities), kept_cves


def should_keep_markdown_row(line: str, kept_cves: set[str]) -> bool:
    # Only filter markdown table rows that mention CVE IDs.
    if "|" not in line:
        return True

    cves_in_row = {m.group(0).upper() for m in CVE_RE.finditer(line)}
    if not cves_in_row:
        return True

    return any(cve in kept_cves for cve in cves_in_row)


def filter_markdown_file(md_path: Path, kept_cves: set[str]) -> None:
    with md_path.open("r", encoding="utf-8") as f:
        lines = f.readlines()

    filtered_lines = [line for line in lines if should_keep_markdown_row(line, kept_cves)]

    with md_path.open("w", encoding="utf-8", newline="\n") as f:
        f.writelines(filtered_lines)


def delete_filtered_cve_files(bulletin_dir: Path, kept_cves: set[str]) -> None:
    for path in bulletin_dir.iterdir():
        if not path.is_file():
            continue
        match = CVE_FILE_RE.match(path.name)
        if not match:
            continue
        cve_id = match.group(1).upper()
        if cve_id not in kept_cves:
            path.unlink()


def process_bulletin(source_root: Path, out_root: Path, bulletin_dir: Path) -> BulletinResult | None:
    relative = bulletin_dir.relative_to(source_root)
    year = relative.parts[0]
    bulletin = relative.parts[1]

    destination = out_root / relative
    shutil.copytree(bulletin_dir, destination, dirs_exist_ok=True)

    json_path = destination / f"{bulletin}.json"
    md_path = destination / f"{bulletin}.md"

    if not json_path.exists() or not md_path.exists():
        return None

    total_cves, kept_cves = filter_json_file(json_path)
    filter_markdown_file(md_path, kept_cves)
    delete_filtered_cve_files(destination, kept_cves)

    if not kept_cves:
        shutil.rmtree(destination)
        return None

    return BulletinResult(
        year=year,
        bulletin=bulletin,
        total_cves=total_cves,
        kept_cves=len(kept_cves),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Filter NVIDIA security bulletins to memory-safety CVEs.",
    )
    parser.add_argument(
        "--source-root",
        default=".",
        help="Repository root containing year directories (default: current directory).",
    )
    parser.add_argument(
        "--out-dir",
        default="filter",
        help="Output directory under source root (default: filter).",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Delete output directory before generating filtered files.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    source_root = Path(args.source_root).resolve()
    out_root = source_root / args.out_dir

    if args.clean and out_root.exists():
        shutil.rmtree(out_root)

    out_root.mkdir(parents=True, exist_ok=True)

    results: list[BulletinResult] = []
    for bulletin_dir in find_bulletin_dirs(source_root):
        result = process_bulletin(source_root, out_root, bulletin_dir)
        if result is not None:
            results.append(result)

    total_bulletins = len(results)
    total_cves = sum(item.total_cves for item in results)
    total_kept = sum(item.kept_cves for item in results)

    print(f"Processed bulletins: {total_bulletins}")
    print(f"Total CVEs before filter: {total_cves}")
    print(f"Total CVEs after filter:  {total_kept}")
    print(f"Output directory: {out_root}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
