#!/usr/bin/env python3
"""Build a static HTML site from filtered CVEs for GitHub Pages.

Input layout (default):
    filter/<year>/<bulletin>/<bulletin>.json

Output layout (default):
    docs/index.html
    docs/<year>/index.html
    docs/<year>/<bulletin>/index.html
"""

from __future__ import annotations

import argparse
import html
import json
import re
import shutil
from pathlib import Path

YEAR_RE = re.compile(r"^\d{4}$")
BULLETIN_RE = re.compile(r"^\d+$")

CSS = """
:root {
  --bg: #f7f7f2;
  --panel: #ffffff;
  --ink: #1e2421;
  --muted: #617069;
  --line: #d7ddd7;
  --accent: #005f73;
  --accent-soft: #e8f4f6;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: Georgia, "Times New Roman", serif;
  background: linear-gradient(180deg, #f7f7f2 0%, #eef3ef 100%);
  color: var(--ink);
}
.wrapper {
  max-width: 980px;
  margin: 0 auto;
  padding: 28px 18px 42px;
}
.header {
  margin-bottom: 24px;
}
.header h1 {
  margin: 0;
  font-size: 2.1rem;
  letter-spacing: 0.3px;
}
.subtitle {
  margin: 8px 0 0;
  color: var(--muted);
}
.panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 12px;
  padding: 16px;
  margin-bottom: 16px;
  box-shadow: 0 2px 12px rgba(21, 28, 25, 0.05);
}
.search-panel {
    display: grid;
    gap: 8px;
}
.search-label {
    font-size: 0.92rem;
    color: var(--muted);
}
.search-input {
    width: 100%;
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 12px 14px;
    font: inherit;
    color: var(--ink);
    background: #fff;
}
.search-input:focus {
    outline: 2px solid rgba(0, 95, 115, 0.18);
    border-color: var(--accent);
}
.search-hint {
    font-size: 0.86rem;
    color: var(--muted);
}
.search-empty {
    display: none;
    color: var(--muted);
    margin-top: 12px;
}
.list {
  list-style: none;
  margin: 0;
  padding: 0;
}
.list li {
  padding: 10px 0;
  border-bottom: 1px solid var(--line);
}
.list li:last-child { border-bottom: 0; }
a {
  color: var(--accent);
  text-decoration: none;
}
a:hover { text-decoration: underline; }
.badge {
  display: inline-block;
  font-size: 0.82rem;
  color: var(--accent);
  background: var(--accent-soft);
  border: 1px solid #c7e4ea;
  border-radius: 999px;
  padding: 2px 10px;
  margin-left: 8px;
}
.kv {
  color: var(--muted);
  font-size: 0.92rem;
  margin-top: 4px;
}
.cve-title {
  margin: 0;
  font-size: 1.15rem;
}
.desc {
  margin: 8px 0 0;
  line-height: 1.45;
}
.search-hidden {
    display: none !important;
}
.footer {
  margin-top: 28px;
  color: var(--muted);
  font-size: 0.9rem;
}
@media (max-width: 700px) {
  .header h1 { font-size: 1.7rem; }
}
""".strip()

SCRIPT = """
<script>
function normalizeText(value) {
    return (value || '').toLowerCase().replace(/\\s+/g, ' ').trim();
}

function attachSearch(inputId, itemSelector, emptyId) {
    const input = document.getElementById(inputId);
    if (!input) {
        return;
    }

    const emptyState = emptyId ? document.getElementById(emptyId) : null;
    const items = Array.from(document.querySelectorAll(itemSelector));

    function applyFilter() {
        const query = normalizeText(input.value);
        let visibleCount = 0;

        for (const item of items) {
            const haystack = normalizeText(item.getAttribute('data-search') || item.textContent);
            const matches = !query || haystack.includes(query);
            item.classList.toggle('search-hidden', !matches);
            if (matches) {
                visibleCount += 1;
            }
        }

        if (emptyState) {
            emptyState.style.display = visibleCount === 0 ? 'block' : 'none';
        }
    }

    input.addEventListener('input', applyFilter);
    applyFilter();
}

window.addEventListener('DOMContentLoaded', function () {
    attachSearch('home-search', '.home-item', 'home-empty');
    attachSearch('year-search', '.year-item', 'year-empty');
    attachSearch('bulletin-search', '.bulletin-item', 'bulletin-empty');
});
</script>
""".strip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate GitHub Pages HTML from filter folder.")
    parser.add_argument("--input", default="filter", help="Filtered CVE root directory (default: filter)")
    parser.add_argument("--output", default="docs", help="Static site output directory (default: docs)")
    parser.add_argument("--clean", action="store_true", help="Delete output directory before generation")
    return parser.parse_args()


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def cve_description(vuln: dict) -> str:
    notes = vuln.get("notes")
    if not isinstance(notes, list):
        return ""
    for note in notes:
        if not isinstance(note, dict):
            continue
        if str(note.get("category", "")).lower() == "summary":
            text = note.get("text")
            if isinstance(text, str):
                return text
    for note in notes:
        if not isinstance(note, dict):
            continue
        title = str(note.get("title", "")).lower()
        if "vulnerability description" in title:
            text = note.get("text")
            if isinstance(text, str):
                return text
    return ""


def render_page(title: str, body: str, subtitle: str = "") -> str:
    subtitle_html = f'<p class="subtitle">{subtitle}</p>' if subtitle else ""
    return (
        "<!doctype html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "  <meta charset=\"utf-8\">\n"
        "  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
        f"  <title>{html.escape(title)}</title>\n"
        f"  <style>{CSS}</style>\n"
        f"  {SCRIPT}\n"
        "</head>\n"
        "<body>\n"
        "  <main class=\"wrapper\">\n"
        "    <header class=\"header\">\n"
        f"      <h1>{html.escape(title)}</h1>\n"
        f"      {subtitle_html}\n"
        "    </header>\n"
        f"    {body}\n"
        "    <footer class=\"footer\">Generated from filter folder for GitHub Pages.</footer>\n"
        "  </main>\n"
        "</body>\n"
        "</html>\n"
    )


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def collect_years(input_root: Path) -> list[Path]:
    years: list[Path] = []
    for p in sorted(input_root.iterdir()):
        if p.is_dir() and YEAR_RE.match(p.name):
            years.append(p)
    return years


def collect_bulletins(year_dir: Path) -> list[Path]:
    bulletins: list[Path] = []
    for p in sorted(year_dir.iterdir()):
        if p.is_dir() and BULLETIN_RE.match(p.name):
            bulletins.append(p)
    return bulletins


def build_bulletin_page(out_dir: Path, year: str, bulletin: str, bulletin_json: dict) -> int:
    title = str(bulletin_json.get("document", {}).get("title", f"Bulletin {bulletin}"))
    updated = str(bulletin_json.get("document", {}).get("tracking", {}).get("current_release_date", ""))

    vulnerabilities = bulletin_json.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        vulnerabilities = []

    parts: list[str] = []
    parts.append('<section class="panel"><a href="../index.html">Back to Year</a> | <a href="../../index.html">Home</a></section>')
    parts.append('<section class="panel search-panel">')
    parts.append('<label class="search-label" for="bulletin-search">Search CVEs</label>')
    parts.append('<input id="bulletin-search" class="search-input" type="search" placeholder="Search by CVE, CWE, or description">')
    parts.append('<div class="search-hint">Filters the CVE cards on this bulletin page.</div>')
    parts.append('<div id="bulletin-empty" class="search-empty">No matching CVEs found.</div>')
    parts.append('</section>')
    parts.append('<section class="panel">')
    parts.append(f"<div class=\"kv\">Year: {html.escape(year)} | Bulletin: {html.escape(bulletin)}</div>")
    if updated:
        parts.append(f"<div class=\"kv\">Updated: {html.escape(updated)}</div>")
    parts.append(f"<div class=\"kv\">CVEs in filter: {len(vulnerabilities)}</div>")
    parts.append("</section>")

    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        cve = str(vuln.get("cve", "Unknown CVE"))
        cwe = str(vuln.get("cwe", {}).get("id", ""))
        desc = cve_description(vuln)
        cve_link = f"https://www.cve.org/CVERecord?id={cve}"
        search_text = " ".join(part for part in [cve, cwe, desc] if part)

        parts.append(f'<section class="panel bulletin-item" data-search="{html.escape(search_text)}">')
        parts.append(
            f"<h2 class=\"cve-title\"><a href=\"{html.escape(cve_link)}\" target=\"_blank\" rel=\"noopener\">{html.escape(cve)}</a>"
            + (f" <span class=\"badge\">{html.escape(cwe)}</span>" if cwe else "")
            + "</h2>"
        )
        if desc:
            parts.append(f"<p class=\"desc\">{html.escape(desc)}</p>")
        parts.append("</section>")

    body = "\n".join(parts)
    page = render_page(title=title, subtitle=f"Filtered CVE list for bulletin {year}/{bulletin}", body=body)
    write_text(out_dir / year / bulletin / "index.html", page)
    return len(vulnerabilities)


def build_year_page(out_dir: Path, year: str, bulletin_stats: list[tuple[str, int]]) -> None:
    items: list[str] = []
    items.append('<section class="panel"><a href="../index.html">Back to Home</a></section>')
    items.append('<section class="panel search-panel">')
    items.append('<label class="search-label" for="year-search">Search bulletins</label>')
    items.append('<input id="year-search" class="search-input" type="search" placeholder="Search by bulletin number or CVE count">')
    items.append('<div class="search-hint">Filters the bulletin list on this year page.</div>')
    items.append('<div id="year-empty" class="search-empty">No matching bulletins found.</div>')
    items.append('</section>')
    items.append('<section class="panel">')
    items.append('<ul class="list">')
    for bulletin, cve_count in bulletin_stats:
        search_text = f"Bulletin {bulletin} {cve_count} CVEs"
        items.append(
            f"<li class=\"year-item\" data-search=\"{html.escape(search_text)}\">"
            f"<a href=\"./{html.escape(bulletin)}/index.html\">Bulletin {html.escape(bulletin)}</a>"
            f"<span class=\"badge\">{cve_count} CVEs</span>"
            "</li>"
        )
    items.append("</ul>")
    items.append("</section>")

    page = render_page(
        title=f"{year} Bulletins",
        subtitle="Bulletins with filtered memory-safety CVEs",
        body="\n".join(items),
    )
    write_text(out_dir / year / "index.html", page)


def build_home_page(out_dir: Path, year_stats: list[tuple[str, int, int]]) -> None:
    items: list[str] = []
    items.append('<section class="panel search-panel">')
    items.append('<label class="search-label" for="home-search">Search years</label>')
    items.append('<input id="home-search" class="search-input" type="search" placeholder="Search by year, bulletin count, or CVE count">')
    items.append('<div class="search-hint">Filters the year list on the home page.</div>')
    items.append('<div id="home-empty" class="search-empty">No matching years found.</div>')
    items.append('</section>')
    items.append('<section class="panel">')
    items.append('<ul class="list">')
    for year, bulletin_count, cve_count in year_stats:
        search_text = f"{year} {bulletin_count} bulletins {cve_count} CVEs"
        items.append(
            f"<li class=\"home-item\" data-search=\"{html.escape(search_text)}\">"
            f"<a href=\"./{html.escape(year)}/index.html\">{html.escape(year)}</a>"
            f"<span class=\"badge\">{bulletin_count} bulletins</span>"
            f"<span class=\"badge\">{cve_count} CVEs</span>"
            "</li>"
        )
    items.append("</ul>")
    items.append("</section>")

    page = render_page(
        title="NVIDIA Product Security - Filtered CVEs",
        subtitle="Memory-safety related CVEs generated from the filter folder",
        body="\n".join(items),
    )
    write_text(out_dir / "index.html", page)


def main() -> int:
    args = parse_args()
    input_root = Path(args.input).resolve()
    output_root = Path(args.output).resolve()

    if not input_root.exists() or not input_root.is_dir():
        raise SystemExit(f"Input directory does not exist: {input_root}")

    if args.clean and output_root.exists():
        shutil.rmtree(output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / ".nojekyll").write_text("", encoding="utf-8")

    year_stats: list[tuple[str, int, int]] = []
    total_bulletins = 0
    total_cves = 0

    for year_dir in collect_years(input_root):
        year = year_dir.name
        bulletin_stats: list[tuple[str, int]] = []

        for bulletin_dir in collect_bulletins(year_dir):
            bulletin = bulletin_dir.name
            json_path = bulletin_dir / f"{bulletin}.json"
            if not json_path.exists():
                continue

            data = read_json(json_path)
            cve_count = build_bulletin_page(output_root, year, bulletin, data)
            bulletin_stats.append((bulletin, cve_count))
            total_bulletins += 1
            total_cves += cve_count

        if bulletin_stats:
            build_year_page(output_root, year, bulletin_stats)
            year_stats.append((year, len(bulletin_stats), sum(c for _, c in bulletin_stats)))

    build_home_page(output_root, year_stats)

    print(f"Generated site: {output_root}")
    print(f"Years: {len(year_stats)}")
    print(f"Bulletins: {total_bulletins}")
    print(f"CVEs: {total_cves}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
