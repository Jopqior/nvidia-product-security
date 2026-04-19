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
  max-width: 1180px;
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
.search-count {
  font-size: 0.92rem;
  color: var(--muted);
}
.search-empty {
  display: none;
  color: var(--muted);
  margin-top: 12px;
}
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
.search-hidden {
  display: none !important;
}
.summary {
  display: grid;
  gap: 4px;
}
.table-wrap {
  overflow-x: auto;
}
.result-table {
  width: 100%;
  min-width: 1120px;
  border-collapse: collapse;
}
.result-table th,
.result-table td {
  border-bottom: 1px solid var(--line);
  padding: 12px 12px;
  text-align: left;
  vertical-align: top;
}
.result-table th {
  background: #f9fbf8;
  color: var(--muted);
  font-size: 0.82rem;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  position: sticky;
  top: 0;
}
.result-table tbody tr:nth-child(even) {
  background: #fcfcfa;
}
.result-table tbody tr:hover {
  background: #f4f8f4;
}
.scope-block,
.detail-block {
  display: grid;
  gap: 6px;
}
.detail-summary,
.muted-line {
  color: var(--muted);
  font-size: 0.9rem;
  line-height: 1.4;
}
.detail-summary {
  font-size: 0.92rem;
}
.count-pill {
  display: inline-block;
  font-size: 0.8rem;
  color: var(--accent);
  background: var(--accent-soft);
  border: 1px solid #c7e4ea;
  border-radius: 999px;
  padding: 2px 10px;
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

function attachSearchTable(inputId, rowSelector, emptyId, countId) {
  const input = document.getElementById(inputId);
  if (!input) {
    return;
  }

  const emptyState = emptyId ? document.getElementById(emptyId) : null;
  const countState = countId ? document.getElementById(countId) : null;
  const rows = Array.from(document.querySelectorAll(rowSelector));

  function applyFilter() {
    const query = normalizeText(input.value);
    let visibleCount = 0;

    for (const row of rows) {
      const haystack = normalizeText(row.getAttribute('data-search') || row.textContent);
      const matches = !query || haystack.includes(query);
      row.classList.toggle('search-hidden', !matches);
      if (matches) {
        visibleCount += 1;
      }
    }

    if (emptyState) {
      emptyState.style.display = visibleCount === 0 ? 'block' : 'none';
    }
    if (countState) {
      countState.textContent = String(visibleCount);
    }
  }

  input.addEventListener('input', applyFilter);
  applyFilter();
}

window.addEventListener('DOMContentLoaded', function () {
  attachSearchTable('home-search', '.result-row', 'home-empty', 'home-count');
  attachSearchTable('year-search', '.result-row', 'year-empty', 'year-count');
  attachSearchTable('bulletin-search', '.result-row', 'bulletin-empty', 'bulletin-count');
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


def bulletin_summary(bulletin_json: dict) -> str:
    document = bulletin_json.get("document")
    if not isinstance(document, dict):
        return ""
    notes = document.get("notes")
    if not isinstance(notes, list):
        return ""
    for note in notes:
        if not isinstance(note, dict):
            continue
        if str(note.get("category", "")).lower() == "summary":
            text = note.get("text")
            if isinstance(text, str):
                return text
    return ""


def bulletin_title(bulletin_json: dict, bulletin: str) -> str:
    document = bulletin_json.get("document")
    if isinstance(document, dict):
        title = document.get("title")
        if isinstance(title, str) and title.strip():
            return title.strip()
    return f"Bulletin {bulletin}"


def bulletin_release_date(bulletin_json: dict) -> str:
    document = bulletin_json.get("document")
    if not isinstance(document, dict):
        return ""
    tracking = document.get("tracking")
    if not isinstance(tracking, dict):
        return ""
    release_date = tracking.get("current_release_date")
    return str(release_date) if release_date else ""


def collect_years(input_root: Path) -> list[Path]:
    years: list[Path] = []
    for path in sorted(input_root.iterdir()):
        if path.is_dir() and YEAR_RE.match(path.name):
            years.append(path)
    return years


def collect_bulletins(year_dir: Path) -> list[Path]:
    bulletins: list[Path] = []
    for path in sorted(year_dir.iterdir()):
        if path.is_dir() and BULLETIN_RE.match(path.name):
            bulletins.append(path)
    return bulletins


def collect_site_data(input_root: Path) -> tuple[dict[str, dict], list[dict]]:
    site: dict[str, dict] = {}
    all_records: list[dict] = []

    for year_dir in collect_years(input_root):
        year = year_dir.name
        year_entry = {
            "year": year,
            "bulletins": [],
            "bulletin_count": 0,
            "cve_count": 0,
        }

        for bulletin_dir in collect_bulletins(year_dir):
            bulletin = bulletin_dir.name
            json_path = bulletin_dir / f"{bulletin}.json"
            if not json_path.exists():
                continue

            bulletin_json = read_json(json_path)
            bulletin_entry = {
                "year": year,
                "bulletin": bulletin,
                "title": bulletin_title(bulletin_json, bulletin),
                "summary": bulletin_summary(bulletin_json),
                "release_date": bulletin_release_date(bulletin_json),
                "cves": [],
                "cve_count": 0,
            }

            vulnerabilities = bulletin_json.get("vulnerabilities")
            if not isinstance(vulnerabilities, list):
                vulnerabilities = []

            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                bulletin_entry["cves"].append(
                    {
                        "year": year,
                        "bulletin": bulletin,
                        "title": bulletin_entry["title"],
                        "summary": bulletin_entry["summary"],
                        "release_date": bulletin_entry["release_date"],
                        "cve": str(vuln.get("cve", "Unknown CVE")),
                        "cwe": str(vuln.get("cwe", {}).get("id", "")),
                        "description": cve_description(vuln),
                    }
                )

            bulletin_entry["cves"].sort(key=lambda item: (item["release_date"], item["cve"]), reverse=True)
            bulletin_entry["cve_count"] = len(bulletin_entry["cves"])
            year_entry["bulletins"].append(bulletin_entry)

            for record in bulletin_entry["cves"]:
                record["bulletin_cve_count"] = bulletin_entry["cve_count"]

        year_entry["bulletins"].sort(key=lambda item: item["bulletin"])
        year_entry["bulletin_count"] = len(year_entry["bulletins"])
        year_entry["cve_count"] = sum(item["cve_count"] for item in year_entry["bulletins"])

        for bulletin_entry in year_entry["bulletins"]:
            for record in bulletin_entry["cves"]:
                record["year_bulletin_count"] = year_entry["bulletin_count"]
                record["year_cve_count"] = year_entry["cve_count"]
                all_records.append(record)

        site[year] = year_entry

    all_records.sort(key=lambda item: (item["release_date"], item["cve"]), reverse=True)
    return site, all_records


def search_terms_for_record(record: dict, scope: str) -> str:
    terms: list[str] = [
        record.get("release_date", ""),
        record.get("cve", ""),
        record.get("cwe", ""),
        record.get("description", ""),
        record.get("title", ""),
        record.get("summary", ""),
    ]

    if scope == "home":
        terms.extend([
            record.get("year", ""),
            str(record.get("year_bulletin_count", "")),
            str(record.get("year_cve_count", "")),
            record.get("bulletin", ""),
            str(record.get("bulletin_cve_count", "")),
        ])
    elif scope == "year":
        terms.extend([
        str(record.get("year_bulletin_count", "")),
        str(record.get("year_cve_count", "")),
            str(record.get("bulletin_cve_count", "")),
            record.get("bulletin", ""),
        ])
    else:
        terms.append(str(record.get("bulletin_cve_count", "")))

    return " ".join(part for part in terms if part)


def scope_path(scope: str, year: str, bulletin: str) -> tuple[str, str]:
    if scope == "home":
        return f"./{year}/index.html", f"./{year}/{bulletin}/index.html"
    if scope == "year":
        return "./index.html", f"./{bulletin}/index.html"
    return "../index.html", "./index.html"


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


def render_search_panel(scope: str, total_count: int, hint: str) -> str:
    input_id = f"{scope}-search"
    count_id = f"{scope}-count"
    empty_id = f"{scope}-empty"
    return (
        '<section class="panel search-panel">'
        f'<label class="search-label" for="{input_id}">Search CVEs</label>'
        f'<input id="{input_id}" class="search-input" type="search" placeholder="Search CVEs in this view">'
        f'<div class="search-hint">{html.escape(hint)}</div>'
        f'<div class="search-count">Matching CVEs: <span id="{count_id}">{total_count}</span></div>'
        f'<div id="{empty_id}" class="search-empty">No matching CVEs found.</div>'
        '</section>'
    )


def render_results_table(scope: str, records: list[dict]) -> str:
    if not records:
        return '<section class="panel">No CVEs found for this view.</section>'

    rows: list[str] = []
    for record in records:
        year_href, bulletin_href = scope_path(scope, record["year"], record["bulletin"])
        cve_href = f"https://www.cve.org/CVERecord?id={record['cve']}"
        search_text = search_terms_for_record(record, scope)
        release_date = html.escape(str(record.get("release_date", ""))[:10])
        bulletin_summary_text = html.escape(record.get("summary", ""))
        scope_cell = (
            '<div class="scope-block">'
            f'<div><a href="{html.escape(year_href)}">{html.escape(record["year"])}</a> '
            f'<span class="count-pill">{record.get("year_bulletin_count", 0)} bulletins</span></div>'
            f'<div><a href="{html.escape(bulletin_href)}">{html.escape(record["bulletin"])}</a> '
            f'<span class="count-pill">{record.get("bulletin_cve_count", 0)} CVEs</span></div>'
            '</div>'
        )
        detail_cell = (
            '<div class="detail-block">'
            f'<div class="detail-summary"><a href="{html.escape(cve_href)}" target="_blank" rel="noopener">{html.escape(record["cve"])}</a></div>'
            f'<div class="muted-line">{html.escape(record.get("cwe", ""))}</div>'
            f'<div>{html.escape(record.get("description", ""))}</div>'
            f'<div class="detail-summary">{html.escape(record.get("title", ""))}</div>'
            f'<div class="detail-summary">{bulletin_summary_text}</div>'
            '</div>'
        )
        rows.append(
            f'<tr class="result-row" data-search="{html.escape(search_text)}">'
            f'<td>{release_date}</td>'
            f'<td>{scope_cell}</td>'
            f'<td>{detail_cell}</td>'
            '</tr>'
        )

    return (
        '<section class="panel table-panel">'
        '<div class="table-wrap">'
        '<table class="result-table">'
        '<thead><tr>'
        '<th>Date</th>'
        '<th>Scope</th>'
        '<th>CVE / Details</th>'
        '</tr></thead>'
        '<tbody>'
        + ''.join(rows)
        + '</tbody></table></div></section>'
    )


def build_home_page(out_dir: Path, year_stats: list[dict], records: list[dict]) -> None:
    total_years = len(year_stats)
    total_bulletins = sum(item["bulletin_count"] for item in year_stats)
    total_cves = sum(item["cve_count"] for item in year_stats)
    body = [
        '<section class="panel summary">',
        f'<div class="kv">Years: {total_years}</div>',
        f'<div class="kv">Bulletins: {total_bulletins}</div>',
        f'<div class="kv">CVEs: {total_cves}</div>',
        '</section>',
        render_search_panel(
            'home',
            len(records),
            'Search by year, bulletin count, CVE count, CVE description, or CWE.',
        ),
        render_results_table('home', records),
    ]
    page = render_page(
        title='NVIDIA Product Security - Filtered CVEs',
        subtitle='Search CVEs across years, bulletins, counts, descriptions, and CWE',
        body='\n'.join(body),
    )
    write_text(out_dir / 'index.html', page)


def build_year_page(out_dir: Path, year: str, year_entry: dict, records: list[dict]) -> None:
    body = [
    '<section class="panel"><a href="../index.html">Back to Home</a></section>',
        '<section class="panel summary">',
        f'<div class="kv">Bulletins: {year_entry["bulletin_count"]}</div>',
        f'<div class="kv">CVEs: {year_entry["cve_count"]}</div>',
        '</section>',
        render_search_panel(
            'year',
            len(records),
            'Search by bulletin count, CVE count, CVE description, or CWE.',
        ),
        render_results_table('year', records),
    ]
    page = render_page(
        title=f'{year} Bulletins',
        subtitle='Search CVEs in this year by count, description, or CWE',
        body='\n'.join(body),
    )
    write_text(out_dir / year / 'index.html', page)


def build_bulletin_page(out_dir: Path, year: str, bulletin_entry: dict) -> int:
    records = bulletin_entry['cves']
    body = [
    '<section class="panel"><a href="../index.html">Back to Year</a> | <a href="../../index.html">Home</a></section>',
        '<section class="panel summary">',
        f'<div class="kv">Year: {html.escape(year)} | Bulletin: {html.escape(bulletin_entry["bulletin"])}</div>',
        f'<div class="kv">Title: {html.escape(bulletin_entry["title"])}</div>',
        f'<div class="kv">Updated: {html.escape(bulletin_entry["release_date"])}</div>' if bulletin_entry['release_date'] else '',
        f'<div class="kv">CVEs: {bulletin_entry["cve_count"]}</div>',
        '</section>',
        render_search_panel(
            'bulletin',
            len(records),
            'Search by CVE count, CVE description, or CWE.',
        ),
        render_results_table('bulletin', records),
    ]
    page = render_page(
        title=bulletin_entry['title'],
        subtitle=f'Search CVEs in bulletin {year}/{bulletin_entry["bulletin"]} by description or CWE',
        body='\n'.join(part for part in body if part),
    )
    write_text(out_dir / year / bulletin_entry['bulletin'] / 'index.html', page)
    return len(records)


def main() -> int:
    args = parse_args()
    input_root = Path(args.input).resolve()
    output_root = Path(args.output).resolve()

    if not input_root.exists() or not input_root.is_dir():
        raise SystemExit(f"Input directory does not exist: {input_root}")

    if args.clean and output_root.exists():
        shutil.rmtree(output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / '.nojekyll').write_text('', encoding='utf-8')

    site, all_records = collect_site_data(input_root)
    year_stats = list(site.values())

    for year in sorted(site):
        year_entry = site[year]
        year_records = [record for bulletin in year_entry['bulletins'] for record in bulletin['cves']]
        year_records.sort(key=lambda item: (item['release_date'], item['cve']), reverse=True)
        build_year_page(output_root, year, year_entry, year_records)

        for bulletin_entry in year_entry['bulletins']:
            build_bulletin_page(output_root, year, bulletin_entry)

    build_home_page(output_root, year_stats, all_records)

    total_bulletins = sum(year_entry['bulletin_count'] for year_entry in year_stats)
    total_cves = sum(year_entry['cve_count'] for year_entry in year_stats)

    print(f"Generated site: {output_root}")
    print(f"Years: {len(year_stats)}")
    print(f"Bulletins: {total_bulletins}")
    print(f"CVEs: {total_cves}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
