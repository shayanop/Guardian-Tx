"""Combine Deliverable A + B into one submission-style PDF.

Pure stdlib + the `markdown` package + headless Chrome/Edge (no LaTeX/pandoc).
Re-run this after you fill in the summaries and prose sections:

    python docs/build_pdf.py            -> docs/Phase1_GuardianTx_DRAFT.pdf

The DRAFT banner stays until you pass --final (only do that once the writing is done).
"""
from __future__ import annotations

import argparse
import html
import os
import re
import shutil
import subprocess
import sys

import markdown

HERE = os.path.dirname(os.path.abspath(__file__))
A = os.path.join(HERE, "deliverable_A_literature_review.md")
B = os.path.join(HERE, "deliverable_B_proposal.md")
OUT_HTML = os.path.join(HERE, "_phase1_combined.html")

CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
]

CSS = """
@page { size: A4; margin: 18mm 16mm; }
body { font-family: 'Segoe UI', Arial, sans-serif; font-size: 11pt; line-height: 1.45;
       color: #111; max-width: 820px; margin: 0 auto; }
h1 { font-size: 20pt; border-bottom: 2px solid #333; padding-bottom: 4px; }
h2 { font-size: 15pt; margin-top: 1.4em; border-bottom: 1px solid #ccc; }
h3 { font-size: 12.5pt; margin-top: 1.1em; }
table { border-collapse: collapse; width: 100%; font-size: 9pt; margin: 8px 0; }
th, td { border: 1px solid #999; padding: 4px 6px; vertical-align: top; text-align: left; }
th { background: #f0f0f0; }
code { font-family: Consolas, monospace; background: #f4f4f4; padding: 1px 3px; font-size: 9.5pt; }
pre { background: #f4f4f4; padding: 8px; overflow-x: auto; font-size: 9pt; white-space: pre-wrap; }
pre.mermaid { background: #fff; text-align: center; }
blockquote { border-left: 3px solid #c39; margin: 8px 0; padding: 4px 12px; background: #fdf0f6; }
.cover { border: 2px solid #b00; background: #fff3f3; padding: 14px 18px; margin-bottom: 20px; border-radius: 6px; }
.cover h1 { border: none; color: #b00; font-size: 16pt; margin: 0 0 6px; }
.pagebreak { page-break-before: always; }
"""

COVER = """
<div class="cover">
  <h1>&#9888; DRAFT &mdash; REWRITE IN YOUR OWN WORDS BEFORE SUBMITTING</h1>
  <p>This PDF combines <b>Deliverable A</b> (Literature Review &amp; Research Gaps)
  and <b>Deliverable B</b> (Project Proposal) for <b>GuardianTx</b>. All sections are
  drafted.</p>
  <p><b>Before submitting you must:</b> rewrite the prose in your own voice (the rubric
  forbids AI-generated text) and verify every figure against the source PDFs; fill the
  <code>[FILL]</code> items &mdash; member names/roll numbers, project code, P4's full
  author list, and the venue-ranking screenshots. Then re-run
  <code>python docs/build_pdf.py --final</code>.</p>
</div>
"""

MD_EXT = ["tables", "fenced_code", "toc", "sane_lists", "attr_list"]


def render_md(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    h = markdown.markdown(text, extensions=MD_EXT)
    # turn ```mermaid fenced blocks into mermaid-renderable <pre>, unescaping entities
    def fix(m):
        return '<pre class="mermaid">' + html.unescape(m.group(1)) + "</pre>"
    h = re.sub(r'<pre><code class="language-mermaid">(.*?)</code></pre>', fix, h, flags=re.S)
    return h


def build_html(final: bool) -> str:
    cover = "" if final else COVER
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<style>{CSS}</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/mermaid/10.9.1/mermaid.min.js"></script>
<script>window.addEventListener('load',()=>{{try{{mermaid.initialize({{startOnLoad:true}});}}catch(e){{}}}});</script>
</head><body>
{cover}
{render_md(A)}
<div class="pagebreak"></div>
{render_md(B)}
</body></html>"""
    with open(OUT_HTML, "w", encoding="utf-8") as f:
        f.write(doc)
    return OUT_HTML


def to_pdf(html_path: str, out_pdf: str) -> None:
    chrome = next((c for c in CHROME_CANDIDATES if os.path.exists(c)), None)
    if not chrome:
        sys.exit("No Chrome/Edge found; open " + html_path + " and print to PDF manually.")
    url = "file:///" + html_path.replace("\\", "/")
    subprocess.run([
        chrome, "--headless", "--disable-gpu", "--no-sandbox",
        "--run-all-compositor-stages-before-draw",
        "--virtual-time-budget=15000",
        f"--print-to-pdf={out_pdf}", "--no-pdf-header-footer", url,
    ], check=True, timeout=120)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--final", action="store_true", help="drop the DRAFT banner")
    ap.add_argument("-o", "--out", default=None)
    args = ap.parse_args()
    out = args.out or os.path.join(
        HERE, "Phase1_GuardianTx" + ("" if args.final else "_DRAFT") + ".pdf")
    to_pdf(build_html(args.final), out)
    print("wrote", out)


if __name__ == "__main__":
    main()
