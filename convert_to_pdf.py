"""
Convert SETUP_CHECKLIST.md to a beautifully styled PDF.
Run: python convert_to_pdf.py
Output: SETUP_CHECKLIST.pdf (in the same directory)
"""
import markdown
from weasyprint import HTML
from pathlib import Path

MD_FILE = Path("SETUP_CHECKLIST.md")
PDF_FILE = Path("SETUP_CHECKLIST.pdf")

# Read markdown
md_content = MD_FILE.read_text(encoding="utf-8")

# Convert markdown to HTML
html_body = markdown.markdown(
    md_content,
    extensions=["tables", "fenced_code", "codehilite", "toc", "nl2br"],
)

# Wrap in a styled HTML document
full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Block Bord AI — Setup Checklist</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

        :root {{
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --gray-50: #f9fafb;
            --gray-100: #f3f4f6;
            --gray-200: #e5e7eb;
            --gray-300: #d1d5db;
            --gray-600: #4b5563;
            --gray-700: #374151;
            --gray-800: #1f2937;
            --gray-900: #111827;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        @page {{
            size: A4;
            margin: 20mm 18mm 20mm 18mm;

            @bottom-center {{
                content: "Block Bord AI — Setup Checklist  |  Page " counter(page) " of " counter(pages);
                font-family: 'Inter', sans-serif;
                font-size: 8pt;
                color: #9ca3af;
            }}
        }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            color: var(--gray-800);
            line-height: 1.65;
            font-size: 10pt;
        }}

        h1 {{
            font-size: 22pt;
            font-weight: 800;
            color: var(--gray-900);
            margin-top: 0;
            margin-bottom: 6pt;
            letter-spacing: -0.5px;
            border-bottom: 3px solid var(--primary);
            padding-bottom: 10pt;
        }}

        h2 {{
            font-size: 15pt;
            font-weight: 700;
            color: var(--primary-dark);
            margin-top: 24pt;
            margin-bottom: 8pt;
            padding-bottom: 4pt;
            border-bottom: 1.5px solid var(--gray-200);
            page-break-after: avoid;
        }}

        h3 {{
            font-size: 12pt;
            font-weight: 600;
            color: var(--gray-800);
            margin-top: 16pt;
            margin-bottom: 6pt;
            page-break-after: avoid;
        }}

        h4 {{
            font-size: 10.5pt;
            font-weight: 600;
            color: var(--gray-700);
            margin-top: 12pt;
            margin-bottom: 4pt;
        }}

        p {{
            margin-bottom: 8pt;
        }}

        strong {{
            font-weight: 600;
            color: var(--gray-900);
        }}

        a {{
            color: var(--primary);
            text-decoration: none;
            font-weight: 500;
        }}

        ul, ol {{
            margin: 6pt 0 10pt 18pt;
        }}

        li {{
            margin-bottom: 3pt;
        }}

        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10pt 0 14pt 0;
            font-size: 9pt;
            page-break-inside: auto;
        }}

        thead {{
            background: var(--primary);
        }}

        th {{
            background: var(--primary);
            color: white;
            font-weight: 600;
            text-align: left;
            padding: 8pt 10pt;
            font-size: 9pt;
            letter-spacing: 0.3px;
        }}

        td {{
            padding: 7pt 10pt;
            border-bottom: 1px solid var(--gray-200);
            vertical-align: top;
        }}

        tr:nth-child(even) {{
            background: var(--gray-50);
        }}

        /* Code blocks */
        code {{
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            background: var(--gray-100);
            padding: 1pt 4pt;
            border-radius: 3pt;
            font-size: 8.5pt;
            color: var(--danger);
        }}

        pre {{
            background: var(--gray-900);
            color: #e5e7eb;
            padding: 12pt 14pt;
            border-radius: 6pt;
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            font-size: 8pt;
            line-height: 1.5;
            margin: 8pt 0 12pt 0;
            overflow-x: auto;
            page-break-inside: avoid;
        }}

        pre code {{
            background: none;
            color: #e5e7eb;
            padding: 0;
        }}

        /* Blockquotes (used for important notes) */
        blockquote {{
            border-left: 4px solid var(--primary);
            background: #eef2ff;
            padding: 10pt 14pt;
            margin: 10pt 0;
            border-radius: 0 6pt 6pt 0;
            font-size: 9.5pt;
        }}

        blockquote strong {{
            color: var(--primary-dark);
        }}

        /* Horizontal rules */
        hr {{
            border: none;
            border-top: 2px solid var(--gray-200);
            margin: 16pt 0;
        }}

        /* Checkboxes */
        input[type="checkbox"] {{
            margin-right: 6pt;
        }}

        /* Print styling */
        h2 {{
            page-break-before: auto;
        }}

        table {{
            page-break-inside: auto;
        }}

        tr {{
            page-break-inside: avoid;
        }}
    </style>
</head>
<body>
{html_body}
</body>
</html>"""

# Generate PDF
print("Generating PDF...")
HTML(string=full_html).write_pdf(str(PDF_FILE))
print(f"✅ PDF created: {PDF_FILE.resolve()}")
print(f"   File size: {PDF_FILE.stat().st_size / 1024:.1f} KB")
print(f"\nOpen it: start {PDF_FILE.name}")
