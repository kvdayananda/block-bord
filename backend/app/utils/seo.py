"""Utility functions for SEO metadata.
Provides helpers to generate title and description for template rendering.
"""
from typing import Optional, Dict

def seo_context(page_name: str, description: Optional[str] = None) -> Dict[str, str]:
    """Return a dict with SEO-friendly title and meta description.
    Args:
        page_name: Human readable page name (e.g., "Login", "Dashboard").
        description: Optional custom description. If omitted, uses default.
    Returns:
        dict with keys `page_title` and `meta_description`.
    """
    title = f"Block Bord AI – {page_name}" if page_name else "Block Bord AI"
    default_desc = (
        "Block Bord AI is an AI‑powered cybersecurity platform that protects users from phishing attacks, "
        "malware, dark‑web leaks, and online threats with real‑time analysis and intelligent detection."
    )
    meta_desc = description if description else default_desc
    return {"page_title": title, "meta_description": meta_desc}
