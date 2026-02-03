"""
OWASP Cheat Sheet Viewer
========================

A dynamic Streamlit application for browsing and exploring OWASP Cheat Sheets.
Uses Firecrawl API for web scraping with disk caching.
"""

import json
import logging
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import pandas as pd
import streamlit as st
import yaml
from bs4 import BeautifulSoup

from src.config_manager import ConfigManager
from src.cache_manager import CacheManager
from src.firecrawl_client import FirecrawlClient
from src.cheatsheet_parser import CheatsheetParser
from src.models import CheatSheet, CheatSheetIndex
from src.top10_data import LLM_RISKS, LLM_RISK_ATTACK_EXAMPLES




# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Page configuration
st.set_page_config(
    page_title="OWASP Cheat Sheet Viewer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1E3A5F;
        text-align: center;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #666;
        text-align: center;
        margin-bottom: 2rem;
    }
    .risk-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 15px;
        color: white;
        margin-bottom: 1rem;
    }
    .severity-critical {
        background-color: #ff4b4b;
        color: white;
        padding: 0.2rem 0.6rem;
        border-radius: 5px;
        font-size: 0.8rem;
    }
    .severity-high {
        background-color: #ff8c00;
        color: white;
        padding: 0.2rem 0.6rem;
        border-radius: 5px;
        font-size: 0.8rem;
    }
    .severity-medium {
        background-color: #ffd700;
        color: black;
        padding: 0.2rem 0.6rem;
        border-radius: 5px;
        font-size: 0.8rem;
    }
    .severity-low {
        background-color: #32cd32;
        color: white;
        padding: 0.2rem 0.6rem;
        border-radius: 5px;
        font-size: 0.8rem;
    }
    .mitigation-box {
        background-color: #e8f5e9;
        border-left: 4px solid #4caf50;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0 8px 8px 0;
    }
    .attack-box {
        background-color: #ffebee;
        border-left: 4px solid #f44336;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0 8px 8px 0;
    }
    .info-box {
        background-color: #e3f2fd;
        border-left: 4px solid #2196f3;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0 8px 8px 0;
    }
    .warning-box {
        background-color: #fff3e0;
        border-left: 4px solid #ff9800;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0 8px 8px 0;
    }
    .cache-info {
        font-size: 0.8rem;
        color: #888;
        text-align: right;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_resource
def get_config() -> ConfigManager:
    """Get or create configuration manager (cached)."""
    return ConfigManager()


@st.cache_resource
def get_cache_manager() -> CacheManager:
    """Get or create cache manager (cached)."""
    config = get_config()
    return CacheManager(config)


@st.cache_resource
def get_firecrawl_client() -> FirecrawlClient:
    """Get or create Firecrawl client (cached)."""
    config = get_config()
    cache = get_cache_manager()
    return FirecrawlClient(config, cache)


@st.cache_resource
def get_parser() -> CheatsheetParser:
    """Get or create cheatsheet parser (cached)."""
    config = get_config()
    return CheatsheetParser(config)


@st.cache_data(ttl=3600)  # Cache for 1 hour
def fetch_cheatsheet_index() -> CheatSheetIndex:
    """
    Fetch the index of available cheat sheets.
    
    Uses Firecrawl to scrape the OWASP Glossary.html page.
    Results are cached on disk for 7 days.
    """
    config = get_config()
    cache = get_cache_manager()
    client = get_firecrawl_client()
    parser = get_parser()
    
    # Check disk cache first
    cache_key = "cheatsheet_index_v2"
    cached_data = cache.get(cache_key)
    
    if cached_data:
        logger.info("Using cached cheat sheet index")
        return CheatSheetIndex(**cached_data)
    
    # Fetch from Glossary.html
    try:
        glossary_url = config.get("owasp.cheatsheets_index", "https://cheatsheetseries.owasp.org/Glossary.html")
        logger.info(f"Fetching cheat sheet index from: {glossary_url}")
        
        scraped = client.scrape_url(
            glossary_url,
            formats=["html", "markdown"],
            only_main_content=False,  # Need full page for sidebar navigation
            use_cache=True,
        )
        
        if scraped.get("success"):
            # Use Glossary-specific parser to avoid non-cheatsheet entries
            index = parser.parse_glossary_page(
                scraped.get("html", ""),
            )
            
            if index.total_count > 0:
                logger.info(f"Successfully parsed {index.total_count} cheat sheets")
                cache.set(cache_key, index.model_dump(), is_index=True)
                return index
            
    except Exception as e:
        logger.error(f"Failed to fetch cheat sheet index: {e}")
    
    # Return empty index on failure
    return CheatSheetIndex(
        cheatsheets=[],
        categories=[],
        last_fetched=datetime.now(),
        total_count=0,
    )


@st.cache_data(ttl=86400)  # Cache for 24 hours
def fetch_cheatsheet(url: str, title: str) -> Optional[CheatSheet]:
    """
    Fetch and parse a single cheat sheet.
    
    Args:
        url: Cheat sheet URL
        title: Cheat sheet title (for cache key)
        
    Returns:
        Parsed CheatSheet or None on failure
    """
    cache = get_cache_manager()
    client = get_firecrawl_client()
    parser = get_parser()
    
    # Check disk cache first
    cached_data = cache.get(url)
    if cached_data and "parsed" in cached_data:
        return CheatSheet(**cached_data["parsed"])
    
    try:
        # Fetch content
        scraped = client.scrape_url(
            url,
            formats=["markdown", "html"],
            only_main_content=True,
            use_cache=True,
        )
        
        if scraped.get("success"):
            # Parse content
            cheatsheet = parser.parse_cheatsheet(
                url,
                scraped.get("html", ""),
                scraped.get("markdown", ""),
            )
            
            # Cache parsed result
            cache_data = {
                "raw": scraped,
                "parsed": cheatsheet.model_dump(),
            }
            cache.set(url, cache_data)
            
            return cheatsheet
            
    except Exception as e:
        logger.error(f"Failed to fetch cheat sheet {url}: {e}")
    
    return None


def list_local_checksheets(directory: str = "data/checksheets") -> list[Path]:
    """List local checksheet JSON files."""
    base_path = Path(directory)
    if not base_path.exists():
        return []
    return sorted(base_path.glob("*.json"))


def load_local_checksheets(path: Path) -> Optional[CheatSheet]:
    """Load a locally generated checksheet JSON into the app model."""
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return CheatSheet(**data)
    except Exception as e:
        logger.error(f"Failed to load local checksheet {path}: {e}")
        return None


def list_local_top10(directory: str = "data/top10") -> list[Path]:
    """List local Top 10 JSON files."""
    base_path = Path(directory)
    if not base_path.exists():
        return []
    return sorted(base_path.glob("*.json"))


def load_local_top10(path: Path) -> Optional[dict[str, Any]]:
    """Load a locally generated Top 10 JSON file."""
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load local Top 10 JSON {path}: {e}")
        return None


def load_top10_config() -> dict:
    """Load Top 10 data source configuration."""
    config_path = Path(__file__).parent / "owasp_llm" / "config.yaml"
    if not config_path.exists():
        return {"data_sources": []}
    with config_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {"data_sources": []}


def _parse_top10_markdown(markdown: str) -> dict[str, dict[str, Any]]:
    """Parse Top 10 risks from markdown content."""
    pattern = re.compile(r"^#+\s*(A0?\d{1,2})\s*[:\-–]\s*(.+)$", re.MULTILINE)
    splits = pattern.split(markdown)

    risks: dict[str, dict[str, Any]] = {}

    if len(splits) < 4:
        return risks

    # splits format: [pre, id1, title1, body1, id2, title2, body2, ...]
    for i in range(1, len(splits), 3):
        risk_id = splits[i].strip()
        title = splits[i + 1].strip()
        body = splits[i + 2]

        description = ""
        body_lines = [line.strip() for line in body.splitlines() if line.strip()]
        if body_lines:
            description = body_lines[0]

        impacts = []
        mitigations = []
        examples = []
        types = []

        current_bucket = None
        for line in body_lines[1:]:
            lower = line.lower()
            if lower.startswith("impact"):
                current_bucket = "impacts"
                continue
            if lower.startswith("mitigation") or lower.startswith("prevention"):
                current_bucket = "mitigations"
                continue
            if lower.startswith("example"):
                current_bucket = "examples"
                continue
            if lower.startswith("type") or lower.startswith("categories"):
                current_bucket = "types"
                continue

            cleaned = re.sub(r"^[\-*\d\.]+\s+", "", line)
            if current_bucket == "impacts":
                impacts.append(cleaned)
            elif current_bucket == "mitigations":
                mitigations.append(cleaned)
            elif current_bucket == "examples":
                examples.append(cleaned)
            elif current_bucket == "types":
                types.append((cleaned, ""))

        risks[risk_id] = {
            "title": title,
            "severity": "Medium",
            "icon": "⚠️",
            "description": description,
            "types": types,
            "impacts": impacts,
            "mitigations": mitigations,
            "examples": examples,
        }

    return risks


def _extract_top10_links(html: str) -> list[tuple[str, str, str]]:
    """Extract Top 10 risk links (id, title, url) from the index page."""
    soup = BeautifulSoup(html, "html.parser")
    pattern = re.compile(r"/Top10/2025/(A0\d|A10)_2025-([A-Za-z0-9_\-]+)/?")
    risks: dict[str, tuple[str, str]] = {}

    for link in soup.find_all("a", href=True):
        href = link["href"]
        match = pattern.search(href)
        if not match:
            continue
        risk_id = match.group(1)
        title = link.get_text(strip=True)
        if not title:
            slug = match.group(2).replace("_", " ")
            title = slug
        url = href if href.startswith("http") else f"https://owasp.org{href}"
        risks[risk_id] = (title, url)

    return [(rid, title, url) for rid, (title, url) in sorted(risks.items())]


def _parse_top10_risk_markdown(risk_id: str, title: str, markdown: str) -> dict[str, Any]:
    """Parse a single Top 10 risk page into structured fields."""
    sections: dict[str, list[str]] = {}
    current = "body"

    for line in markdown.splitlines():
        header_match = re.match(r"^#{2,4}\s+(.+)$", line.strip())
        if header_match:
            current = header_match.group(1).strip().lower()
            sections.setdefault(current, [])
            continue
        if line.strip():
            sections.setdefault(current, []).append(line.strip())

    def collect_list(keys: list[str]) -> list[str]:
        items: list[str] = []
        for key in keys:
            for header, lines in sections.items():
                if key in header:
                    for line in lines:
                        cleaned = re.sub(r"^[\-*\d\.]+\s+", "", line)
                        if cleaned and cleaned not in items:
                            items.append(cleaned)
        return items

    description = ""
    for header_key in ["overview", "description", "about"]:
        if header_key in sections and sections[header_key]:
            description = sections[header_key][0]
            break
    if not description:
        description = sections.get("body", [""])[0] if sections.get("body") else ""

    impacts = collect_list(["impact", "risk", "consequence"])
    mitigations = collect_list(["prevention", "mitigation", "how to prevent", "how to protect", "controls"])
    examples = collect_list(["example", "scenario", "attack"])
    types = [(t, "") for t in collect_list(["type", "category", "key concepts"])[:5]]

    return {
        "title": title,
        "severity": "Medium",
        "icon": "⚠️",
        "description": description,
        "types": types,
        "impacts": impacts,
        "mitigations": mitigations,
        "examples": examples,
    }


def _parse_top10_risk_html(title: str, html: str) -> dict[str, Any]:
    """Parse a Top 10 risk page HTML into structured fields."""
    soup = BeautifulSoup(html, "html.parser")
    description = ""
    first_p = soup.find("p")
    if first_p:
        description = first_p.get_text(strip=True)

    sections: dict[str, list[str]] = {}
    for header in soup.find_all(["h2", "h3"]):
        section_title = header.get_text(strip=True).lower()
        content: list[str] = []
        current = header.find_next_sibling()
        while current and current.name not in ["h2", "h3"]:
            if current.name in ["ul", "ol"]:
                for li in current.find_all("li"):
                    content.append(li.get_text(strip=True))
            elif current.name == "p":
                content.append(current.get_text(strip=True))
            current = current.find_next_sibling()
        if content:
            sections[section_title] = content

    def collect_list(keys: list[str]) -> list[str]:
        items: list[str] = []
        for key in keys:
            for header, lines in sections.items():
                if key in header:
                    for line in lines:
                        if line and line not in items:
                            items.append(line)
        return items

    impacts = collect_list(["impact", "consequence", "risk"])
    mitigations = collect_list(["prevention", "mitigation", "how to prevent", "how to fix", "controls", "defense"])
    examples = collect_list(["example", "scenario", "attack"])
    types = [(t, "") for t in collect_list(["what is", "overview", "description", "category", "types"])[:5]]

    return {
        "title": title,
        "severity": "Medium",
        "icon": "⚠️",
        "description": description,
        "types": types,
        "impacts": impacts,
        "mitigations": mitigations,
        "examples": examples,
    }


@st.cache_data(ttl=86400)
def fetch_owasp_top10_2025(url: str) -> dict[str, dict[str, Any]]:
    """Fetch and parse OWASP Top 10 2025 into the shared risk structure using Firecrawl."""
    cache = get_cache_manager()
    client = get_firecrawl_client()

    cache_key = f"top10_{url}"
    cached = cache.get(cache_key)
    if cached and "risks" in cached:
        return cached["risks"]

    scraped = client.scrape_url(
        url,
        formats=["markdown", "html"],
        only_main_content=False,
        use_cache=True,
    )

    if not scraped.get("success"):
        return {}

    markdown = scraped.get("markdown", "")
    risks = _parse_top10_markdown(markdown)

    # If main page lacks details, follow risk links and extract per-risk content
    if not risks:
        risk_links = _extract_top10_links(scraped.get("html", ""))
        for risk_id, title, risk_url in risk_links:
            detail_scraped = client.scrape_url(
                risk_url,
                formats=["markdown", "html"],
                only_main_content=True,
                use_cache=True,
            )
            if not detail_scraped.get("success"):
                continue
            risk_data = _parse_top10_risk_markdown(
                risk_id,
                title,
                detail_scraped.get("markdown", ""),
            )
            if not risk_data.get("description"):
                risk_data = _parse_top10_risk_html(title, detail_scraped.get("html", ""))
            risks[risk_id] = risk_data

    # Fallback to HTML parsing if markdown is sparse
    if not risks:
        soup = BeautifulSoup(scraped.get("html", ""), "html.parser")
        pattern = re.compile(r"\bA0?(\d{1,2})\s*[:\-–]\s*(.+)")
        for header in soup.find_all(["h2", "h3"]):
            text = header.get_text(strip=True)
            match = pattern.search(text)
            if not match:
                continue
            number = int(match.group(1))
            title = match.group(2).strip()
            risk_id = f"A{number:02d}"
            description = ""
            next_p = header.find_next_sibling("p")
            if next_p:
                description = next_p.get_text(strip=True)
            risks[risk_id] = {
                "title": title,
                "severity": "Medium",
                "icon": "⚠️",
                "description": description,
                "types": [],
                "impacts": [],
                "mitigations": [],
                "examples": [],
            }

    cache.set(cache_key, {"risks": risks})
    return risks


def get_top10_risks(source_id: str, url: str, source_type: str) -> dict[str, dict[str, Any]]:
    """Return risk data based on selected source."""
    if source_id == "llm_top10_2025" or source_type == "static":
        return LLM_RISKS
    return fetch_owasp_top10_2025(url)


def get_code_review_crew():
    """Load the code review crew dynamically."""
    app_root = Path(__file__).parent
    if str(app_root) not in sys.path:
        sys.path.insert(0, str(app_root))
    from agents.code_review_crew.crew import CodeReviewCrew
    return CodeReviewCrew().crew()


def build_cheatsheet_context(cheatsheet: Optional[CheatSheet]) -> str:
    if not cheatsheet:
        return ""
    lines = [f"Cheat Sheet: {cheatsheet.title}", f"Category: {cheatsheet.category}"]
    for risk in cheatsheet.risks[:10]:
        lines.append(f"- {risk.id}: {risk.title} (Severity: {risk.severity})")
        for mitigation in risk.mitigations[:3]:
            lines.append(f"  - Mitigation: {mitigation}")
    return "\n".join(lines)


def build_top10_context(source_label: str, risks: dict[str, dict[str, Any]]) -> str:
    lines = [f"Top 10 Source: {source_label}"]
    for risk_id, risk in list(risks.items())[:10]:
        lines.append(f"- {risk_id}: {risk.get('title', '')} (Severity: {risk.get('severity', 'Medium')})")
        for mitigation in risk.get("mitigations", [])[:3]:
            lines.append(f"  - Mitigation: {mitigation}")
    return "\n".join(lines)


def render_code_review_panel(context_text: str, context_label: str) -> None:
    """Render code review input panel and run crew."""
    st.subheader("🧪 Code Review Against Selected Guidance")
    st.markdown("Upload files or paste a PR diff, then run the review crew.")

    uploaded_files = st.file_uploader(
        "Upload file(s) to review",
        accept_multiple_files=True,
        type=None,
    )
    pr_diff = st.text_area("Or paste PR diff", height=200)
    user_prompt = st.text_area("Additional prompt (optional)", height=120)

    if st.button("Run Code Review", type="primary"):
        content_parts: list[str] = []
        if pr_diff.strip():
            content_parts.append("=== PR DIFF ===\n" + pr_diff.strip())
        if uploaded_files:
            for f in uploaded_files:
                try:
                    text = f.read().decode("utf-8", errors="ignore")
                    content_parts.append(f"=== FILE: {f.name} ===\n{text}")
                except Exception:
                    content_parts.append(f"=== FILE: {f.name} ===\n<Could not read file>")

        if not content_parts:
            st.warning("Provide a PR diff or upload at least one file.")
            return

        combined_content = "\n\n".join(content_parts)
        max_chars = 12000
        if len(combined_content) > max_chars:
            combined_content = combined_content[:max_chars] + "\n\n[Truncated to fit context limit]"
        combined_prompt = "\n\n".join([
            "Review the code ONLY against the selected guidance below. Do not use any other OWASP Top 10 or external frameworks.",
            f"Selected guidance: {context_label}",
            "Guidance details:",
            context_text or "(no context provided)",
            "Additional user prompt:",
            user_prompt or "(none)",
            "Code/PR content:",
            combined_content,
        ])

        with st.spinner("Running code review crew..."):
            try:
                crew = get_code_review_crew()
                result = crew.kickoff(inputs={"file_content": combined_prompt})
                report_json = result.json_dict if hasattr(result, "json_dict") else {}
            except Exception as e:
                st.error(f"Code review failed: {e}")
                return

        report_lines = [
            "# Code Review Report",
            "",
            f"Generated: {datetime.now().isoformat()}",
            f"Selected guidance: {context_label}",
            "",
        ]
        report_lines.append("## Findings")
        report_lines.append(str(report_json.get("findings", "")))
        report_lines.append("")
        report_lines.append("## Confidence")
        report_lines.append(str(report_json.get("confidence", "")))
        report_lines.append("")
        report_lines.append("## Fixes")
        for fix in report_json.get("fix", []):
            report_lines.append(f"- **{fix.get('description', '')}**")
            report_lines.append(f"  - Solution: {fix.get('solutions', '')}")
            report_lines.append(f"  - Explanation: {fix.get('explanation', '')}")
        report_lines.append("")
        report_lines.append("## Recommendations")
        report_lines.append(str(report_json.get("recommendations", "")))

        report_content = "\n".join(report_lines)
        report_dir = Path("report")
        report_dir.mkdir(exist_ok=True)
        report_path = report_dir / f"code_review_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        report_path.write_text(report_content, encoding="utf-8")

        st.success("Report generated and saved.")
        st.download_button("Download Report", data=report_content, file_name=report_path.name)
        st.markdown(report_content)


def render_reports_page() -> None:
    """Render saved reports list and viewer."""
    st.title("📄 Reports")

    report_dir = Path("report")
    report_files = sorted(report_dir.glob("*.md"), reverse=True) if report_dir.exists() else []

    if not report_files:
        st.info("No reports found. Run a code review to generate one.")
        return

    selected_name = st.selectbox(
        "Select a report:",
        [p.name for p in report_files],
        index=0,
    )
    selected_path = next((p for p in report_files if p.name == selected_name), None)
    if not selected_path:
        return

    content = selected_path.read_text(encoding="utf-8")
    st.download_button("Download Report", data=content, file_name=selected_path.name)
    st.markdown(content)


def render_app_selector() -> str:
    """Render top-level app selector."""
    return st.sidebar.selectbox(
        "Application:",
        ["Cheat Sheets", "Top 10"],
        index=0,
    )


def render_cheatsheet_sidebar() -> tuple[str, Optional[str], Optional[Path], str]:
    """
    Render the sidebar with cheat sheet selector and navigation.
    
    Returns:
        Tuple of (selected_page, selected_cheatsheet_url)
    """
    st.sidebar.image("https://owasp.org/assets/images/logo.png", width=200)
    st.sidebar.title("🛡️ OWASP Cheat Sheets")
    st.sidebar.divider()
    
    # Data source selection
    data_source = st.sidebar.radio(
        "📦 Data Source:",
        ["Live OWASP (Firecrawl)", "Local Checksheet JSON"],
        index=0
    )

    local_checksheets = list_local_checksheets()

    # Fetch cheat sheet index only for live mode
    index = None
    if data_source == "Live OWASP (Firecrawl)":
        with st.sidebar.status("Loading cheat sheets...", expanded=False) as status:
            index = fetch_cheatsheet_index()
            status.update(label=f"Loaded {index.total_count} cheat sheets", state="complete")
    
    # Category filter
    selected_category = "All"
    if index:
        categories = ["All"] + sorted(index.categories)
        selected_category = st.sidebar.selectbox("📁 Filter by Category:", categories)
    
    # Filter cheat sheets by category
    filtered_cheatsheets = []
    if index:
        filtered_cheatsheets = index.cheatsheets
        if selected_category != "All":
            filtered_cheatsheets = [
                cs for cs in index.cheatsheets
                if cs.get("category") == selected_category
            ]
    
    # Cheat sheet selector
    cs_options = {cs["title"]: cs["url"] for cs in filtered_cheatsheets}
    
    selected_url = None
    selected_local = None
    if data_source == "Live OWASP (Firecrawl)":
        if not cs_options:
            st.sidebar.warning("No cheat sheets found. Check your API configuration.")
        else:
            selected_title = st.sidebar.selectbox(
                "📋 Select Cheat Sheet:",
                list(cs_options.keys()),
                help="Choose a cheat sheet to explore"
            )
            selected_url = cs_options.get(selected_title)
    else:
        if not local_checksheets:
            st.sidebar.warning("No local checksheets found. Run the checksheet crew to generate JSON.")
        else:
            selected_local_name = st.sidebar.selectbox(
                "📋 Select Local Checksheet:",
                [p.name for p in local_checksheets],
                help="Choose a generated checksheet JSON"
            )
            selected_local = next((p for p in local_checksheets if p.name == selected_local_name), None)
    
    st.sidebar.divider()
    
    # Navigation
    page = st.sidebar.radio(
        "📍 Navigate to:",
        ["🏠 Overview", "📋 All Risks", "🔍 Risk Details", "🧪 Attack Examples", "📊 Risk Matrix", "📚 Resources", "📄 Reports"],
        index=0
    )
    
    st.sidebar.divider()
    
    # Cache info
    cache = get_cache_manager()
    stats = cache.get_stats()
    st.sidebar.markdown(f"""
    <div class="cache-info">
    Cache: {stats['entry_count']} entries ({stats['total_size_mb']} MB)<br>
    Expires in: {stats['default_expiry_days']} days
    </div>
    """, unsafe_allow_html=True)
    
    # Cache controls
    if st.sidebar.button("🔄 Clear Cache", help="Force refresh all data"):
        cache.clear_all()
        st.cache_data.clear()
        st.rerun()
    
    st.sidebar.divider()
    st.sidebar.markdown("""
    **Quick Links:**
    - [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
    - [GitHub Repository](https://github.com/OWASP/CheatSheetSeries)
    """)
    
    return page, selected_url, selected_local, data_source


def render_top10_sidebar() -> tuple[str, dict[str, Any], Optional[Path], str]:
    """Render sidebar for Top 10 selection."""
    st.sidebar.image("https://owasp.org/assets/images/logo.png", width=200)
    st.sidebar.title("🛡️ OWASP Top 10")
    st.sidebar.markdown("**2025 Edition**")
    st.sidebar.divider()

    config = load_top10_config()
    data_sources = config.get("data_sources", [])
    source_labels = [s.get("label", s.get("id", "Unknown")) for s in data_sources]

    data_source = st.sidebar.radio(
        "📦 Data Source:",
        ["Live (web)", "Local Top 10 JSON"],
        index=0,
    )

    selected_label = st.sidebar.selectbox(
        "Data Source:",
        source_labels or ["OWASP LLM Top 10 (2025)"],
        index=0,
    )

    selected_source = next(
        (s for s in data_sources if s.get("label") == selected_label),
        {"id": "llm_top10_2025", "url": "", "source": "static"},
    )

    selected_local = None
    if data_source == "Local Top 10 JSON":
        local_files = list_local_top10()
        if not local_files:
            st.sidebar.warning("No local Top 10 JSON found. Run the Top 10 crew to generate JSON.")
        else:
            selected_name = st.sidebar.selectbox(
                "📋 Select Local Top 10:",
                [p.name for p in local_files],
                help="Choose a generated Top 10 JSON",
            )
            selected_local = next((p for p in local_files if p.name == selected_name), None)

    page = st.sidebar.radio(
        "Navigate to:",
        ["🏠 Overview", "📋 All Risks", "🔍 Risk Details", "🧪 Attack Examples", "📊 Risk Matrix", "📚 Resources", "📄 Reports"],
        index=0,
    )

    st.sidebar.divider()
    st.sidebar.markdown("""
    **Quick Links:**
    - [OWASP GenAI Project](https://genai.owasp.org/)
    - [OWASP Top 10](https://owasp.org/www-project-top-ten/)
    """)

    return page, selected_source, selected_local, data_source


def render_overview(cheatsheet: Optional[CheatSheet]) -> None:
    """Render the overview page."""
    st.markdown('<h1 class="main-header">🛡️ OWASP Cheat Sheet Viewer</h1>', unsafe_allow_html=True)
    st.markdown('<p class="sub-header">Security Best Practices and Mitigation Strategies</p>', unsafe_allow_html=True)
    
    if not cheatsheet:
        st.warning("Please select a cheat sheet from the sidebar to begin.")
        st.markdown("""
        <div class="info-box">
        <strong>About this Application:</strong> This viewer provides an interactive way to explore 
        OWASP Cheat Sheets, which offer concise guidance on implementing secure development practices.
        Select a cheat sheet from the sidebar to get started.
        </div>
        """, unsafe_allow_html=True)
        return
    
    # Cheat sheet header
    st.markdown(f"## {cheatsheet.icon} {cheatsheet.title}")
    st.markdown(f"**Category:** {cheatsheet.category}")
    
    # Introduction
    if cheatsheet.introduction:
        st.markdown(f"""
        <div class="info-box">
        {cheatsheet.introduction[:800]}{'...' if len(cheatsheet.introduction) > 800 else ''}
        </div>
        """, unsafe_allow_html=True)
    
    # Quick stats
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Security Items", len(cheatsheet.risks), help="Number of identified security topics")
    with col2:
        critical_count = sum(1 for r in cheatsheet.risks if r.severity == "Critical")
        st.metric("Critical", str(critical_count), help="Critical severity items")
    with col3:
        high_count = sum(1 for r in cheatsheet.risks if r.severity == "High")
        st.metric("High Severity", str(high_count), help="High severity items")
    with col4:
        st.metric("Sections", len(cheatsheet.sections), help="Number of content sections")
    
    st.divider()
    
    # Quick overview cards
    st.subheader("📋 Key Security Topics")
    
    cols = st.columns(2)
    for idx, risk in enumerate(cheatsheet.risks[:6]):
        with cols[idx % 2]:
            severity_icon = {
                "Critical": "🔴",
                "High": "🟠",
                "Medium": "🟡",
                "Low": "🟢"
            }.get(risk.severity, "⚪")
            
            with st.container(border=True):
                st.markdown(f"### {risk.icon} {risk.id}: {risk.title}")
                st.markdown(f"**Severity:** {severity_icon} {risk.severity}")
                st.markdown(risk.description[:150] + "..." if len(risk.description) > 150 else risk.description)


def render_all_risks(cheatsheet: Optional[CheatSheet]) -> None:
    """Render all risks in a list view."""
    st.title("📋 All Security Topics")
    
    if not cheatsheet or not cheatsheet.risks:
        st.info("No security topics found. Please select a cheat sheet.")
        return
    
    st.markdown(f"**Cheat Sheet:** {cheatsheet.title}")
    st.divider()
    
    for risk in cheatsheet.risks:
        with st.expander(f"{risk.icon} {risk.id}: {risk.title} ({risk.severity})", expanded=False):
            st.markdown(f"**Description:** {risk.description}")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**🎯 Key Impacts:**")
                for impact in risk.impacts[:3]:
                    st.markdown(f"- {impact}")
                if not risk.impacts:
                    st.markdown("- See detailed documentation")
            
            with col2:
                st.markdown("**🛡️ Key Mitigations:**")
                for mitigation in risk.mitigations[:3]:
                    st.markdown(f"- {mitigation}")
                if not risk.mitigations:
                    st.markdown("- Apply recommended security controls")


def render_risk_details(cheatsheet: Optional[CheatSheet]) -> None:
    """Render detailed view of a selected risk."""
    st.title("🔍 Security Topic Details")
    
    if not cheatsheet or not cheatsheet.risks:
        st.info("No security topics available. Please select a cheat sheet.")
        return
    
    # Risk selector
    risk_options = {f"{r.id}: {r.title}": r for r in cheatsheet.risks}
    selected = st.selectbox("Select a Topic to Explore:", list(risk_options.keys()))
    risk = risk_options[selected]
    
    st.divider()
    
    # Header
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown(f"## {risk.icon} {risk.id}: {risk.title}")
    with col2:
        severity_colors = {"Critical": "#ff4b4b", "High": "#ff8c00", "Medium": "#ffd700", "Low": "#32cd32"}
        st.markdown(f"""
        <div style="background-color: {severity_colors.get(risk.severity, '#888')}; 
                    padding: 10px; border-radius: 10px; text-align: center; 
                    color: {'white' if risk.severity != 'Medium' else 'black'};">
            <strong>{risk.severity}</strong>
        </div>
        """, unsafe_allow_html=True)
    
    # Description
    st.markdown(f"""
    <div class="info-box">
    {risk.description}
    </div>
    """, unsafe_allow_html=True)
    
    # Tabs for detailed information
    tab1, tab2, tab3, tab4 = st.tabs(["📌 Types", "💥 Impacts", "🛡️ Mitigations", "📝 Examples"])
    
    with tab1:
        st.subheader("Topic Categories")
        if risk.types:
            for type_name, type_desc in risk.types:
                with st.container(border=True):
                    st.markdown(f"**{type_name}**")
                    st.markdown(type_desc)
        else:
            st.info("Refer to the main content sections for detailed categorization.")
    
    with tab2:
        st.subheader("Potential Impacts")
        for impact in risk.impacts:
            st.markdown(f"- ⚠️ {impact}")
        if not risk.impacts:
            st.info("See the cheat sheet documentation for impact details.")
    
    with tab3:
        st.subheader("Prevention & Mitigation Strategies")
        for idx, mitigation in enumerate(risk.mitigations, 1):
            st.markdown(f"""
            <div class="mitigation-box">
            <strong>{idx}.</strong> {mitigation}
            </div>
            """, unsafe_allow_html=True)
        if not risk.mitigations:
            st.info("Apply security best practices as documented in the cheat sheet.")
    
    with tab4:
        st.subheader("Code Examples")
        for idx, example in enumerate(risk.examples, 1):
            st.markdown(f"**Example {idx}:**")
            st.code(example, language="text")
        if not risk.examples:
            st.info("See the source cheat sheet for code examples.")


def render_attack_examples(cheatsheet: Optional[CheatSheet]) -> None:
    """Render attack demonstration examples."""
    st.title("🧪 Attack Demonstrations")
    st.markdown("Use these examples to understand attack vectors. For educational purposes only.")
    
    if not cheatsheet or not cheatsheet.attack_examples:
        st.info("No attack examples available for this cheat sheet.")
        return
    
    for example in cheatsheet.attack_examples:
        risk = next(
            (r for r in cheatsheet.risks if r.id == example.risk_id),
            None
        )
        severity = risk.severity if risk else "Medium"
        icon = risk.icon if risk else "⚠️"
        
        with st.expander(f"{icon} {example.risk_id}: {example.title} ({severity})"):
            st.markdown(f"**Goal:** {example.goal}")
            
            if example.attack_prompt:
                st.markdown("**Attack Vector/Code:**")
                st.code(example.attack_prompt, language="text")
            
            st.markdown(f"""
            <div class="attack-box">
            <strong>Impact:</strong> {example.impact}
            </div>
            """, unsafe_allow_html=True)
            
            st.markdown(f"""
            <div class="mitigation-box">
            <strong>Mitigation:</strong> {example.mitigation}
            </div>
            """, unsafe_allow_html=True)


def render_risk_matrix(cheatsheet: Optional[CheatSheet]) -> None:
    """Render a risk matrix visualization."""
    st.title("📊 Security Assessment Matrix")
    
    if not cheatsheet or not cheatsheet.risks:
        st.info("No data available for matrix visualization.")
        return
    
    # Create risk data for visualization
    risk_data = []
    for risk in cheatsheet.risks:
        risk_data.append({
            "ID": risk.id,
            "Title": risk.title,
            "Severity": risk.severity,
            "Impact Count": len(risk.impacts),
            "Mitigation Count": len(risk.mitigations),
        })
    
    df = pd.DataFrame(risk_data)
    
    # Severity distribution
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Severity Distribution")
        if not df.empty:
            severity_counts = df["Severity"].value_counts()
            st.bar_chart(severity_counts)
        else:
            st.info("No severity data available.")
    
    with col2:
        st.subheader("Overview Table")
        st.dataframe(df, width="stretch", hide_index=True)
    
    # Risk comparison
    st.subheader("Detailed Comparison")
    
    if not df.empty:
        # Create a styled table
        def highlight_severity(val: str) -> str:
            colors = {
                "Critical": "background-color: #ff4b4b; color: white",
                "High": "background-color: #ff8c00; color: white",
                "Medium": "background-color: #ffd700; color: black",
                "Low": "background-color: #32cd32; color: white",
            }
            return colors.get(val, "")
        
        styled_df = df.style.map(highlight_severity, subset=["Severity"])
        st.dataframe(styled_df, width="stretch", hide_index=True)


def render_resources(cheatsheet: Optional[CheatSheet]) -> None:
    """Render resources and references page."""
    st.title("📚 Resources & References")
    
    if cheatsheet:
        st.markdown(f"### Current Cheat Sheet: {cheatsheet.title}")
        st.markdown(f"**Source:** [{cheatsheet.url}]({cheatsheet.url})")
        
        if cheatsheet.tags:
            st.markdown(f"**Tags:** {', '.join(cheatsheet.tags)}")
        
        if cheatsheet.related_cheatsheets:
            st.markdown("**Related Cheat Sheets:**")
            for related in cheatsheet.related_cheatsheets:
                st.markdown(f"- {related.replace('-', ' ').title()}")
        
        st.divider()
    
    st.markdown("""
    ### Official OWASP Resources
    
    - **[OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)** - Complete collection
    - **[OWASP Top 10](https://owasp.org/www-project-top-ten/)** - Top 10 Web Application Security Risks
    - **[OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)** - Application Security Verification Standard
    - **[OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)** - Comprehensive testing methodology
    
    ### Related Frameworks
    
    - **[MITRE ATT&CK](https://attack.mitre.org/)** - Adversarial Tactics and Techniques
    - **[NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)** - Federal guidance
    - **[CIS Controls](https://www.cisecurity.org/controls)** - Center for Internet Security
    
    ### Additional Learning
    
    - Secure coding practices
    - Threat modeling methodologies
    - Security testing tools and techniques
    - Incident response procedures
    """)
    
    st.divider()
    
    st.info("""
    **Note:** This application provides a summary view of OWASP Cheat Sheets. 
    For the most comprehensive and up-to-date information, always refer to the official documentation.
    """)


def render_top10_overview(risks: dict[str, dict[str, Any]], title: str, subtitle: str) -> None:
    """Render Top 10 overview page."""
    st.markdown(f'<h1 class="main-header">🛡️ {title}</h1>', unsafe_allow_html=True)
    st.markdown(f'<p class="sub-header">{subtitle}</p>', unsafe_allow_html=True)

    st.markdown("""
    <div class="info-box">
    <strong>About this Guide:</strong> The OWASP Top 10 identifies the most critical security risks and mitigation guidance.
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("Total Risks", str(len(risks)), help="Number of identified security risks")
    with col2:
        critical_count = sum(1 for r in risks.values() if r["severity"] == "Critical")
        st.metric("Critical Severity", str(critical_count), help="Critical severity risks")
    with col3:
        high_count = sum(1 for r in risks.values() if r["severity"] == "High")
        st.metric("High Severity", str(high_count), help="High severity risks")
    with col4:
        medium_count = sum(1 for r in risks.values() if r["severity"] == "Medium")
        st.metric("Medium Severity", str(medium_count), help="Medium severity risks")

    st.divider()
    st.subheader("📋 Quick Overview")

    cols = st.columns(2)
    for idx, (risk_id, risk_data) in enumerate(risks.items()):
        with cols[idx % 2]:
            severity_color = {
                "Critical": "🔴",
                "High": "🟠",
                "Medium": "🟡",
                "Low": "🟢",
            }.get(risk_data.get("severity", ""), "⚪")

            with st.container(border=True):
                st.markdown(f"### {risk_data.get('icon', '⚠️')} {risk_id}: {risk_data.get('title', '')}")
                st.markdown(f"**Severity:** {severity_color} {risk_data.get('severity', 'Medium')}")
                description = risk_data.get("description", "")
                if description:
                    st.markdown(description[:150] + ("..." if len(description) > 150 else ""))


def render_top10_all_risks(risks: dict[str, dict[str, Any]]) -> None:
    """Render Top 10 list view."""
    st.title("📋 All OWASP Top 10 Risks")

    for risk_id, risk_data in risks.items():
        with st.expander(f"{risk_data.get('icon', '⚠️')} {risk_id}: {risk_data.get('title', '')} ({risk_data.get('severity', 'Medium')})", expanded=False):
            st.markdown(f"**Description:** {risk_data.get('description', '')}")

            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**🎯 Key Impacts:**")
                for impact in risk_data.get("impacts", [])[:3]:
                    st.markdown(f"- {impact}")
            with col2:
                st.markdown("**🛡️ Key Mitigations:**")
                for mitigation in risk_data.get("mitigations", [])[:3]:
                    st.markdown(f"- {mitigation}")


def render_top10_risk_details(risks: dict[str, dict[str, Any]]) -> None:
    """Render detailed view of a selected Top 10 risk."""
    st.title("🔍 Risk Details")

    risk_options = {f"{k}: {v.get('title', '')}": k for k, v in risks.items()}
    selected = st.selectbox("Select a Risk to Explore:", list(risk_options.keys()))
    risk_id = risk_options[selected]
    risk = risks[risk_id]

    st.divider()
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown(f"## {risk.get('icon', '⚠️')} {risk_id}: {risk.get('title', '')}")
    with col2:
        severity_colors = {"Critical": "#ff4b4b", "High": "#ff8c00", "Medium": "#ffd700", "Low": "#32cd32"}
        st.markdown(f"""
        <div style="background-color: {severity_colors.get(risk.get('severity', 'Medium'), '#888')};
                    padding: 10px; border-radius: 10px; text-align: center;
                    color: {'white' if risk.get('severity') != 'Medium' else 'black'};">
            <strong>{risk.get('severity', 'Medium')}</strong>
        </div>
        """, unsafe_allow_html=True)

    st.markdown(f"""
    <div class="info-box">
    {risk.get('description', '')}
    </div>
    """, unsafe_allow_html=True)

    tab1, tab2, tab3, tab4 = st.tabs(["📌 Types", "💥 Impacts", "🛡️ Mitigations", "⚔️ Examples"])

    with tab1:
        st.subheader("Vulnerability Types")
        for type_name, type_desc in risk.get("types", []):
            with st.container(border=True):
                st.markdown(f"**{type_name}**")
                st.markdown(type_desc)
        if not risk.get("types"):
            st.info("No types listed for this risk.")

    with tab2:
        st.subheader("Potential Impacts")
        for impact in risk.get("impacts", []):
            st.markdown(f"- ⚠️ {impact}")
        if not risk.get("impacts"):
            st.info("No impacts listed for this risk.")

    with tab3:
        st.subheader("Prevention & Mitigation Strategies")
        for idx, mitigation in enumerate(risk.get("mitigations", []), 1):
            st.markdown(f"""
            <div class="mitigation-box">
            <strong>{idx}.</strong> {mitigation}
            </div>
            """, unsafe_allow_html=True)
        if not risk.get("mitigations"):
            st.info("No mitigations listed for this risk.")

    with tab4:
        st.subheader("Examples")
        for idx, example in enumerate(risk.get("examples", []), 1):
            st.markdown(f"""
            <div class="attack-box">
            <strong>Scenario {idx}:</strong> {example}
            </div>
            """, unsafe_allow_html=True)
        if not risk.get("examples"):
            st.info("No examples listed for this risk.")


def render_top10_risk_matrix(risks: dict[str, dict[str, Any]]) -> None:
    """Render Top 10 risk matrix."""
    st.title("📊 Risk Assessment Matrix")

    risk_data = []
    for risk_id, risk in risks.items():
        risk_data.append({
            "Risk ID": risk_id,
            "Title": risk.get("title", ""),
            "Severity": risk.get("severity", "Medium"),
            "Impact Count": len(risk.get("impacts", [])),
            "Mitigation Count": len(risk.get("mitigations", [])),
        })

    df = pd.DataFrame(risk_data)

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Severity Distribution")
        severity_counts = df["Severity"].value_counts()
        st.bar_chart(severity_counts)
    with col2:
        st.subheader("Risk Overview Table")
        st.dataframe(df, width="stretch", hide_index=True)

    st.subheader("Risk Comparison")
    comparison_df = df[["Risk ID", "Title", "Severity", "Impact Count", "Mitigation Count"]]

    def highlight_severity(val: str) -> str:
        colors = {
            "Critical": "background-color: #ff4b4b; color: white",
            "High": "background-color: #ff8c00; color: white",
            "Medium": "background-color: #ffd700; color: black",
            "Low": "background-color: #32cd32; color: white",
        }
        return colors.get(val, "")

    styled_df = comparison_df.style.map(highlight_severity, subset=["Severity"])
    st.dataframe(styled_df, width="stretch", hide_index=True)


def render_top10_attack_examples(risks: dict[str, dict[str, Any]], attack_examples: dict[str, dict[str, Any]]) -> None:
    st.title("🧪 Attack Demos by Risk")
    st.markdown("Use these crafted prompts to illustrate each OWASP LLM risk. Run them only in isolated, non-production sandboxes.")

    if not attack_examples:
        st.info("Attack examples are available only for the LLM Top 10 dataset.")
        return

    for risk_id, example in attack_examples.items():
        risk_meta = risks[risk_id]
        with st.expander(f"{risk_meta.get('icon', '⚠️')} {risk_id}: {example['title']} ({risk_meta.get('severity', 'Medium')})"):
            st.markdown(f"**Goal:** {example['goal']}")
            st.markdown("**Attack Prompt:**")
            st.code(example["attack_prompt"], language="text")
            st.markdown(f"**Impact:** {example['impact']}")
            st.markdown(f"**Mitigation:** {example['mitigation']}")


def render_top10_resources(source_url: str, source_label: str) -> None:
    """Render Top 10 resources page."""
    st.title("📚 Resources & References")

    st.markdown(f"""
    ### Official OWASP Resources

    - **[Selected Source]({source_url})** - {source_label}
    - **[OWASP GenAI Security Project](https://genai.owasp.org/)** - Main project page
    - **[OWASP Top 10](https://owasp.org/www-project-top-ten/)** - OWASP Top 10 overview
    """)

    st.divider()
    st.info("""
    **Note:** This application provides a summary view of OWASP Top 10 content.
    For the most comprehensive and up-to-date information, always refer to the official documentation.
    """)


def main() -> None:
    """Main application entry point."""
    app_section = render_app_selector()

    if app_section == "Cheat Sheets":
        page, selected_url, selected_local, data_source = render_cheatsheet_sidebar()

        cheatsheet: Optional[CheatSheet] = None
        if data_source == "Local Checksheet JSON":
            if selected_local:
                with st.spinner("Loading local checksheet..."):
                    cheatsheet = load_local_checksheets(selected_local)
        else:
            if selected_url:
                with st.spinner("Loading cheat sheet content..."):
                    cheatsheet = fetch_cheatsheet(selected_url, "selected")

        if page == "🏠 Overview":
            render_overview(cheatsheet)
        elif page == "📋 All Risks":
            render_all_risks(cheatsheet)
        elif page == "🔍 Risk Details":
            render_risk_details(cheatsheet)
        elif page == "🧪 Attack Examples":
            render_attack_examples(cheatsheet)
        elif page == "📊 Risk Matrix":
            render_risk_matrix(cheatsheet)
        elif page == "📚 Resources":
            render_resources(cheatsheet)
        elif page == "📄 Reports":
            render_reports_page()

        cheatsheet_label = f"Cheat Sheet: {cheatsheet.title}" if cheatsheet else "Cheat Sheet: (none selected)"
        render_code_review_panel(build_cheatsheet_context(cheatsheet), cheatsheet_label)

    else:
        page, selected_source, selected_local, data_source = render_top10_sidebar()
        source_id = selected_source.get("id", "llm_top10_2025")
        source_url = selected_source.get("url", "")
        source_type = selected_source.get("source", "static")
        source_label = selected_source.get("label", "OWASP LLM Top 10 (2025)")

        if data_source == "Local Top 10 JSON" and selected_local:
            local_data = load_local_top10(selected_local) or {}
            risks = local_data.get("risks", {})
            source_label = local_data.get("title", source_label)
            source_url = local_data.get("source_url", source_url)
            source_id = local_data.get("id", source_id)
            attack_examples = {}
        else:
            risks = get_top10_risks(source_id, source_url, source_type)
            attack_examples = LLM_RISK_ATTACK_EXAMPLES if source_id == "llm_top10_2025" else {}
        title = "OWASP Top 10 for LLM Applications" if source_id == "llm_top10_2025" else "OWASP Top 10 (2025)"
        subtitle = "2025 Edition - Security Risks & Mitigations for Large Language Models" if source_id == "llm_top10_2025" else "2025 Edition - Web Application Security Risks"

        if page == "🏠 Overview":
            render_top10_overview(risks, title, subtitle)
        elif page == "📋 All Risks":
            render_top10_all_risks(risks)
        elif page == "🔍 Risk Details":
            render_top10_risk_details(risks)
        elif page == "🧪 Attack Examples":
            render_top10_attack_examples(risks, attack_examples)
        elif page == "📊 Risk Matrix":
            render_top10_risk_matrix(risks)
        elif page == "📚 Resources":
            render_top10_resources(source_url, source_label)
        elif page == "📄 Reports":
            render_reports_page()

        top10_label = f"Top 10: {source_label}"
        render_code_review_panel(build_top10_context(source_label, risks), top10_label)
    
    # Footer
    st.divider()
    st.markdown("""
    <div style="text-align: center; color: #666; font-size: 0.8rem;">
        Built with Streamlit | Data sourced from OWASP Cheat Sheet Series<br>
        <a href="https://cheatsheetseries.owasp.org/">https://cheatsheetseries.owasp.org/</a>
    </div>
    """, unsafe_allow_html=True)


if __name__ == "__main__":
    main()