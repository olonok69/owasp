"""
Cheat Sheet Parser for OWASP Cheat Sheet Viewer
===============================================

Parses scraped cheat sheet content into structured data models.
"""

import hashlib
import logging
import re
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .models import (
    AttackExample,
    CheatSheet,
    CheatSheetIndex,
    CheatSheetSection,
    RiskItem,
)
from .config_manager import ConfigManager


logger = logging.getLogger(__name__)


# Category icons mapping
CATEGORY_ICONS = {
    "authentication": "🔐",
    "authorization": "🛡️",
    "cryptography": "🔒",
    "injection": "💉",
    "session": "📋",
    "input": "📝",
    "output": "📤",
    "api": "🔌",
    "web": "🌐",
    "mobile": "📱",
    "database": "🗄️",
    "cloud": "☁️",
    "docker": "🐳",
    "kubernetes": "⚙️",
    "network": "🌍",
    "logging": "📊",
    "error": "⚠️",
    "file": "📁",
    "xml": "📄",
    "json": "📋",
    "deserialization": "🔄",
    "csrf": "🎭",
    "xss": "💥",
    "clickjacking": "🖱️",
    "password": "🔑",
    "jwt": "🎫",
    "oauth": "🔓",
    "saml": "📜",
    "ldap": "📚",
    "sql": "🗃️",
    "nosql": "📦",
    "graphql": "📈",
    "rest": "🔗",
    "microservices": "🧩",
    "serverless": "⚡",
    "ci/cd": "🔄",
    "default": "📋",
}

# Severity keywords for risk classification
SEVERITY_KEYWORDS = {
    "critical": ["critical", "severe", "catastrophic", "emergency", "extremely dangerous"],
    "high": ["high", "serious", "major", "significant", "dangerous", "important"],
    "medium": ["medium", "moderate", "notable", "considerable"],
    "low": ["low", "minor", "minimal", "limited"],
}


class CheatsheetParser:
    """
    Parses OWASP cheat sheet content into structured data.
    
    Handles extraction of:
    - Index of all available cheat sheets
    - Individual cheat sheet content
    - Risk items and mitigations
    - Attack examples and scenarios
    """
    
    def __init__(self, config: Optional[ConfigManager] = None) -> None:
        """
        Initialize the parser.
        
        Args:
            config: Configuration manager instance
        """
        self._config = config or ConfigManager()
        self._base_url = self._config.owasp_base_url
    
    def parse_glossary_page(
        self,
        html_content: str,
    ) -> CheatSheetIndex:
        """
        Parse the OWASP Glossary.html page to extract all cheat sheets.
        
        This is the most reliable source as it contains a curated, 
        alphabetically organized list with language tags.
        
        Args:
            html_content: Raw HTML of the Glossary.html page
            
        Returns:
            CheatSheetIndex with all discovered cheat sheets
        """
        cheatsheets = []
        categories = set()
        languages_map = {}  # Track which languages each cheatsheet uses
        
        soup = BeautifulSoup(html_content, "lxml")
        
        # Method 1: Parse the sidebar navigation (most reliable)
        # Look for links in the navigation that point to cheatsheets/
        nav_links = soup.find_all("a", href=re.compile(r"cheatsheets/.*_Cheat_Sheet\.html"))
        
        for link in nav_links:
            href = link.get("href", "")
            text = link.get_text(strip=True)
            
            if not href or not text:
                continue
            
            # Build full URL
            full_url = urljoin(self._base_url + "/", href)
            
            # Extract ID from URL (e.g., "Authentication_Cheat_Sheet" -> "authentication")
            match = re.search(r"cheatsheets/(.+)_Cheat_Sheet\.html", href)
            if match:
                raw_id = match.group(1)
                cs_id = raw_id.replace("_", "-").lower()
            else:
                cs_id = self._slugify(text)
            
            # Clean title
            title = self._clean_title(text)
            
            # Determine category from title
            category = self._extract_category(title, href)
            categories.add(category)
            
            # Avoid duplicates
            if any(cs["url"] == full_url for cs in cheatsheets):
                continue
            
            cheatsheets.append({
                "id": cs_id,
                "title": title,
                "url": full_url,
                "category": category,
            })
        
        # Method 2: Parse main content for language tags
        # Look for language icons next to cheatsheet links
        main_content = soup.find("article") or soup.find("main") or soup
        
        for link in main_content.find_all("a", href=re.compile(r"cheatsheets/.*\.html")):
            href = link.get("href", "")
            full_url = urljoin(self._base_url + "/", href)
            
            # Find language icons near this link
            parent = link.parent
            if parent:
                lang_icons = parent.find_all("img", alt=True)
                languages = [img.get("alt", "").strip() for img in lang_icons if img.get("alt")]
                if languages:
                    languages_map[full_url] = languages
        
        # Add language info to cheatsheets (as a string for compatibility)
        for cs in cheatsheets:
            if cs["url"] in languages_map:
                cs["languages"] = ", ".join(languages_map[cs["url"]])
        
        # Sort alphabetically by title
        cheatsheets.sort(key=lambda x: x["title"].lower())
        
        logger.info(f"Parsed {len(cheatsheets)} cheat sheets from Glossary.html")
        
        return CheatSheetIndex(
            cheatsheets=cheatsheets,
            categories=sorted(categories),
            last_fetched=datetime.now(),
            total_count=len(cheatsheets),
        )

    def parse_cheatsheet_index(
        self,
        html_content: str,
        markdown_content: str = "",
    ) -> CheatSheetIndex:
        """
        Parse the cheat sheet index page to extract available cheat sheets.
        
        Args:
            html_content: Raw HTML of the index page
            markdown_content: Optional markdown content
            
        Returns:
            CheatSheetIndex with all discovered cheat sheets
        """
        cheatsheets = []
        categories = set()
        
        soup = BeautifulSoup(html_content, "lxml")
        
        # Look for cheat sheet links - they typically end with _Cheat_Sheet.html
        # or _Cheat_Sheet/ 
        cheatsheet_pattern = re.compile(
            r"cheatsheets/([^/]+)_Cheat_Sheet",
            re.IGNORECASE
        )
        
        # Also look for direct links in the content
        for link in soup.find_all("a", href=True):
            href = link.get("href", "")
            text = link.get_text(strip=True)
            
            # Skip empty or anchor-only links
            if not href or href.startswith("#") or not text:
                continue
            
            # Check if it's a cheat sheet link
            if "cheat" in href.lower() or "cheat" in text.lower():
                # Normalize URL
                full_url = urljoin(self._base_url, href)
                
                # Extract ID from URL
                match = cheatsheet_pattern.search(href)
                if match:
                    cs_id = match.group(1).replace("_", "-").lower()
                else:
                    # Generate ID from link text
                    cs_id = self._slugify(text)
                
                # Determine category
                category = self._extract_category(text, href)
                categories.add(category)
                
                cheatsheets.append({
                    "id": cs_id,
                    "title": self._clean_title(text),
                    "url": full_url,
                    "category": category,
                })
        
        # Deduplicate by URL
        seen_urls = set()
        unique_cheatsheets = []
        for cs in cheatsheets:
            if cs["url"] not in seen_urls:
                seen_urls.add(cs["url"])
                unique_cheatsheets.append(cs)
        
        return CheatSheetIndex(
            cheatsheets=unique_cheatsheets,
            categories=sorted(categories),
            last_fetched=datetime.now(),
            total_count=len(unique_cheatsheets),
        )
    
    def parse_sitemap_for_cheatsheets(self, sitemap_content: str) -> list[dict[str, str]]:
        """
        Parse sitemap.xml to extract cheat sheet URLs.
        
        Args:
            sitemap_content: XML content of sitemap
            
        Returns:
            List of cheat sheet info dictionaries
        """
        cheatsheets = []
        
        soup = BeautifulSoup(sitemap_content, "lxml-xml")
        
        for url_elem in soup.find_all("url"):
            loc = url_elem.find("loc")
            if loc and loc.text:
                url = loc.text.strip()
                
                # Filter for cheat sheet pages
                if "_Cheat_Sheet" in url or "/cheatsheets/" in url:
                    # Extract title from URL
                    path = urlparse(url).path
                    filename = path.split("/")[-1].replace(".html", "")
                    title = filename.replace("_", " ").replace("-", " ")
                    title = re.sub(r"\s+Cheat\s+Sheet$", "", title, flags=re.IGNORECASE)
                    
                    cs_id = self._slugify(title)
                    category = self._extract_category(title, url)
                    
                    cheatsheets.append({
                        "id": cs_id,
                        "title": title.strip(),
                        "url": url,
                        "category": category,
                    })
        
        return cheatsheets
    
    def parse_cheatsheet(
        self,
        url: str,
        html_content: str,
        markdown_content: str,
    ) -> CheatSheet:
        """
        Parse a single cheat sheet page into structured data.
        
        Args:
            url: Source URL
            html_content: Raw HTML content
            markdown_content: Markdown version of content
            
        Returns:
            Parsed CheatSheet object
        """
        soup = BeautifulSoup(html_content, "lxml")
        
        # Extract title
        title_elem = soup.find("h1") or soup.find("title")
        title = title_elem.get_text(strip=True) if title_elem else "Unknown"
        title = self._clean_title(title)
        
        # Generate ID
        cs_id = self._slugify(title)
        
        # Extract category and icon
        category = self._extract_category(title, url)
        icon = self._get_category_icon(category)
        
        # Extract introduction (first paragraph or abstract)
        intro = self._extract_introduction(soup, markdown_content)
        
        # Parse sections
        sections = self._parse_sections(soup, markdown_content)
        
        # Extract risks
        risks = self._extract_risks(sections, title)
        
        # Generate attack examples from content
        attack_examples = self._extract_attack_examples(sections, risks)
        
        # Extract metadata
        contributors = self._extract_contributors(soup)
        tags = self._extract_tags(soup, title, category)
        related = self._find_related_cheatsheets(soup)
        
        return CheatSheet(
            id=cs_id,
            title=title,
            url=url,
            description=intro[:500] if intro else "",
            category=category,
            icon=icon,
            introduction=intro,
            sections=sections,
            risks=risks,
            attack_examples=attack_examples,
            last_updated=datetime.now(),
            contributors=contributors,
            related_cheatsheets=related,
            tags=tags,
            raw_markdown=markdown_content,
        )
    
    def _extract_introduction(
        self,
        soup: BeautifulSoup,
        markdown: str,
    ) -> str:
        """Extract introduction section from content."""
        # Try to find introduction heading
        intro_patterns = ["introduction", "overview", "about", "summary"]
        
        for pattern in intro_patterns:
            header = soup.find(
                re.compile(r"h[1-3]"),
                string=re.compile(pattern, re.IGNORECASE)
            )
            if header:
                # Get content until next header
                content = []
                for sibling in header.find_next_siblings():
                    if sibling.name and sibling.name.startswith("h"):
                        break
                    content.append(sibling.get_text(strip=True))
                if content:
                    return " ".join(content)
        
        # Fallback: get first few paragraphs
        paragraphs = soup.find_all("p", limit=3)
        intro_text = " ".join(p.get_text(strip=True) for p in paragraphs)
        
        return intro_text[:1000] if intro_text else ""
    
    def _parse_sections(
        self,
        soup: BeautifulSoup,
        markdown: str,
    ) -> list[CheatSheetSection]:
        """Parse content into hierarchical sections."""
        sections = []
        
        # Find all h2 headers as main sections
        for h2 in soup.find_all("h2"):
            section_title = self._clean_title(h2.get_text(strip=True))
            
            # Skip navigation/footer sections
            if any(skip in section_title.lower() for skip in ["navigation", "footer", "sidebar"]):
                continue
            
            # Collect content until next h2
            content_parts = []
            subsections = []
            code_examples = []
            warnings = []
            tips = []
            
            current = h2.find_next_sibling()
            while current and current.name != "h2":
                if current.name == "h3":
                    # This is a subsection
                    subsection = self._parse_subsection(current)
                    if subsection:
                        subsections.append(subsection)
                elif current.name == "pre" or current.name == "code":
                    code_examples.append(current.get_text())
                elif current.name in ["div", "p"]:
                    text = current.get_text(strip=True)
                    
                    # Check for warnings/cautions
                    if any(w in text.lower() for w in ["warning", "caution", "danger", "note:"]):
                        warnings.append(text)
                    elif any(t in text.lower() for t in ["tip:", "best practice", "recommendation"]):
                        tips.append(text)
                    else:
                        content_parts.append(text)
                
                current = current.find_next_sibling()
            
            section = CheatSheetSection(
                title=section_title,
                content="\n\n".join(content_parts),
                subsections=subsections,
                code_examples=code_examples,
                warnings=warnings,
                tips=tips,
            )
            sections.append(section)
        
        return sections
    
    def _parse_subsection(self, h3_elem: Any) -> Optional[CheatSheetSection]:
        """Parse an h3 subsection."""
        title = self._clean_title(h3_elem.get_text(strip=True))
        content_parts = []
        code_examples = []
        
        current = h3_elem.find_next_sibling()
        while current and current.name not in ["h2", "h3"]:
            if current.name == "pre" or current.name == "code":
                code_examples.append(current.get_text())
            elif current.name in ["p", "div", "ul", "ol"]:
                content_parts.append(current.get_text(strip=True))
            current = current.find_next_sibling()
        
        if not content_parts and not code_examples:
            return None
        
        return CheatSheetSection(
            title=title,
            content="\n\n".join(content_parts),
            code_examples=code_examples,
        )
    
    def _extract_risks(
        self,
        sections: list[CheatSheetSection],
        cheatsheet_title: str,
    ) -> list[RiskItem]:
        """Extract risk items from parsed sections."""
        risks = []
        risk_keywords = [
            "vulnerability", "risk", "threat", "attack", "weakness",
            "exploit", "injection", "bypass", "disclosure", "exposure"
        ]
        
        for idx, section in enumerate(sections, 1):
            # Check if section discusses a security risk
            section_lower = section.title.lower()
            content_lower = section.content.lower()
            
            is_risk_section = any(kw in section_lower or kw in content_lower for kw in risk_keywords)
            
            if is_risk_section or self._looks_like_risk_section(section):
                risk_id = f"{self._slugify(cheatsheet_title)[:6].upper()}{idx:02d}"
                
                # Determine severity
                severity = self._assess_severity(section.content)
                
                # Extract impacts
                impacts = self._extract_list_items(section.content, ["impact", "effect", "result", "consequence"])
                
                # Extract mitigations
                mitigations = self._extract_list_items(
                    section.content,
                    ["mitigation", "prevention", "defense", "protect", "secure", "recommendation"]
                )
                
                # If no explicit mitigations found, look for "do/don't" patterns
                if not mitigations:
                    mitigations = self._extract_recommendations(section.content)
                
                # Clean description - remove code blocks and JSON
                clean_description = self._clean_description(section.content)
                
                risk = RiskItem(
                    id=risk_id,
                    title=section.title,
                    severity=severity,
                    icon=self._get_severity_icon(severity),
                    description=clean_description[:500],
                    impacts=impacts[:5],
                    mitigations=mitigations[:7],
                    examples=[ex[:200] for ex in section.code_examples[:3]],
                )
                risks.append(risk)
        
        # If no explicit risks found, create general risk from content
        if not risks and sections:
            main_section = sections[0]
            clean_description = self._clean_description(main_section.content)
            risks.append(RiskItem(
                id=f"{self._slugify(cheatsheet_title)[:6].upper()}01",
                title=cheatsheet_title,
                severity="Medium",
                icon="⚠️",
                description=clean_description[:500],
                mitigations=self._extract_recommendations(main_section.content)[:5],
            ))
        
        return risks
    
    def _clean_description(self, content: str) -> str:
        """Remove code blocks, JSON, and other non-prose content from description."""
        if not content:
            return ""
        
        # Remove code blocks (```...```)
        cleaned = re.sub(r'```[\s\S]*?```', '', content)
        
        # Remove inline code (`...`)
        cleaned = re.sub(r'`[^`]+`', '', cleaned)
        
        # Remove JSON-like content (objects and arrays)
        cleaned = re.sub(r'\{[^}]*\}', '', cleaned)
        cleaned = re.sub(r'\[[^\]]*\]', '', cleaned)
        
        # Remove lines that look like code (start with common code patterns)
        lines = cleaned.split('\n')
        prose_lines = []
        for line in lines:
            line_stripped = line.strip()
            # Skip lines that look like code
            if any([
                line_stripped.startswith(('import ', 'from ', 'def ', 'class ', 'if ', 'for ', 'while ')),
                line_stripped.startswith(('const ', 'let ', 'var ', 'function ')),
                line_stripped.startswith(('<', '{', '[', '//', '#!', '#!/')),
                line_stripped.endswith((';', '{', '}', ':')),
                '=' in line_stripped and '"' in line_stripped and ':' in line_stripped,  # JSON-like
                line_stripped.startswith('tools='),
                line_stripped.startswith('commands'),
                re.match(r'^[\s]*[\w_]+\s*[=:]\s*[\[\{"\']', line_stripped),  # variable assignment
            ]):
                continue
            prose_lines.append(line)
        
        cleaned = '\n'.join(prose_lines)
        
        # Clean up extra whitespace
        cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
        cleaned = re.sub(r' {2,}', ' ', cleaned)
        cleaned = cleaned.strip()
        
        # If we've removed everything, return a generic message
        if len(cleaned) < 20:
            return "See the cheat sheet for detailed security guidance."
        
        return cleaned
    
    def _looks_like_risk_section(self, section: CheatSheetSection) -> bool:
        """Heuristic check if section discusses security risks."""
        # Count security-related terms
        security_terms = [
            "secure", "security", "protect", "prevent", "attack",
            "vulnerability", "exploit", "malicious", "unauthorized",
            "injection", "bypass", "sensitive", "credential", "token"
        ]
        
        text = f"{section.title} {section.content}".lower()
        matches = sum(1 for term in security_terms if term in text)
        
        return matches >= 2
    
    def _assess_severity(self, content: str) -> str:
        """Assess severity level based on content keywords."""
        content_lower = content.lower()
        
        for severity, keywords in SEVERITY_KEYWORDS.items():
            if any(kw in content_lower for kw in keywords):
                return severity.capitalize()
        
        return "Medium"
    
    def _extract_list_items(
        self,
        content: str,
        trigger_keywords: list[str],
    ) -> list[str]:
        """Extract list items following certain keywords."""
        items = []
        
        # Look for bullet points or numbered lists
        lines = content.split("\n")
        in_relevant_section = False
        
        for line in lines:
            line_lower = line.lower().strip()
            
            # Check if we're entering a relevant section
            if any(kw in line_lower for kw in trigger_keywords):
                in_relevant_section = True
                continue
            
            # Check if line is a list item
            if in_relevant_section:
                # Match bullet points, numbers, or dashes
                if re.match(r"^[\-\*\•]\s+", line.strip()) or re.match(r"^\d+[\.\)]\s+", line.strip()):
                    item = re.sub(r"^[\-\*\•\d\.\)]+\s*", "", line.strip())
                    if item and len(item) > 10:
                        items.append(item)
                elif line.strip() == "" or line.strip().startswith("#"):
                    in_relevant_section = False
        
        return items
    
    def _extract_recommendations(self, content: str) -> list[str]:
        """Extract do/don't recommendations from content."""
        recommendations = []
        
        # Patterns for recommendations
        patterns = [
            r"(?:do|should|must|always|ensure|use|implement)[\s:]+([^\.]+\.)",
            r"(?:don't|should not|must not|never|avoid)[\s:]+([^\.]+\.)",
            r"(?:recommend|best practice|tip)[\s:]+([^\.]+\.)",
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            recommendations.extend(matches)
        
        # Clean up
        recommendations = [r.strip() for r in recommendations if len(r) > 20]
        
        return list(set(recommendations))[:10]
    
    def _extract_attack_examples(
        self,
        sections: list[CheatSheetSection],
        risks: list[RiskItem],
    ) -> list[AttackExample]:
        """Generate attack examples from sections and risks."""
        examples = []
        
        # Look for attack/exploit sections
        attack_keywords = ["attack", "exploit", "example", "scenario", "case study"]
        
        for section in sections:
            if any(kw in section.title.lower() for kw in attack_keywords):
                # Find associated risk
                associated_risk = next(
                    (r for r in risks if r.title.lower() in section.title.lower()),
                    risks[0] if risks else None
                )
                
                if associated_risk:
                    example = AttackExample(
                        risk_id=associated_risk.id,
                        title=section.title,
                        goal=section.content[:200] if section.content else "",
                        attack_prompt=section.code_examples[0] if section.code_examples else "",
                        impact=associated_risk.impacts[0] if associated_risk.impacts else "",
                        mitigation=associated_risk.mitigations[0] if associated_risk.mitigations else "",
                    )
                    examples.append(example)
        
        # Generate examples from risks if none found
        if not examples:
            for risk in risks[:3]:
                example = AttackExample(
                    risk_id=risk.id,
                    title=f"{risk.title} Attack Scenario",
                    goal=f"Exploit {risk.title.lower()} vulnerability",
                    attack_prompt=risk.examples[0] if risk.examples else "See documentation for examples",
                    impact=risk.impacts[0] if risk.impacts else "Security compromise",
                    mitigation=risk.mitigations[0] if risk.mitigations else "Apply recommended controls",
                )
                examples.append(example)
        
        return examples
    
    def _extract_contributors(self, soup: BeautifulSoup) -> list[str]:
        """Extract contributor names if available."""
        contributors = []
        
        # Look for authors/contributors section
        for header in soup.find_all(["h2", "h3"]):
            if "author" in header.get_text().lower() or "contributor" in header.get_text().lower():
                next_elem = header.find_next_sibling()
                if next_elem:
                    contributors.extend(
                        [li.get_text(strip=True) for li in next_elem.find_all("li")]
                    )
        
        return contributors[:10]
    
    def _extract_tags(
        self,
        soup: BeautifulSoup,
        title: str,
        category: str,
    ) -> list[str]:
        """Extract or generate tags for the cheat sheet."""
        tags = [category]
        
        # Extract from meta keywords if available
        meta_keywords = soup.find("meta", {"name": "keywords"})
        if meta_keywords:
            keywords = meta_keywords.get("content", "").split(",")
            tags.extend([k.strip().lower() for k in keywords if k.strip()])
        
        # Generate from title
        title_words = re.findall(r"\b[A-Z][a-z]+\b", title)
        tags.extend([w.lower() for w in title_words if len(w) > 3])
        
        return list(set(tags))[:10]
    
    def _find_related_cheatsheets(self, soup: BeautifulSoup) -> list[str]:
        """Find references to other cheat sheets."""
        related = []
        
        for link in soup.find_all("a", href=True):
            href = link.get("href", "")
            if "_Cheat_Sheet" in href and href != "#":
                # Extract ID
                match = re.search(r"([^/]+)_Cheat_Sheet", href)
                if match:
                    related.append(match.group(1).replace("_", "-").lower())
        
        return list(set(related))[:5]
    
    def _extract_category(self, title: str, url: str) -> str:
        """Determine category from title and URL."""
        text = f"{title} {url}".lower()
        
        # Check against known categories
        for category in CATEGORY_ICONS.keys():
            if category in text:
                return category.capitalize()
        
        # Fallback categorization
        if any(term in text for term in ["auth", "login", "password", "credential"]):
            return "Authentication"
        elif any(term in text for term in ["inject", "sql", "xss", "command"]):
            return "Injection"
        elif any(term in text for term in ["api", "rest", "graphql"]):
            return "API Security"
        elif any(term in text for term in ["web", "http", "browser"]):
            return "Web Security"
        elif any(term in text for term in ["crypto", "encrypt", "hash"]):
            return "Cryptography"
        
        return "General"
    
    def _get_category_icon(self, category: str) -> str:
        """Get icon for a category."""
        return CATEGORY_ICONS.get(category.lower(), CATEGORY_ICONS["default"])
    
    def _get_severity_icon(self, severity: str) -> str:
        """Get icon for a severity level."""
        icons = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢",
        }
        return icons.get(severity, "⚪")
    
    def _clean_title(self, title: str) -> str:
        """Clean up a title string."""
        # Remove pilcrow and other permalink markers
        title = re.sub(r"\s*¶\s*", " ", title)
        # Remove "Cheat Sheet" suffix
        title = re.sub(r"\s*[-–]\s*OWASP.*$", "", title, flags=re.IGNORECASE)
        title = re.sub(r"\s*Cheat\s*Sheet\s*$", "", title, flags=re.IGNORECASE)
        # Normalize whitespace
        title = re.sub(r"\s+", " ", title)
        return title.strip()
    
    def _slugify(self, text: str) -> str:
        """Convert text to URL-safe slug."""
        # Remove special characters
        text = re.sub(r"[^\w\s-]", "", text.lower())
        # Replace spaces with hyphens
        text = re.sub(r"[\s_]+", "-", text)
        # Remove duplicate hyphens
        text = re.sub(r"-+", "-", text)
        return text.strip("-")