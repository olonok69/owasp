"""
Data Models for OWASP Cheat Sheet Viewer
========================================

Defines Pydantic models for structured data representation.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class RiskItem(BaseModel):
    """Represents a security risk or vulnerability item."""
    
    id: str = Field(..., description="Unique identifier for the risk")
    title: str = Field(..., description="Risk title")
    severity: str = Field(default="Medium", description="Risk severity: Critical, High, Medium, Low")
    icon: str = Field(default="⚠️", description="Display icon")
    description: str = Field(default="", description="Detailed description")
    types: list[tuple[str, str]] = Field(default_factory=list, description="Types of this risk")
    impacts: list[str] = Field(default_factory=list, description="Potential impacts")
    mitigations: list[str] = Field(default_factory=list, description="Mitigation strategies")
    examples: list[str] = Field(default_factory=list, description="Attack examples")
    references: list[str] = Field(default_factory=list, description="Reference links")


class AttackExample(BaseModel):
    """Represents an attack demonstration example."""
    
    risk_id: str = Field(..., description="Associated risk ID")
    title: str = Field(..., description="Attack title")
    goal: str = Field(default="", description="Attack goal description")
    attack_prompt: str = Field(default="", description="Example attack prompt or code")
    impact: str = Field(default="", description="Impact description")
    mitigation: str = Field(default="", description="Mitigation strategy")


class CheatSheetSection(BaseModel):
    """Represents a section within a cheat sheet."""
    
    title: str = Field(..., description="Section title")
    content: str = Field(default="", description="Section content in markdown")
    subsections: list["CheatSheetSection"] = Field(
        default_factory=list, description="Nested subsections"
    )
    code_examples: list[str] = Field(default_factory=list, description="Code examples")
    warnings: list[str] = Field(default_factory=list, description="Warning/caution notes")
    tips: list[str] = Field(default_factory=list, description="Best practice tips")


class CheatSheet(BaseModel):
    """Represents a complete OWASP Cheat Sheet."""
    
    id: str = Field(..., description="Unique identifier (slug)")
    title: str = Field(..., description="Cheat sheet title")
    url: str = Field(..., description="Source URL")
    description: str = Field(default="", description="Brief description")
    category: str = Field(default="General", description="Category classification")
    icon: str = Field(default="📋", description="Display icon")
    
    # Content sections
    introduction: str = Field(default="", description="Introduction text")
    sections: list[CheatSheetSection] = Field(
        default_factory=list, description="Main content sections"
    )
    
    # Extracted risk/security items
    risks: list[RiskItem] = Field(default_factory=list, description="Identified risks")
    attack_examples: list[AttackExample] = Field(
        default_factory=list, description="Attack demonstrations"
    )
    
    # Metadata
    last_updated: Optional[datetime] = Field(default=None, description="Last update date")
    contributors: list[str] = Field(default_factory=list, description="Contributors")
    related_cheatsheets: list[str] = Field(
        default_factory=list, description="Related cheat sheet IDs"
    )
    tags: list[str] = Field(default_factory=list, description="Tags for categorization")
    
    # Raw content for fallback
    raw_markdown: str = Field(default="", description="Raw markdown content")


class CheatSheetIndex(BaseModel):
    """Index of all available cheat sheets."""
    
    cheatsheets: list[dict[str, str]] = Field(
        default_factory=list,
        description="List of {id, title, url, category} dicts"
    )
    categories: list[str] = Field(default_factory=list, description="Available categories")
    last_fetched: datetime = Field(
        default_factory=datetime.now, description="When index was fetched"
    )
    total_count: int = Field(default=0, description="Total number of cheat sheets")


class CacheEntry(BaseModel):
    """Represents a cached data entry."""
    
    key: str = Field(..., description="Cache key")
    data: dict = Field(..., description="Cached data")
    created_at: datetime = Field(default_factory=datetime.now)
    expires_at: datetime = Field(..., description="Expiration datetime")
    content_hash: str = Field(default="", description="Hash of content for change detection")
    
    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        return datetime.now() > self.expires_at
