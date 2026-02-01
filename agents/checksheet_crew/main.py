#!/usr/bin/env python3
"""
OWASP Checksheet Crew

Creates a CrewAI workflow that extracts an OWASP cheat sheet into a
structured checksheet JSON compatible with the Streamlit app.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Optional

import yaml
from crewai import Agent, Crew, Task
from crewai_tools import ScrapeWebsiteTool
from dotenv import load_dotenv
from pydantic import BaseModel, Field


# =============================================================================
# Configuration Loading
# =============================================================================

def load_configs() -> tuple[dict, dict]:
    """Load agent and task configurations from YAML files."""
    config_files = {
        "agents": os.path.join(os.path.dirname(__file__), "config", "agents.yaml"),
        "tasks": os.path.join(os.path.dirname(__file__), "config", "tasks.yaml"),
    }

    configs: dict[str, dict] = {}
    for config_type, file_path in config_files.items():
        with open(file_path, "r", encoding="utf-8") as file:
            configs[config_type] = yaml.safe_load(file)

    return configs["agents"], configs["tasks"]


# =============================================================================
# Output Schemas (Aligned with src.models)
# =============================================================================

class RiskItemJSON(BaseModel):
    id: str = Field(..., description="Unique identifier for the risk")
    title: str = Field(..., description="Risk title")
    severity: str = Field(default="Medium", description="Critical, High, Medium, Low")
    icon: str = Field(default="⚠️", description="Display icon")
    description: str = Field(default="", description="Detailed description")
    types: list[tuple[str, str]] = Field(default_factory=list, description="Types of risk")
    impacts: list[str] = Field(default_factory=list, description="Potential impacts")
    mitigations: list[str] = Field(default_factory=list, description="Mitigation strategies")
    examples: list[str] = Field(default_factory=list, description="Attack examples")
    references: list[str] = Field(default_factory=list, description="Reference links")


class AttackExampleJSON(BaseModel):
    risk_id: str = Field(..., description="Associated risk ID")
    title: str = Field(..., description="Attack title")
    goal: str = Field(default="", description="Attack goal description")
    attack_prompt: str = Field(default="", description="Example attack prompt or code")
    impact: str = Field(default="", description="Impact description")
    mitigation: str = Field(default="", description="Mitigation strategy")


class CheatSheetSectionJSON(BaseModel):
    title: str = Field(..., description="Section title")
    content: str = Field(default="", description="Section content in markdown")
    subsections: list["CheatSheetSectionJSON"] = Field(default_factory=list)
    code_examples: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    tips: list[str] = Field(default_factory=list)


class ChecksheetJSON(BaseModel):
    id: str
    title: str
    url: str
    description: str = ""
    category: str = "General"
    icon: str = "📋"
    introduction: str = ""
    sections: list[CheatSheetSectionJSON] = Field(default_factory=list)
    risks: list[RiskItemJSON] = Field(default_factory=list)
    attack_examples: list[AttackExampleJSON] = Field(default_factory=list)
    last_updated: Optional[str] = None
    contributors: list[str] = Field(default_factory=list)
    related_cheatsheets: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    raw_markdown: str = ""


# =============================================================================
# Helpers
# =============================================================================

def slugify(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9\s-]", "", text)
    text = re.sub(r"\s+", "-", text)
    return text[:80] or "cheatsheet"


def normalize_severity(severity: str) -> str:
    value = (severity or "").strip().lower()
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }
    return mapping.get(value, "Medium")


def write_output(output: dict, output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    file_name = f"{slugify(output.get('title', 'cheatsheet'))}.json"
    file_path = os.path.join(output_dir, file_name)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    return file_path


# =============================================================================
# Crew Builder
# =============================================================================

@dataclass
class ChecksheetCrew:
    verbose: bool = True

    def __post_init__(self) -> None:
        self.agents_config, self.tasks_config = load_configs()
        self.scrape_tool = ScrapeWebsiteTool()
        self._build_agents()
        self._build_tasks()
        self._build_crew()

    def _build_agents(self) -> None:
        self.extractor = Agent(
            config=self.agents_config["cheatsheet_extractor"],
            tools=[self.scrape_tool],
            verbose=self.verbose,
        )
        self.validator = Agent(
            config=self.agents_config["cheatsheet_validator"],
            verbose=self.verbose,
        )

    def _build_tasks(self) -> None:
        self.extract_task = Task(
            config=self.tasks_config["extract_cheatsheet"],
            output_json=ChecksheetJSON,
            agent=self.extractor,
        )

        self.validate_task = Task(
            config=self.tasks_config["validate_cheatsheet"],
            output_json=ChecksheetJSON,
            context=[self.extract_task],
            agent=self.validator,
        )

    def _build_crew(self) -> None:
        self.crew = Crew(
            agents=[self.extractor, self.validator],
            tasks=[self.extract_task, self.validate_task],
            memory=True,
        )

    def run(self, url: str, output_dir: str = "data/checksheets") -> dict[str, Any]:
        inputs = {"url": url}
        result = self.crew.kickoff(inputs=inputs)

        # Pull the final JSON result from the last task
        json_output = None
        if hasattr(result, "tasks_output") and result.tasks_output:
            json_output = result.tasks_output[-1].json_dict
        elif hasattr(result, "json_dict"):
            json_output = result.json_dict

        if not json_output:
            raise RuntimeError("No JSON output produced by the crew.")

        # Normalize severities for safety
        for risk in json_output.get("risks", []):
            risk["severity"] = normalize_severity(risk.get("severity", ""))

        output_path = write_output(json_output, output_dir)
        json_output["_output_file"] = output_path
        return json_output


# =============================================================================
# Main Entry Point
# =============================================================================

def main() -> None:
    load_dotenv()

    url = os.environ.get("CHEATSHEET_URL")
    if not url:
        print("Error: CHEATSHEET_URL environment variable is required.")
        print("Example: set CHEATSHEET_URL=https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html")
        return

    crew = ChecksheetCrew(verbose=True)
    result = crew.run(url)

    print("\n✅ Checksheet extraction complete")
    print(f"Output saved to: {result.get('_output_file', 'unknown')}")


if __name__ == "__main__":
    main()
