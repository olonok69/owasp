#!/usr/bin/env python3
"""
OWASP Top 10 Crew

Creates a CrewAI workflow that extracts an OWASP Top 10 page into
structured JSON compatible with the unified Streamlit app.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any

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
# Output Schemas
# =============================================================================

class Top10RiskJSON(BaseModel):
    id: str = Field(..., description="Risk ID (e.g., A01, LLM01)")
    title: str = Field(..., description="Risk title")
    severity: str = Field(default="Medium", description="Critical, High, Medium, Low")
    icon: str = Field(default="⚠️", description="Display icon")
    description: str = Field(default="", description="Short description")
    types: list[tuple[str, str]] = Field(default_factory=list)
    impacts: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    examples: list[str] = Field(default_factory=list)


class Top10JSON(BaseModel):
    id: str
    title: str
    source_url: str
    risks: dict[str, Top10RiskJSON]


# =============================================================================
# Helpers
# =============================================================================

def slugify(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9\s-]", "", text)
    text = re.sub(r"\s+", "-", text)
    return text[:80] or "top10"


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
    file_name = f"{slugify(output.get('id', 'top10'))}.json"
    file_path = os.path.join(output_dir, file_name)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    return file_path


# =============================================================================
# Crew Builder
# =============================================================================

@dataclass
class Top10Crew:
    verbose: bool = True

    def __post_init__(self) -> None:
        self.agents_config, self.tasks_config = load_configs()
        self.scrape_tool = ScrapeWebsiteTool()
        self._build_agents()
        self._build_tasks()
        self._build_crew()

    def _build_agents(self) -> None:
        self.extractor = Agent(
            config=self.agents_config["top10_extractor"],
            tools=[self.scrape_tool],
            verbose=self.verbose,
        )
        self.validator = Agent(
            config=self.agents_config["top10_validator"],
            verbose=self.verbose,
        )

    def _build_tasks(self) -> None:
        self.extract_task = Task(
            config=self.tasks_config["extract_top10"],
            output_json=Top10JSON,
            agent=self.extractor,
        )

        self.validate_task = Task(
            config=self.tasks_config["validate_top10"],
            output_json=Top10JSON,
            context=[self.extract_task],
            agent=self.validator,
        )

    def _build_crew(self) -> None:
        self.crew = Crew(
            agents=[self.extractor, self.validator],
            tasks=[self.extract_task, self.validate_task],
            memory=True,
        )

    def run(self, url: str, output_dir: str = "data/top10") -> dict[str, Any]:
        inputs = {"url": url}
        result = self.crew.kickoff(inputs=inputs)

        json_output = None
        if hasattr(result, "tasks_output") and result.tasks_output:
            json_output = result.tasks_output[-1].json_dict
        elif hasattr(result, "json_dict"):
            json_output = result.json_dict

        if not json_output:
            raise RuntimeError("No JSON output produced by the crew.")

        for risk in json_output.get("risks", {}).values():
            risk["severity"] = normalize_severity(risk.get("severity", ""))

        output_path = write_output(json_output, output_dir)
        json_output["_output_file"] = output_path
        return json_output


# =============================================================================
# Main Entry Point
# =============================================================================

def main() -> None:
    load_dotenv()

    url = os.environ.get("TOP10_URL")
    if not url:
        print("Error: TOP10_URL environment variable is required.")
        print("Example: set TOP10_URL=https://owasp.org/Top10/2025/")
        return

    crew = Top10Crew(verbose=True)
    result = crew.run(url)

    print("\n✅ Top 10 extraction complete")
    print(f"Output saved to: {result.get('_output_file', 'unknown')}")


if __name__ == "__main__":
    main()
