#!/usr/bin/env python3
"""
Automatic Code Review Crew Application

A multi-agent AI system built with CrewAI that automatically reviews pull requests
for code quality and security vulnerabilities. The crew consists of three specialized
agents working together to analyze code changes, identify issues, and make approval decisions.

Features:
- Memory: Agents remember patterns across multiple PR reviews
- Guardrails: Validates outputs to ensure consistency and quality
- Execution Hooks: Automates file reading before agent execution
"""

import os
import yaml
from typing import Any, Tuple

from crewai import Agent, Task, Crew
from crewai_tools import SerperDevTool, ScrapeWebsiteTool
from pydantic import BaseModel
from dotenv import load_dotenv

# =============================================================================
# Configuration Loading
# =============================================================================

def load_configs() -> tuple[dict, dict]:
    """
    Load agent and task configurations from YAML files.
    
    Returns:
        Tuple containing agents_config and tasks_config dictionaries.
    """
    config_files = {
        'agents': 'config/agents.yaml',
        'tasks': 'config/tasks.yaml'
    }
    
    configs = {}
    for config_type, file_path in config_files.items():
        with open(file_path, 'r', encoding='utf-8') as file:
            configs[config_type] = yaml.safe_load(file)
    
    return configs['agents'], configs['tasks']


# =============================================================================
# Pydantic Models for Structured Output
# =============================================================================

class CodeQualityJSON(BaseModel):
    """Schema for code quality analysis output."""
    critical_issues: list[str]
    minor_issues: list[str]
    reasoning: str


class SecurityVulnerability(BaseModel):
    """Schema for individual security vulnerability."""
    description: str
    risk_level: str
    evidence: str


class ReviewSecurityJSON(BaseModel):
    """Schema for security review output."""
    security_vulnerabilities: list[SecurityVulnerability]
    owasp_top_10: list[dict[str, Any]]
    blocking: bool
    highest_risk: str
    security_recommendations: list[str]


# =============================================================================
# Guardrails
# =============================================================================

def security_review_output_guardrail(output: Any) -> Tuple[bool, Any]:
    """
    Guardrail for validating security review output.
    
    Validates that:
    - All risk levels are valid (low, medium, high)
    - The highest_risk value matches the actual highest risk in vulnerabilities
    
    Args:
        output: TaskOutput object or dictionary containing the security review results.
        
    Returns:
        Tuple of (success: bool, result_or_error_message: Any)
    """
    # Extract JSON output from TaskOutput object
    try:
        json_output = output if isinstance(output, dict) else output.json_dict
    except Exception as e:
        return (False, (
            f"Error retrieving the `json_dict` argument: \n{str(e)}\n"
            "Make sure you set the output_json parameter in the Task."
        ))
    
    # Handle missing JSON output
    if not json_output:
        return (False, "Missing JSON output from task.")
    
    # Define valid risk levels
    valid_risk_levels = ['low', 'medium', 'high']
    
    # Check if security_vulnerabilities key exists
    if 'security_vulnerabilities' not in json_output:
        return (False, "Missing 'security_vulnerabilities' key in output.")
    
    # Validate each vulnerability's risk level
    vulnerabilities = json_output.get('security_vulnerabilities', [])
    risk_levels_found = []
    
    for vuln in vulnerabilities:
        risk_level = vuln.get('risk_level', '').lower()
        if risk_level not in valid_risk_levels:
            return (False, f"Invalid risk_level '{risk_level}'. Must be one of: {valid_risk_levels}")
        risk_levels_found.append(risk_level)
    
    # Validate highest_risk matches actual highest risk (auto-fix if needed)
    if risk_levels_found:
        # Determine actual highest risk
        if 'high' in risk_levels_found:
            actual_highest = 'high'
        elif 'medium' in risk_levels_found:
            actual_highest = 'medium'
        else:
            actual_highest = 'low'
        
        reported_highest = json_output.get('highest_risk', '').lower()
        if reported_highest not in valid_risk_levels or reported_highest != actual_highest:
            json_output['highest_risk'] = actual_highest
    
    return (True, json_output)


def review_decision_guardrail(output: Any) -> Tuple[bool, Any]:
    """
    Guardrail for validating review decision output.
    
    Ensures the output includes one of the required decision values:
    'approve', 'request changes', or 'escalate'.
    
    Args:
        output: TaskOutput object or string containing the review decision.
        
    Returns:
        Tuple of (success: bool, result_or_error_message: Any)
    """
    # Extract raw output from TaskOutput object
    try:
        raw_output = output if isinstance(output, str) else output.raw
    except Exception as e:
        return (False, (
            f"Error retrieving the `raw` argument: \n{str(e)}\n"
            "Make sure you set the raw parameter in the Task."
        ))
    
    # Define required decision keywords
    valid_decisions = ["approve", "request changes", "escalate"]
    
    # Check if any valid decision keyword is present
    if not any(decision in raw_output.lower() for decision in valid_decisions):
        return (False, "Output does not include one of the valid actionable decisions.")
    
    return (True, raw_output)


# =============================================================================
# Execution Hooks
# =============================================================================

def read_file_hook(inputs: dict) -> dict:
    """
    Before-kickoff hook that reads the PR file and adds its content to inputs.
    
    This hook automates file reading, which is a non-agentic task that
    doesn't require intelligent decision-making.
    
    Args:
        inputs: Dictionary containing 'file_path' key with path to the PR file.
        
    Returns:
        Modified inputs dictionary with 'file_content' key added.
        
    Raises:
        ValueError: If 'file_path' is missing from inputs.
        RuntimeError: If the file cannot be read.
    """
    # Get the file path from inputs
    filename = inputs.get("file_path")
    
    if not filename:
        raise ValueError("Missing 'file_path' in inputs")
    
    # Read the file contents
    try:
        with open(filename, "r", encoding='utf-8') as f:
            file_contents = f.read()
    except Exception as e:
        raise RuntimeError(f"Failed to read file {filename}: {e}")
    
    # Add file contents to inputs
    inputs["file_content"] = file_contents
    
    return inputs


# =============================================================================
# Crew Builder
# =============================================================================

class AutomaticCodeReviewCrew:
    """
    Automatic Code Review Crew orchestrating multiple AI agents.
    
    This crew analyzes pull requests for code quality and security issues,
    then makes a decision on whether to approve, request changes, or escalate.
    
    Attributes:
        agents_config: Configuration dictionary for agents.
        tasks_config: Configuration dictionary for tasks.
        verbose: Whether to enable verbose output.
    """
    
    def __init__(self, verbose: bool = True):
        """
        Initialize the code review crew.
        
        Args:
            verbose: Enable detailed logging output.
        """
        self.verbose = verbose
        self.agents_config, self.tasks_config = load_configs()
        
        # Initialize tools
        self.serper_search_tool = SerperDevTool(search_url="https://owasp.org")
        self.scrape_website_tool = ScrapeWebsiteTool()
        
        # Build agents and tasks
        self._build_agents()
        self._build_tasks()
        self._build_crew()
    
    def _build_agents(self) -> None:
        """Create all agent instances with their configurations."""
        # Senior Developer Agent - Code Quality Expert
        self.senior_developer = Agent(
            config=self.agents_config['senior_developer'],
            verbose=self.verbose
        )
        
        # Security Engineer Agent - Security Expert with search tools
        self.security_engineer = Agent(
            config=self.agents_config['security_engineer'],
            tools=[self.serper_search_tool, self.scrape_website_tool],
            verbose=self.verbose
        )
        
        # Tech Lead Agent - Decision Maker
        self.tech_lead = Agent(
            config=self.agents_config['tech_lead'],
            verbose=self.verbose
        )
    
    def _build_tasks(self) -> None:
        """Create all task instances with their configurations and guardrails."""
        # Task 1: Analyze Code Quality
        self.analyze_code_quality = Task(
            config=self.tasks_config['analyze_code_quality'],
            output_json=CodeQualityJSON,
            agent=self.senior_developer
        )
        
        # Task 2: Review Security
        self.review_security = Task(
            config=self.tasks_config['review_security'],
            output_json=ReviewSecurityJSON,
            guardrails=[security_review_output_guardrail],
            agent=self.security_engineer
        )
        
        # Task 3: Make Review Decision
        self.make_review_decision = Task(
            config=self.tasks_config['make_review_decision'],
            markdown=True,
            guardrails=[review_decision_guardrail],
            context=[self.analyze_code_quality, self.review_security],
            agent=self.tech_lead
        )

        # Task 4: Write Recommendation Report to markdown file
        self.write_recommendation_report = Task(
            config=self.tasks_config['write_recommendation_report'],
            markdown=True,
            context=[
                self.analyze_code_quality,
                self.review_security,
                self.make_review_decision
            ],
            agent=self.tech_lead
        )
    
    def _build_crew(self) -> None:
        """Assemble the crew with agents, tasks, memory, and hooks."""
        self.crew = Crew(
            agents=[
                self.senior_developer,
                self.security_engineer,
                self.tech_lead
            ],
            tasks=[
                self.analyze_code_quality,
                self.review_security,
                self.make_review_decision,
                self.write_recommendation_report
            ],
            memory=True,
            before_kickoff_callbacks=[read_file_hook]
        )
    
    def review(self, file_path: str) -> Any:
        """
        Execute the code review crew on a pull request file.
        
        Args:
            file_path: Path to the file containing the code changes (diff).
            
        Returns:
            CrewOutput containing the review results.
        """
        inputs = {"file_path": file_path}
        result = self.crew.kickoff(inputs=inputs)

        # Persist the recommendation report if produced
        if hasattr(result, 'tasks_output') and result.tasks_output:
            report_output = result.tasks_output[-1].raw
            report_path = os.path.join("report", "recommendations.md")
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report_output)

        return result


# =============================================================================
# Main Entry Point
# =============================================================================

def main() -> None:
    """Main function to run the automatic code review."""
    # Check for required environment variables
    load_dotenv()
    
    if not os.environ.get("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY environment variable is required.")
        print("Please set it before running the application:")
        print("  export OPENAI_API_KEY='your-api-key'")
        return
    
    # Set defaults for model and local Chroma storage if not provided
    os.environ.setdefault("MODEL", "gpt-4o-mini")
    os.environ.setdefault("CHROMA_DB_DIR", os.path.join(os.getcwd(), ".chroma-store"))
    
    # Path to the code changes file (override with CODE_CHANGES_FILE env)
    pr_file_path = os.environ.get("CODE_CHANGES_FILE", "code_changes.txt")
    
    # Check if the file exists
    if not os.path.exists(pr_file_path):
        print(f"Error: Code changes file '{pr_file_path}' not found.")
        print("Please create a file with the pull request diff content.")
        return
    
    print("=" * 60)
    print("🚀 Starting Automatic Code Review Crew")
    print("=" * 60)
    print(f"\n📄 Reviewing: {pr_file_path}")
    print("-" * 60)
    
    # Initialize and run the crew
    crew = AutomaticCodeReviewCrew(verbose=True)
    result = crew.review(pr_file_path)
    
    print("\n" + "=" * 60)
    print("📋 FINAL REVIEW DECISION")
    print("=" * 60)
    
    # Display the final decision and note where the report is written
    if hasattr(result, 'tasks_output') and result.tasks_output:
        # The decision is produced by make_review_decision (second-to-last task)
        final_decision = result.tasks_output[-2].raw if len(result.tasks_output) >= 2 else result.tasks_output[-1].raw
        print(final_decision)
        print("\n📝 Recommendation report saved to report/recommendations.md")
    else:
        print(result)
    
    print("\n" + "=" * 60)
    print("✅ Code Review Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
