import os
from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai_tools import SerperDevTool, ScrapeWebsiteTool
from pydantic import BaseModel

from agents.code_review_crew.utils import get_openai_api_key, get_serper_api_key
from agents.code_review_crew.guardrails.guardrails import security_review_output_guardrail

os.environ["OPENAI_API_KEY"] = get_openai_api_key() or ""
os.environ["SERPER_API_KEY"] = get_serper_api_key() or ""


@CrewBase
class CodeReviewCrew:
    """CodeReview crew"""
    @agent
    def senior_developer(self) -> Agent:
        return Agent(
            config=self.agents_config["senior_developer"],
            llm="gpt-4o-mini",
        )

    @agent
    def security_engineer(self) -> Agent:
        os.environ["SERPER_API_KEY"] = get_serper_api_key() or ""
        return Agent(
            config=self.agents_config["security_engineer"],
            tools=[
                SerperDevTool(
                    search_url="https://owasp.org",
                    base_url=os.getenv("DLAI_SERPER_BASE_URL", "https://google.serper.dev"),
                ),
                ScrapeWebsiteTool(),
            ],
            llm="gpt-4o-mini",
        )

    @agent
    def tech_lead(self) -> Agent:
        return Agent(
            config=self.agents_config["tech_lead"],
            llm="gpt-4o-mini",
        )

    @task
    def analyze_code_quality(self) -> Task:
        class CodeQualityJSON(BaseModel):
            critical_issues: list[str]
            minor_issues: list[str]
            reasoning: str

        return Task(
            config=self.tasks_config["analyze_code_quality"],
            output_json=CodeQualityJSON,
            async_execution=True,
        )

    @task
    def review_security(self) -> Task:
        class SecurityVulnerability(BaseModel):
            description: str
            risk_level: str
            evidence: str

        class ReviewSecurityJSON(BaseModel):
            security_vulnerabilities: list[SecurityVulnerability]
            blocking: bool
            highest_risk: str
            security_recommendations: list[str]

        return Task(
            config=self.tasks_config["review_security"],
            output_json=ReviewSecurityJSON,
            async_execution=True,
            guardrails=[security_review_output_guardrail],
        )

    @task
    def summarize_findings(self) -> Task:
        class Fix(BaseModel):
            description: str
            solutions: str
            explanation: str

        class SummarizedFindingsJSON(BaseModel):
            confidence: int
            findings: str
            fix: list[Fix]
            recommendations: str

        return Task(
            config=self.tasks_config["summarize_findings"],
            output_json=SummarizedFindingsJSON,
        )

    @crew
    def crew(self) -> Crew:
        """Creates the CodeReviewCrew crew"""
        return Crew(
            agents=self.agents,
            tasks=self.tasks,
            process=Process.sequential,
            verbose=True,
            memory=False,
        )
