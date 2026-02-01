# OWASP Top 10 Crew

Generates structured Top 10 JSON for the unified Streamlit app. The output can be selected from the Top 10 section when using Local Top 10 JSON.

## Setup

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run

```bash
set TOP10_URL=https://owasp.org/Top10/2025/
python agents/top10_crew/main.py
```

The output file is saved under `data/top10/`.
