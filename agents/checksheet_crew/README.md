# OWASP Checksheet Crew

Generates a structured checksheet JSON from an OWASP cheat sheet URL using CrewAI. The JSON matches the app’s `CheatSheet` model and can be loaded from the Streamlit sidebar (Local Checksheet JSON).

## What it does

- Scrapes a cheat sheet URL
- Extracts sections, risks, mitigations, and examples
- Outputs a JSON file under `data/checksheets/`

## Setup

Install dependencies (root requirements include CrewAI):

```bash
pip install -r requirements.txt
```

## Run

Set the cheat sheet URL and run:

```bash
set CHEATSHEET_URL=https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
python agents/checksheet_crew/main.py
```

On success, the output JSON is saved to `data/checksheets/`.

## Use in the App

1. Start the app.
2. In the sidebar, switch **Data Source** to **Local Checksheet JSON**.
3. Pick the generated file.

## Notes

- If the output is missing fields, the app will still load it with defaults.
- Ensure the `data/checksheets/` folder is accessible from the app’s working directory.
