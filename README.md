# OWASP Top 10 LLM Security Risks 2025 - Streamlit App

A comprehensive Streamlit application showcasing the OWASP Top 10 security risks for Large Language Model (LLM) applications.

## 🛡️ Features

- **Overview Dashboard**: Quick summary of all 10 LLM security risks with severity metrics
- **All Risks View**: Expandable list of all risks with key impacts and mitigations
- **Risk Details**: Deep-dive into each risk with tabs for types, impacts, mitigations, and attack scenarios
- **Risk Matrix**: Visual comparison and assessment of all risks
- **Resources**: Links to official OWASP documentation and related frameworks

## 📋 OWASP Top 10 LLM Risks Covered

1. **LLM01: Prompt Injection** - Manipulating LLM behavior through malicious prompts
2. **LLM02: Sensitive Information Disclosure** - Exposure of PII, credentials, and confidential data
3. **LLM03: Supply Chain Vulnerabilities** - Risks from third-party models, data, and dependencies
4. **LLM04: Data and Model Poisoning** - Manipulation of training data to introduce backdoors
5. **LLM05: Improper Output Handling** - Insufficient validation of LLM outputs
6. **LLM06: Excessive Agency** - Over-permissioned LLM actions without proper controls
7. **LLM07: System Prompt Leakage** - Exposure of system prompts and instructions
8. **LLM08: Vector and Embedding Weaknesses** - Vulnerabilities in RAG and vector databases
9. **LLM09: Misinformation** - Hallucinations and false information generation
10. **LLM10: Unbounded Consumption** - Resource exhaustion and denial of service

## 🚀 Installation & Running

### Prerequisites
- Python 3.8+
- pip

### Setup

1. Clone or download this repository

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
streamlit run app.py
```

4. Open your browser to `http://localhost:8501`

## 📸 Screenshots

The app includes:
- Interactive sidebar navigation
- Severity-coded risk cards
- Detailed tabbed views for each risk
- Data visualization for risk comparison
- External links to official resources

## 📚 Data Sources

- [OWASP GenAI Security Project](https://genai.owasp.org/)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [GitHub Repository](https://github.com/OWASP/www-project-top-10-for-large-language-model-applications)

## 📄 License

This project is for educational purposes. The OWASP content is licensed under Creative Commons Attribution-ShareAlike v4.0.

## 🤝 Contributing

Feel free to submit issues and enhancement requests!
