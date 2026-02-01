# OWASP Cheat Sheet Viewer

A dynamic Streamlit application for browsing and exploring OWASP Cheat Sheets with intelligent caching and web scraping capabilities.

## 🛡️ Features

- **Dynamic Cheat Sheet Selection**: Browse all available OWASP cheat sheets via a dropdown selector
- **Category Filtering**: Filter cheat sheets by security category
- **Overview Dashboard**: Quick summary with severity metrics
- **All Risks View**: Expandable list of security topics with impacts and mitigations
- **Risk Details**: Deep-dive into each security topic with tabs for types, impacts, mitigations, and examples
- **Attack Examples**: Educational demonstrations of attack vectors
- **Risk Matrix**: Visual comparison and assessment of security topics
- **Resources**: Links to official documentation and related frameworks

## 🚀 Installation & Setup

### Prerequisites

- Python 3.10+
- Firecrawl API key (get one at [firecrawl.dev](https://firecrawl.dev))

### Step 1: Clone/Download

```bash
# Navigate to your project directory
cd owasp_cheatsheet_viewer
```

### Step 2: Create Virtual Environment (Recommended)

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure API Key

Create a `.env` file in the project root:

```bash
# .env
FIRECRAWL_API_KEY=your_api_key_here
```

Or set it as an environment variable:

```bash
export FIRECRAWL_API_KEY=your_api_key_here
```

### Step 5: Run the Application

```bash
streamlit run app.py
```

Open your browser to `http://localhost:8501`

## 📁 Project Structure

```
owasp_cheatsheet_viewer/
├── config.yaml          # Application configuration
├── requirements.txt     # Python dependencies
├── app.py              # Main Streamlit application
├── .env                # Environment variables (create this)
├── src/
│   ├── __init__.py
│   ├── config_manager.py    # Configuration loading
│   ├── cache_manager.py     # Disk caching with expiration
│   ├── firecrawl_client.py  # Firecrawl API client
│   ├── cheatsheet_parser.py # Content parsing and extraction
│   └── models.py            # Pydantic data models
├── cache/               # Cached data (auto-created)
└── logs/                # Application logs (auto-created)
```

## ⚙️ Configuration

Edit `config.yaml` to customize behavior:

```yaml
# Firecrawl API settings
firecrawl:
  api_key: "${FIRECRAWL_API_KEY}"  # Uses environment variable
  timeout: 60

# Cache settings
cache:
  enabled: true
  directory: "./cache"
  expiry_days: 90        # Cheat sheet content cache
  index_expiry_days: 7   # Index refresh frequency
  max_size_mb: 500

# Rate limiting (respect OWASP servers)
rate_limit:
  requests_per_minute: 30
```

### Configuration Options

| Section | Option | Default | Description |
|---------|--------|---------|-------------|
| `firecrawl.api_key` | `${FIRECRAWL_API_KEY}` | - | API key (from env var) |
| `firecrawl.timeout` | `60` | - | Request timeout in seconds |
| `firecrawl.max_retries` | `3` | - | Retry attempts on failure |
| `cache.enabled` | `true` | - | Enable/disable caching |
| `cache.expiry_days` | `90` | - | Content cache duration |
| `cache.index_expiry_days` | `7` | - | Index refresh frequency |
| `cache.max_size_mb` | `500` | - | Maximum cache size |
| `rate_limit.requests_per_minute` | `30` | - | API rate limiting |

## 🔄 Caching System

The application implements a sophisticated caching system:

1. **Disk-based Cache**: All scraped content is stored locally in JSON format
2. **Automatic Expiration**: Content expires after 90 days (configurable)
3. **Index Refresh**: The cheat sheet index refreshes every 7 days
4. **Size Management**: Automatic cleanup when cache exceeds limits
5. **Manual Control**: Clear cache button in the sidebar

### Cache Behavior

```
First Request:
1. Check disk cache → Miss
2. Fetch from Firecrawl API
3. Parse and structure content
4. Store in disk cache
5. Return to user

Subsequent Requests (within expiry):
1. Check disk cache → Hit
2. Return cached content immediately

After Expiry:
1. Check disk cache → Expired
2. Fetch fresh content
3. Update cache
```

## 📊 Data Flow

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   User Selects  │────▶│  Check Cache    │────▶│  Cache Hit?     │
│   Cheat Sheet   │     │  (Disk Cache)   │     │                 │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                              ┌───────────────────────────┼───────────────────────────┐
                              │ Yes                       │ No                        │
                              ▼                           ▼                           │
                    ┌─────────────────┐         ┌─────────────────┐                  │
                    │  Return Cached  │         │  Firecrawl API  │                  │
                    │  Content        │         │  Scrape URL     │                  │
                    └─────────────────┘         └────────┬────────┘                  │
                                                         │                           │
                                                         ▼                           │
                                               ┌─────────────────┐                   │
                                               │  Parse Content  │                   │
                                               │  (Parser)       │                   │
                                               └────────┬────────┘                   │
                                                         │                           │
                                                         ▼                           │
                                               ┌─────────────────┐                   │
                                               │  Store in Cache │                   │
                                               │  (90 days TTL)  │                   │
                                               └────────┬────────┘                   │
                                                         │                           │
                              ┌───────────────────────────┘                           │
                              ▼                                                       │
                    ┌─────────────────┐                                              │
                    │  Render UI      │◀─────────────────────────────────────────────┘
                    │  Components     │
                    └─────────────────┘
```

## 🔧 Customization

### Adding New Categories

Edit the `CATEGORY_ICONS` dictionary in `src/cheatsheet_parser.py`:

```python
CATEGORY_ICONS = {
    "authentication": "🔐",
    "your_category": "🆕",  # Add your category
    # ...
}
```

### Modifying Severity Keywords

Edit `SEVERITY_KEYWORDS` in `src/cheatsheet_parser.py`:

```python
SEVERITY_KEYWORDS = {
    "critical": ["critical", "severe", "your_keyword"],
    # ...
}
```

### Custom Styling

Modify the CSS in `app.py` within the `st.markdown()` block:

```python
st.markdown("""
<style>
    .main-header {
        /* Your custom styles */
    }
</style>
""", unsafe_allow_html=True)
```

## 🐛 Troubleshooting

### Common Issues

**1. "Firecrawl API key not configured"**
```bash
# Solution: Set the environment variable
export FIRECRAWL_API_KEY=your_key_here
```

**2. "No cheat sheets found"**
- Check internet connectivity
- Verify API key is valid
- Check if OWASP site is accessible
- Clear cache and retry

**3. "Cache errors"**
```bash
# Solution: Clear the cache directory
rm -rf cache/*
```

**4. "Rate limit exceeded"**
- Wait a few minutes and retry
- Reduce `requests_per_minute` in config

### Debug Mode

Enable debug logging in `config.yaml`:

```yaml
logging:
  level: "DEBUG"
```

## 📝 API Usage Notes

### Firecrawl API

The application uses Firecrawl for web scraping with these endpoints:

- `POST /scrape` - Scrape individual pages
- `GET /crawl/{id}` - Check crawl job status
- `POST /map` - Get site URLs

Rate limits are respected automatically. The default configuration allows 30 requests per minute.

### Caching Strategy

To minimize API usage:

1. Index is cached for 7 days
2. Individual cheat sheets cached for 90 days
3. Failed requests are not cached
4. Users can force refresh via sidebar button

## 📄 License

This project is for educational purposes. OWASP content is licensed under Creative Commons Attribution-ShareAlike v4.0.

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📚 References

- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [Firecrawl Documentation](https://docs.firecrawl.dev/)
- [Streamlit Documentation](https://docs.streamlit.io/)