"""
Configuration Manager for OWASP Cheat Sheet Viewer
==================================================

Handles loading configuration from YAML files and environment variables.
"""

import os
import re
import logging
from pathlib import Path
from typing import Any, Optional

import yaml
from dotenv import load_dotenv


class ConfigManager:
    """
    Manages application configuration from YAML files and environment variables.
    
    Supports variable substitution in the format ${VAR_NAME} for environment
    variables within the configuration file.
    """
    
    _instance: Optional["ConfigManager"] = None
    _config: dict[str, Any] = {}
    
    def __new__(cls, config_path: Optional[str] = None) -> "ConfigManager":
        """Singleton pattern to ensure single configuration instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, config_path: Optional[str] = None) -> None:
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to the YAML configuration file.
                        Defaults to 'config.yaml' in the project root.
        """
        if self._initialized:
            return
        
        # Find project root (current working directory)
        cwd = Path.cwd()
        module_root = Path(__file__).parent.parent
        
        # Explicitly load .env file
        env_file = cwd / ".env"
        if not env_file.exists():
            env_file = module_root / ".env"
        
        if env_file.exists():
            print(f"[ConfigManager] Loading .env from: {env_file}")
            load_dotenv(dotenv_path=env_file, override=True)
        else:
            print(f"[ConfigManager] WARNING: No .env file found!")
            print(f"[ConfigManager]   Checked: {cwd / '.env'}")
            print(f"[ConfigManager]   Checked: {module_root / '.env'}")
            load_dotenv()
        
        # Debug: Check if API key was loaded
        api_key = os.environ.get("FIRECRAWL_API_KEY", "")
        if api_key:
            print(f"[ConfigManager] FIRECRAWL_API_KEY loaded: Yes ({api_key[:10]}...)")
        else:
            print("[ConfigManager] ERROR: FIRECRAWL_API_KEY is NOT SET!")
        
        # Determine config path - try multiple locations
        if config_path is None:
            config_path = os.environ.get("OWASP_CONFIG_PATH")
            
        if config_path is None:
            # Try relative to current working directory first
            cwd_config = cwd / "config.yaml"
            if cwd_config.exists():
                config_path = str(cwd_config)
            else:
                # Fall back to relative to this file
                config_path = str(module_root / "config.yaml")
        
        self._config_path = Path(config_path)
        print(f"[ConfigManager] Loading config from: {self._config_path}")
        self._load_config()
        self._initialized = True
        
        # Setup logging based on config
        self._setup_logging()
        
        # Log the loaded firecrawl config for debugging
        fc_config = self.get("firecrawl", {})
        print(f"[ConfigManager] Firecrawl base_url: {fc_config.get('base_url')}")
        print(f"[ConfigManager] Firecrawl api_key set: {bool(fc_config.get('api_key'))}")
        logging.info(f"Firecrawl config loaded - base_url: {fc_config.get('base_url')}, api_key set: {bool(fc_config.get('api_key'))}")
    
    def _load_config(self) -> None:
        """Load configuration from YAML file."""
        if not self._config_path.exists():
            logging.warning(f"Config file not found: {self._config_path}, using defaults")
            self._config = self._get_defaults()
            return
        
        try:
            with open(self._config_path, "r", encoding="utf-8") as f:
                raw_config = yaml.safe_load(f)
            
            # Substitute environment variables
            self._config = self._substitute_env_vars(raw_config)
            
        except yaml.YAMLError as e:
            logging.error(f"Error parsing config file: {e}")
            self._config = self._get_defaults()
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            self._config = self._get_defaults()
    
    def _substitute_env_vars(self, obj: Any) -> Any:
        """
        Recursively substitute ${VAR_NAME} patterns with environment variables.
        
        Args:
            obj: Configuration object (dict, list, or scalar)
            
        Returns:
            Object with environment variables substituted
        """
        if isinstance(obj, dict):
            return {k: self._substitute_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._substitute_env_vars(item) for item in obj]
        elif isinstance(obj, str):
            # Match ${VAR_NAME} pattern
            pattern = r"\$\{([^}]+)\}"
            matches = re.findall(pattern, obj)
            
            result = obj
            for var_name in matches:
                env_value = os.environ.get(var_name, "")
                result = result.replace(f"${{{var_name}}}", env_value)
            
            return result
        return obj
    
    def _get_defaults(self) -> dict[str, Any]:
        """Return default configuration values."""
        return {
            "firecrawl": {
                "api_key": os.environ.get("FIRECRAWL_API_KEY", ""),
                "base_url": "https://api.firecrawl.dev/v1",
                "timeout": 60,
                "max_retries": 3,
                "retry_delay": 2,
            },
            "owasp": {
                "base_url": "https://cheatsheetseries.owasp.org",
                "cheatsheets_index": "https://cheatsheetseries.owasp.org/Glossary.html",
            },
            "cache": {
                "enabled": True,
                "directory": "./cache",
                "expiry_days": 90,
                "index_expiry_days": 7,
                "max_size_mb": 500,
            },
            "app": {
                "title": "OWASP Cheat Sheet Viewer",
                "page_icon": "🛡️",
                "layout": "wide",
                "default_cheatsheet": None,
            },
            "logging": {
                "level": "INFO",
                "file": "./logs/app.log",
                "max_size_mb": 10,
                "backup_count": 5,
            },
            "rate_limit": {
                "requests_per_minute": 30,
                "burst_limit": 5,
            },
        }
    
    def _setup_logging(self) -> None:
        """Configure logging based on configuration settings."""
        log_config = self.get("logging", {})
        log_level = getattr(logging, log_config.get("level", "INFO").upper())
        
        # Create logs directory if needed
        log_file = log_config.get("file", "./logs/app.log")
        log_dir = Path(log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure root logger
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(log_file, encoding="utf-8"),
            ]
        )
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value by key (supports dot notation).
        
        Args:
            key: Configuration key (e.g., "firecrawl.api_key")
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split(".")
        value = self._config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def get_all(self) -> dict[str, Any]:
        """Get the complete configuration dictionary."""
        return self._config.copy()
    
    def reload(self) -> None:
        """Reload configuration from file."""
        self._load_config()
        logging.info("Configuration reloaded")
    
    @property
    def firecrawl_api_key(self) -> str:
        """Get Firecrawl API key."""
        return self.get("firecrawl.api_key", "")
    
    @property
    def cache_directory(self) -> Path:
        """Get cache directory path."""
        return Path(self.get("cache.directory", "./cache"))
    
    @property
    def cache_expiry_days(self) -> int:
        """Get cache expiry in days."""
        return self.get("cache.expiry_days", 90)
    
    @property
    def index_expiry_days(self) -> int:
        """Get index cache expiry in days."""
        return self.get("cache.index_expiry_days", 7)
    
    @property
    def owasp_base_url(self) -> str:
        """Get OWASP base URL."""
        return self.get("owasp.base_url", "https://cheatsheetseries.owasp.org")