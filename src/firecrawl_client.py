"""
Firecrawl Client for OWASP Cheat Sheet Viewer
=============================================

Handles web scraping via the Firecrawl API with rate limiting and retries.
"""

import logging
import time
from typing import Any, Optional

import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from .config_manager import ConfigManager
from .cache_manager import CacheManager


logger = logging.getLogger(__name__)


class FirecrawlError(Exception):
    """Base exception for Firecrawl-related errors."""
    pass


class FirecrawlRateLimitError(FirecrawlError):
    """Rate limit exceeded error."""
    pass


class FirecrawlClient:
    """
    Client for the Firecrawl Web Data API.
    
    Provides methods for scraping web content with automatic retries,
    rate limiting, and caching integration.
    """
    
    def __init__(
        self,
        config: Optional[ConfigManager] = None,
        cache: Optional[CacheManager] = None
    ) -> None:
        """
        Initialize the Firecrawl client.
        
        Args:
            config: Configuration manager instance
            cache: Cache manager instance
        """
        self._config = config or ConfigManager()
        self._cache = cache or CacheManager(self._config)
        
        self._api_key = self._config.firecrawl_api_key
        self._base_url = self._config.get("firecrawl.base_url", "https://api.firecrawl.dev/v1")
        self._timeout = self._config.get("firecrawl.timeout", 60)
        self._max_retries = self._config.get("firecrawl.max_retries", 3)
        
        # Rate limiting
        self._requests_per_minute = self._config.get("rate_limit.requests_per_minute", 30)
        self._last_request_time = 0.0
        self._min_request_interval = 60.0 / self._requests_per_minute
        
        # Validate API key
        if not self._api_key:
            logger.warning("Firecrawl API key not configured! Set FIRECRAWL_API_KEY environment variable.")
        else:
            logger.info(f"Firecrawl client initialized with base_url: {self._base_url}")
            logger.info(f"Firecrawl API key: {self._api_key[:10]}...")
        
        # HTTP client
        self._client = httpx.Client(
            timeout=self._timeout,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            }
        )
    
    def _wait_for_rate_limit(self) -> None:
        """Enforce rate limiting between requests."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_request_interval:
            sleep_time = self._min_request_interval - elapsed
            time.sleep(sleep_time)
        self._last_request_time = time.time()
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.HTTPError, FirecrawlRateLimitError)),
    )
    def _make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs: Any
    ) -> dict[str, Any]:
        """
        Make an API request with retry logic.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (e.g., "scrape", "crawl")
            **kwargs: Additional request parameters
            
        Returns:
            API response as dictionary
            
        Raises:
            FirecrawlError: On API errors
            FirecrawlRateLimitError: On rate limit exceeded
        """
        self._wait_for_rate_limit()
        
        # FIXED: Proper URL construction - ensure /v1/ is included
        base = self._base_url.rstrip("/")
        path = endpoint.lstrip("/")
        url = f"{base}/{path}"
        
        logger.debug(f"Firecrawl request: {method} {url}")
        
        try:
            response = self._client.request(method, url, **kwargs)
            
            if response.status_code == 429:
                raise FirecrawlRateLimitError("Rate limit exceeded")
            
            response.raise_for_status()
            return response.json()
            
        except httpx.HTTPStatusError as e:
            error_text = e.response.text[:500] if e.response.text else "No response body"
            logger.error(f"Firecrawl API error: {e.response.status_code} - {error_text}")
            raise FirecrawlError(f"API error: {e.response.status_code}") from e
        except httpx.RequestError as e:
            logger.error(f"Firecrawl request error: {e}")
            raise FirecrawlError(f"Request error: {e}") from e
    
    def scrape_url(
        self,
        url: str,
        formats: Optional[list[str]] = None,
        only_main_content: bool = True,
        include_tags: Optional[list[str]] = None,
        exclude_tags: Optional[list[str]] = None,
        use_cache: bool = True,
        cache_expiry_days: Optional[int] = None,
    ) -> dict[str, Any]:
        """
        Scrape a single URL using Firecrawl.
        
        Args:
            url: URL to scrape
            formats: Output formats (e.g., ["markdown", "html"])
            only_main_content: Extract only main content
            include_tags: HTML tags to include
            exclude_tags: HTML tags to exclude
            use_cache: Whether to use caching
            cache_expiry_days: Custom cache expiry
            
        Returns:
            Scraped content with metadata
        """
        # Check cache first
        if use_cache:
            cached = self._cache.get(url)
            if cached:
                logger.info(f"Using cached content for: {url}")
                return cached
        
        logger.info(f"Scraping URL: {url}")
        logger.debug(f"Using Firecrawl base_url: {self._base_url}")
        
        payload = {
            "url": url,
            "formats": formats or ["markdown", "html"],
            "onlyMainContent": only_main_content,
        }
        
        if include_tags:
            payload["includeTags"] = include_tags
        if exclude_tags:
            payload["excludeTags"] = exclude_tags
        
        try:
            response = self._make_request("POST", "scrape", json=payload)
            
            result = {
                "url": url,
                "success": response.get("success", False),
                "markdown": response.get("data", {}).get("markdown", ""),
                "html": response.get("data", {}).get("html", ""),
                "metadata": response.get("data", {}).get("metadata", {}),
                "scraped_at": time.time(),
            }
            
            # Cache the result
            if use_cache and result["success"]:
                self._cache.set(url, result, expiry_days=cache_expiry_days)
            
            return result
            
        except FirecrawlError as e:
            logger.error(f"Failed to scrape {url}: {e}")
            return {
                "url": url,
                "success": False,
                "error": str(e),
                "markdown": "",
                "html": "",
                "metadata": {},
            }
    
    def crawl_site(
        self,
        start_url: str,
        max_pages: int = 50,
        include_paths: Optional[list[str]] = None,
        exclude_paths: Optional[list[str]] = None,
        use_cache: bool = True,
    ) -> dict[str, Any]:
        """
        Crawl a website starting from a URL.
        
        Args:
            start_url: Starting URL for crawl
            max_pages: Maximum pages to crawl
            include_paths: URL path patterns to include
            exclude_paths: URL path patterns to exclude
            use_cache: Whether to use caching
            
        Returns:
            Crawl results with all pages
        """
        cache_key = f"crawl:{start_url}:{max_pages}"
        
        if use_cache:
            cached = self._cache.get(cache_key)
            if cached:
                logger.info(f"Using cached crawl for: {start_url}")
                return cached
        
        logger.info(f"Starting crawl from: {start_url}")
        
        payload = {
            "url": start_url,
            "limit": max_pages,
            "scrapeOptions": {
                "formats": ["markdown"],
                "onlyMainContent": True,
            }
        }
        
        if include_paths:
            payload["includePaths"] = include_paths
        if exclude_paths:
            payload["excludePaths"] = exclude_paths
        
        try:
            # Start crawl job
            response = self._make_request("POST", "crawl", json=payload)
            job_id = response.get("id")
            
            if not job_id:
                raise FirecrawlError("No job ID returned")
            
            # Poll for completion
            result = self._wait_for_crawl_completion(job_id)
            
            if use_cache and result.get("success"):
                self._cache.set(cache_key, result, is_index=True)
            
            return result
            
        except FirecrawlError as e:
            logger.error(f"Crawl failed for {start_url}: {e}")
            return {"success": False, "error": str(e), "pages": []}
    
    def _wait_for_crawl_completion(
        self,
        job_id: str,
        max_wait_seconds: int = 300,
        poll_interval: int = 5,
    ) -> dict[str, Any]:
        """
        Wait for a crawl job to complete.
        
        Args:
            job_id: Crawl job ID
            max_wait_seconds: Maximum time to wait
            poll_interval: Seconds between status checks
            
        Returns:
            Crawl results
        """
        start_time = time.time()
        
        while time.time() - start_time < max_wait_seconds:
            try:
                response = self._make_request("GET", f"crawl/{job_id}")
                status = response.get("status", "unknown")
                
                if status == "completed":
                    return {
                        "success": True,
                        "job_id": job_id,
                        "pages": response.get("data", []),
                        "total_pages": response.get("total", 0),
                    }
                elif status == "failed":
                    return {
                        "success": False,
                        "error": response.get("error", "Crawl failed"),
                        "pages": [],
                    }
                
                time.sleep(poll_interval)
                
            except FirecrawlError as e:
                logger.warning(f"Error checking crawl status: {e}")
                time.sleep(poll_interval)
        
        return {
            "success": False,
            "error": "Crawl timeout exceeded",
            "pages": [],
        }
    
    def extract_links(
        self,
        url: str,
        pattern: Optional[str] = None,
        use_cache: bool = True,
    ) -> list[dict[str, str]]:
        """
        Extract links from a page.
        
        Args:
            url: URL to extract links from
            pattern: Optional regex pattern to filter links
            use_cache: Whether to use caching
            
        Returns:
            List of link dictionaries with url and text
        """
        cache_key = f"links:{url}:{pattern or 'all'}"
        
        if use_cache:
            cached = self._cache.get(cache_key)
            if cached:
                return cached
        
        # Scrape the page
        scraped = self.scrape_url(
            url,
            formats=["links"],
            only_main_content=False,
            use_cache=use_cache,
        )
        
        links = scraped.get("metadata", {}).get("links", [])
        
        # Filter by pattern if provided
        if pattern:
            import re
            regex = re.compile(pattern)
            links = [link for link in links if regex.search(link.get("url", ""))]
        
        if use_cache:
            self._cache.set(cache_key, links, is_index=True)
        
        return links
    
    def map_site(self, url: str, use_cache: bool = True) -> list[str]:
        """
        Get a sitemap of all URLs on a website.
        
        Args:
            url: Base URL of the site
            use_cache: Whether to use caching
            
        Returns:
            List of all URLs found
        """
        cache_key = f"sitemap:{url}"
        
        if use_cache:
            cached = self._cache.get(cache_key)
            if cached:
                return cached
        
        logger.info(f"Mapping site: {url}")
        
        try:
            response = self._make_request("POST", "map", json={"url": url})
            urls = response.get("links", [])
            
            if use_cache and urls:
                self._cache.set(cache_key, urls, is_index=True)
            
            return urls
            
        except FirecrawlError as e:
            logger.error(f"Site mapping failed: {e}")
            return []
    
    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()
    
    def __enter__(self) -> "FirecrawlClient":
        return self
    
    def __exit__(self, *args: Any) -> None:
        self.close()
