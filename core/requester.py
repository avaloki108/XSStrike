import random
import requests
import time
from urllib3.exceptions import ProtocolError
import warnings
from urllib3.exceptions import InsecureRequestWarning

import core.config
from core.utils import converter, getVar
from core.log import setup_logger
from core.request_cache import request_cache  # ADD CACHING SUPPORT

logger = setup_logger(__name__)

# Configure SSL warnings based on verification setting
if not core.config.verify_ssl:
    warnings.filterwarnings("ignore", category=InsecureRequestWarning)
    logger.warning("SSL certificate verification is disabled. This is not recommended for production use.")
else:
    logger.info("SSL certificate verification is enabled.")


def prepare_headers(headers):
    """
    Prepare HTTP headers with appropriate User-Agent.
    
    Args:
        headers: Dictionary of HTTP headers
        
    Returns:
        Dictionary of prepared headers
    """
    user_agents = [
        "Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991",
    ]

    prepared_headers = headers.copy()
    if "User-Agent" not in prepared_headers:
        prepared_headers["User-Agent"] = random.choice(user_agents)
    elif prepared_headers["User-Agent"] == "$":
        prepared_headers["User-Agent"] = random.choice(user_agents)

    return prepared_headers


def prepare_request_data(url, data):
    """
    Prepare request URL and data based on configuration.
    
    Args:
        url: Target URL
        data: Request data/parameters
        
    Returns:
        Tuple of (prepared_url, prepared_data, is_get_request)
    """
    prepared_url = url
    prepared_data = data
    is_get = True

    if getVar("jsonData"):
        prepared_data = converter(data)
        is_get = False
    elif getVar("path"):
        prepared_url = converter(data, url)
        prepared_data = []
        is_get = True

    return prepared_url, prepared_data, is_get


def get_ssl_config():
    """
    Get SSL configuration settings.
    
    Returns:
        SSL verification setting (bool or string path)
    """
    verify = core.config.verify_ssl
    # Use custom certificate path if provided
    if core.config.ssl_cert_path and verify:
        verify = core.config.ssl_cert_path
    return verify


def execute_request(url, data, headers, GET, timeout, verify):
    """
    Execute a single HTTP request.
    
    Args:
        url: Target URL
        data: Request data/parameters
        headers: HTTP headers
        GET: Boolean indicating if this is a GET request
        timeout: Request timeout
        verify: SSL verification setting
        
    Returns:
        requests.Response object
        
    Raises:
        Various requests exceptions
    """
    if GET:
        return requests.get(
            url,
            params=data,
            headers=headers,
            timeout=timeout,
            verify=verify,
            proxies=core.config.proxies,
        )
    elif getVar("jsonData"):
        return requests.post(
            url,
            json=data,
            headers=headers,
            timeout=timeout,
            verify=verify,
            proxies=core.config.proxies,
        )
    else:
        return requests.post(
            url,
            data=data,
            headers=headers,
            timeout=timeout,
            verify=verify,
            proxies=core.config.proxies,
        )


def handle_request_error(e, attempt, max_retries):
    """
    Handle request errors with appropriate retry logic.
    
    Args:
        e: The exception that occurred
        attempt: Current attempt number
        max_retries: Maximum number of retries
        
    Returns:
        Tuple of (should_retry, retry_delay)
    """
    if isinstance(e, ProtocolError):
        if attempt < max_retries:
            retry_delay = 600 + (attempt * 60)  # 10min + additional minutes for each retry
            logger.warning(
                f"WAF is dropping suspicious requests. Retrying in {retry_delay // 60} minutes... (attempt {attempt + 1}/{max_retries})")
            return True, retry_delay
        else:
            logger.error("Max retries reached for WAF protection. Skipping request.")
            return False, 0

    elif isinstance(e, (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
                        requests.exceptions.RequestException)):
        if attempt < max_retries:
            retry_delay = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
            logger.warning(
                f"Network error: {str(e)}. Retrying in {retry_delay} seconds... (attempt {attempt + 1}/{max_retries})")
            return True, retry_delay
        else:
            logger.error(f"Max retries reached. Unable to connect to the target: {str(e)}")
            return False, 0

    else:
        logger.warning(f"Unexpected error: {str(e)}. Unable to connect to the target.")
        return False, 0


def requester(url, data, headers, GET, delay, timeout, max_retries=3):
    """
    Make HTTP request with retry mechanism for handling transient errors.
    
    Args:
        url: Target URL
        data: Request data/parameters
        headers: HTTP headers
        GET: Boolean indicating if this is a GET request
        delay: Base delay between requests
        timeout: Request timeout
        max_retries: Maximum number of retry attempts (default: 3)
    
    Returns:
        requests.Response object or empty Response on failure
    """
    # Sleep for the specified delay
    time.sleep(delay)

    # Prepare request components
    prepared_url, prepared_data, is_get_request = prepare_request_data(url, data)
    if not GET:
        is_get_request = False  # Override if explicitly set to POST

    prepared_headers = prepare_headers(headers)
    verify = get_ssl_config()

    # Check cache first (only for GET requests or when caching is enabled)
    cache_enabled = getVar('cache_enabled', True)  # Default to enabled
    if cache_enabled:
        cached_entry = request_cache.get(
            url=prepared_url,
            method='GET' if is_get_request else 'POST',
            headers=prepared_headers,
            data=prepared_data if not is_get_request else None
        )

        if cached_entry:
            logger.debug(f"Cache HIT for {prepared_url}")

            # Return a mock response object with cached data
            class CachedResponse:
                def __init__(self, entry):
                    self.status_code = entry.response_status
                    self.headers = entry.response_headers
                    self.text = entry.response_content
                    self.content = entry.response_content.encode('utf-8')
                    self.url = entry.url
                    self.elapsed = type('obj', (object,), {'total_seconds': lambda: entry.response_time})()

            return CachedResponse(cached_entry)

    # Log request details
    logger.debug(f"Requester url: {prepared_url}")
    logger.debug(f"Requester headers: {prepared_headers}")

    for attempt in range(max_retries + 1):
        logger.debug(f"Request attempt {attempt + 1}/{max_retries + 1}")

        try:
            start_time = time.time()
            response = execute_request(prepared_url, prepared_data, prepared_headers, is_get_request, timeout, verify)
            response_time = time.time() - start_time

            # Cache the response if caching is enabled
            if cache_enabled and hasattr(response, 'status_code'):
                request_cache.put(
                    url=prepared_url,
                    method='GET' if is_get_request else 'POST',
                    headers=prepared_headers,
                    data=prepared_data if not is_get_request else None,
                    response_status=response.status_code,
                    response_headers=dict(response.headers) if hasattr(response, 'headers') else {},
                    response_content=response.text if hasattr(response, 'text') else '',
                    response_time=response_time
                )
                logger.debug(f"Cache STORE for {prepared_url}")

            return response
        except Exception as e:
            should_retry, retry_delay = handle_request_error(e, attempt, max_retries)
            if should_retry:
                time.sleep(retry_delay)
            else:
                return requests.Response()

    return requests.Response()
