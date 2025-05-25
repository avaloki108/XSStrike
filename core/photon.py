import re
import time
import hashlib
import concurrent.futures
from urllib.parse import urlparse, urljoin, urldefrag
from collections import defaultdict
from typing import Set, List, Dict, Any

from core.dom import dom
from core.log import setup_logger
from core.utils import getUrl, getParams
from core.requester import requester
from core.zetanize import zetanize
from core.plugin_manager import plugin_manager, PluginHook

logger = setup_logger(__name__)


class CrawlerOptimizer:
    """Optimizes crawler performance with caching and deduplication."""

    def __init__(self):
        self.response_cache = {}  # Cache responses to avoid duplicate requests
        self.link_signatures = set()  # Track unique link patterns
        self.domain_stats = defaultdict(int)  # Track requests per domain
        self.blocked_extensions = {
            '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.bmp',
            '.xls', '.xlsx', '.doc', '.docx', '.ppt', '.pptx', '.zip', '.rar',
            '.tar', '.gz', '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.css', '.js'
        }

    def should_crawl_url(self, url: str, main_url: str) -> bool:
        """Determine if URL should be crawled based on optimization rules."""
        # Check for blocked file extensions
        parsed = urlparse(url)
        path_lower = parsed.path.lower()

        if any(path_lower.endswith(ext) for ext in self.blocked_extensions):
            return False

        # Check for common non-content patterns
        non_content_patterns = [
            r'/api/', r'/admin/', r'/wp-admin/', r'/wp-content/',
            r'/assets/', r'/static/', r'/public/', r'/uploads/',
            r'/images/', r'/img/', r'/css/', r'/js/', r'/fonts/'
        ]

        if any(re.search(pattern, path_lower) for pattern in non_content_patterns):
            return False

        # Rate limiting per domain
        domain = parsed.netloc
        if self.domain_stats[domain] > 100:  # Limit requests per domain
            return False

        return True

    def normalize_url(self, url: str) -> str:
        """Normalize URL for better deduplication."""
        # Remove fragment
        url, _ = urldefrag(url)

        # Remove common tracking parameters
        tracking_params = {
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
            'gclid', 'fbclid', 'mc_cid', 'mc_eid', '_ga', '_gid'
        }

        parsed = urlparse(url)
        if parsed.query:
            params = []
            for param in parsed.query.split('&'):
                if '=' in param:
                    key = param.split('=')[0]
                    if key not in tracking_params:
                        params.append(param)

            query = '&'.join(params) if params else ''
            url = url.split('?')[0]
            if query:
                url += '?' + query

        return url

    def get_link_signature(self, url: str) -> str:
        """Generate signature for similar URLs to avoid duplicate patterns."""
        parsed = urlparse(url)
        path = parsed.path

        # Replace numeric patterns with placeholders
        path = re.sub(r'/\d+/', '/ID/', path)
        path = re.sub(r'/\d+$', '/ID', path)
        path = re.sub(r'=\d+', '=ID', parsed.query or '')

        signature = f"{parsed.netloc}{path}"
        return hashlib.md5(signature.encode()).hexdigest()


def photon(seedUrl, headers, level, threadCount, delay, timeout, skipDOM):
    """Optimized web crawler with performance improvements."""
    forms = []  # web forms
    processed = set()  # urls that have been crawled
    storage = set()  # urls that belong to the target i.e. in-scope
    schema = urlparse(seedUrl).scheme  # extract the scheme e.g. http or https
    host = urlparse(seedUrl).netloc  # extract the host e.g. example.com
    main_url = schema + "://" + host  # join scheme and host to make the root url
    storage.add(seedUrl)  # add the url to storage
    checkedDOMs = []

    # Initialize optimizer
    optimizer = CrawlerOptimizer()

    # Performance metrics
    start_time = time.time()
    request_count = 0
    cache_hits = 0

    # Execute pre-crawl plugins
    pre_crawl_context = {
        "target_url": seedUrl,
        "headers": headers,
        "level": level,
        "thread_count": threadCount
    }
    plugin_manager.execute_hook(PluginHook.PRE_CRAWL, pre_crawl_context)

    def extract_links_optimized(response: str, base_url: str) -> List[str]:
        """Optimized link extraction with better patterns."""
        links = set()

        # Multiple patterns for different link types
        patterns = [
            r'<[aA][^>]*href=["\']\s*([^"\'>\s]+)\s*["\']',  # Standard href
            r'<form[^>]*action=["\']\s*([^"\'>\s]+)\s*["\']',  # Form actions
            r'<iframe[^>]*src=["\']\s*([^"\'>\s]+)\s*["\']',  # Iframes
            r'window\.location\s*=\s*["\']([^"\']+)["\']',  # JS redirects
            r'location\.href\s*=\s*["\']([^"\']+)["\']'  # JS location changes
        ]

        for pattern in patterns:
            matches = re.findall(pattern, response, re.IGNORECASE)
            for match in matches:
                if match.strip():
                    links.add(match.strip())

        # Process and normalize links
        processed_links = []
        for link in links:
            try:
                # Handle different URL formats
                if link.startswith('http'):
                    if link.startswith(main_url):
                        full_url = link
                    else:
                        continue  # External link
                elif link.startswith('//'):
                    if link.split('/')[2].startswith(host):
                        full_url = schema + ':' + link
                    else:
                        continue  # External link
                elif link.startswith('/'):
                    full_url = main_url + link
                elif link.startswith('?') or link.startswith('#'):
                    full_url = base_url + link
                else:
                    full_url = urljoin(base_url, link)

                # Normalize and check if should crawl
                normalized_url = optimizer.normalize_url(full_url)
                if optimizer.should_crawl_url(normalized_url, main_url):
                    processed_links.append(normalized_url)

            except Exception as e:
                logger.debug(f"Error processing link {link}: {e}")
                continue

        return processed_links

    def rec(target):
        """Optimized crawler function with caching and deduplication."""
        nonlocal request_count, cache_hits

        processed.add(target)
        request_count += 1

        # Check link signature for deduplication
        signature = optimizer.get_link_signature(target)
        if signature in optimizer.link_signatures:
            cache_hits += 1
            return
        optimizer.link_signatures.add(signature)

        # Update domain stats
        domain = urlparse(target).netloc
        optimizer.domain_stats[domain] += 1

        printableTarget = "/".join(target.split("/")[3:])
        if len(printableTarget) > 40:
            printableTarget = printableTarget[-40:]
        else:
            printableTarget = printableTarget + (" " * (40 - len(printableTarget)))
        logger.run(f"Parsing {printableTarget} [{request_count}]\r")

        url = getUrl(target, True)
        params = getParams(target, "", True)

        # Handle GET parameters
        if "=" in target:  # if there's a = in the url, there should be GET parameters
            inps = []
            for name, value in params.items():
                inps.append({"name": name, "value": value})
            forms.append({0: {"action": url, "method": "get", "inputs": inps}})

        # Check response cache
        cache_key = f"{url}:{str(sorted(params.items()))}"
        if cache_key in optimizer.response_cache:
            response_text = optimizer.response_cache[cache_key]
            cache_hits += 1
        else:
            try:
                response = requester(url, params, headers, True, delay, timeout)
                response_text = response.text
                optimizer.response_cache[cache_key] = response_text

                # Limit cache size
                if len(optimizer.response_cache) > 1000:
                    # Remove oldest entries (simple FIFO)
                    keys_to_remove = list(optimizer.response_cache.keys())[:100]
                    for key in keys_to_remove:
                        del optimizer.response_cache[key]

            except Exception as e:
                logger.debug(f"Request failed for {url}: {e}")
                return

        # Execute post-request plugins
        post_request_context = {
            "url": url,
            "response": response_text,
            "params": params,
            "headers": headers
        }
        plugin_manager.execute_hook(PluginHook.POST_REQUEST, post_request_context)

        # DOM analysis (if not skipped)
        if not skipDOM:
            highlighted = dom(response_text)
            if highlighted:
                clean_highlighted = "".join(
                    [re.sub(r"^\d+\s+", "", line) for line in highlighted]
                )
                if clean_highlighted not in checkedDOMs:
                    checkedDOMs.append(clean_highlighted)
                    logger.good(f"Potentially vulnerable objects found at {url}")
                    logger.red_line(level="good")
                    for line in highlighted:
                        logger.no_format(line, level="good")
                    logger.red_line(level="good")

        # Form parsing
        try:
            forms.append(zetanize(response_text))
        except Exception as e:
            logger.debug(f"Form parsing failed for {url}: {e}")

        # Extract links with optimization
        new_links = extract_links_optimized(response_text, url)
        storage.update(new_links)

    try:
        for level_num in range(level):
            urls = storage - processed  # urls to crawl = all urls - urls that have been crawled

            if not urls:
                logger.info(f"No more URLs to crawl at level {level_num + 1}")
                break

            logger.info(f"Crawling level {level_num + 1} with {len(urls)} URLs")

            # Improved thread pool management
            max_workers = min(threadCount, len(urls), 20)  # Cap max workers

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all tasks
                future_to_url = {executor.submit(rec, url): url for url in urls}

                # Process completed tasks with timeout
                try:
                    for future in concurrent.futures.as_completed(future_to_url, timeout=300):
                        url = future_to_url[future]
                        try:
                            future.result(timeout=30)
                        except concurrent.futures.TimeoutError:
                            logger.warning(f"Timeout processing {url}")
                        except Exception as e:
                            logger.debug(f"Error processing {url}: {e}")
                except concurrent.futures.TimeoutError:
                    logger.warning("Overall crawl timeout reached")

    except KeyboardInterrupt:
        # Execute post-crawl plugins even on interruption
        post_crawl_context = {
            "processed_urls": list(processed),
            "interrupted": True,
            "performance_stats": {
                "requests": request_count,
                "cache_hits": cache_hits,
                "duration": time.time() - start_time
            }
        }
        plugin_manager.execute_hook(PluginHook.POST_CRAWL, post_crawl_context)
        return [forms, processed]

    # Performance logging
    duration = time.time() - start_time
    cache_hit_rate = (cache_hits / request_count * 100) if request_count > 0 else 0

    logger.info(f"Crawl completed in {duration:.2f}s")
    logger.info(f"Processed {request_count} requests with {cache_hit_rate:.1f}% cache hit rate")
    logger.info(f"Found {len(forms)} forms across {len(processed)} pages")

    # Execute post-crawl plugins
    post_crawl_context = {
        "processed_urls": list(processed),
        "interrupted": False,
        "performance_stats": {
            "requests": request_count,
            "cache_hits": cache_hits,
            "duration": duration,
            "cache_hit_rate": cache_hit_rate
        }
    }
    plugin_manager.execute_hook(PluginHook.POST_CRAWL, post_crawl_context)

    return [forms, processed]
