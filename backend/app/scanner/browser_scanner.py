from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from app.security.network_policy import egress_proxy_url
from app.security.url_validator import URLValidationError, validate_and_normalize_url

class BrowserScanError(Exception):
    pass

@dataclass
class BrowserConfig:
    navigation_timeout_ms: int = 12_000
    max_requests: int = 120
    max_external_hosts: int = 40
    max_content_chars: int = 200_000
    max_screenshot_bytes: int = 600_000

def _host(url: str) -> str:
    return (urlparse(url).hostname or "").lower().rstrip(".")

def _is_http(url: str) -> bool:
    return urlparse(url).scheme.lower() in {"http", "https"}

def _extract_forms(page) -> list[dict[str, Any]]:
    return page.locator("form").evaluate_all(
        """
        forms => forms.slice(0, 30).map(form => ({
          action: form.action || null,
          method: (form.method || 'get').toUpperCase(),
          inputs: Array.from(form.querySelectorAll('input')).slice(0, 30).map(i => ({
            type: i.type || 'text', name: i.name || null, autocomplete: i.autocomplete || null
          }))
        }))
        """
    )

def _extract_content(page, max_chars: int) -> dict[str, Any]:
    title = page.title()[:500]
    locator = page.locator("body")
    text = locator.inner_text(timeout=3_000) if locator.count() else ""
    text = re.sub(r"\s+", " ", text).strip()
    return {"title": title, "text": text[:max_chars], "text_truncated": len(text) > max_chars}

def scan_page(url: str, config: BrowserConfig | None = None) -> dict[str, Any]:
    config = config or BrowserConfig()
    normalized = validate_and_normalize_url(url)
    request_count = 0
    blocked_requests: list[dict[str, str]] = []
    external_hosts: set[str] = set()

    with sync_playwright() as pw:
        proxy = {"server": egress_proxy_url()} if egress_proxy_url() else None
        browser = pw.chromium.launch(
            headless=True,
            proxy=proxy,
            args=[
                "--disable-dev-shm-usage", "--disable-gpu", "--disable-background-networking",
                "--disable-default-apps", "--no-first-run", "--disable-sync", "--no-pings",
                "--disable-features=Translate,MediaRouter", "--disable-extensions",
            ],
        )
        try:
            context = browser.new_context(
                java_script_enabled=True,
                ignore_https_errors=False,
                service_workers="block",
                accept_downloads=False,
                viewport={"width": 1365, "height": 900},
                locale="en-US",
            )
            page = context.new_page()
            page.set_default_timeout(4_000)

            def handle_route(route):
                nonlocal request_count
                request_count += 1
                target = route.request.url
                if request_count > config.max_requests:
                    blocked_requests.append({"url": target[:2048], "reason": "request_limit"})
                    route.abort(); return
                if not _is_http(target):
                    blocked_requests.append({"url": target[:2048], "reason": "non_http_scheme"})
                    route.abort(); return
                try:
                    # Re-resolve and validate every browser URL immediately before navigation/request.
                    validate_and_normalize_url(target)
                except URLValidationError as exc:
                    blocked_requests.append({"url": target[:2048], "reason": f"ssrf_block:{exc}"})
                    route.abort(); return
                host = _host(target)
                if host and host != _host(normalized):
                    external_hosts.add(host)
                    if len(external_hosts) > config.max_external_hosts:
                        blocked_requests.append({"url": target[:2048], "reason": "external_host_limit"})
                        route.abort(); return
                if route.request.resource_type in {"media", "font", "websocket"}:
                    blocked_requests.append({"url": target[:2048], "reason": "resource_type_limit"})
                    route.abort(); return
                route.continue_()

            page.route("**/*", handle_route)
            response = page.goto(normalized, wait_until="domcontentloaded", timeout=config.navigation_timeout_ms)
            page.wait_for_timeout(800)
            final_url = validate_and_normalize_url(page.url())
            content = _extract_content(page, config.max_content_chars)
            forms = _extract_forms(page)
            links = page.locator("a[href]").evaluate_all("els => els.slice(0, 100).map(a => a.href).filter(Boolean)")
            external_links = sorted({u for u in links if _host(u) and _host(u) != _host(final_url)})[:100]
            screenshot = page.screenshot(type="png", full_page=False)
            screenshot_available = len(screenshot) <= config.max_screenshot_bytes
            screenshot_b64 = base64.b64encode(screenshot).decode("ascii") if screenshot_available else None
            return {
                "status": "COMPLETED", "initial_url": normalized, "final_url": final_url,
                "http_status": response.status if response else None, "page_title": content["title"],
                "content": content, "forms": forms, "form_count": len(forms),
                "external_hosts": sorted(external_hosts), "external_host_count": len(external_hosts),
                "external_links": external_links, "external_link_count": len(external_links),
                "request_count": request_count, "blocked_requests": blocked_requests[:50],
                "screenshot_png_base64": screenshot_b64, "screenshot_available": screenshot_available,
                "browser": "chromium-playwright", "egress_proxy": bool(egress_proxy_url()),
            }
        finally:
            browser.close()
    
