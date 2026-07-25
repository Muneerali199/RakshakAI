"""Notion API client with OAuth support."""
from __future__ import annotations
import os
import time
import logging
import hashlib
import hmac
from typing import Optional
from urllib.parse import urlencode

import requests
from dotenv import load_dotenv
from pathlib import Path as _Path

load_dotenv(_Path(__file__).resolve().parent.parent.parent.parent / ".env")

from v2.integrations.notion.types import NotionConfig

log = logging.getLogger("rakshakai.notion")


class NotionClient:
    """Notion API client with automatic token management."""

    def __init__(self, config: Optional[NotionConfig] = None):
        self.config = config or NotionConfig(
            api_key=os.environ.get("NOTION_API_KEY", ""),
            integration_token=os.environ.get("NOTION_INTEGRATION_TOKEN", ""),
            database_id=os.environ.get("NOTION_DATABASE_ID", ""),
            dashboard_page_id=os.environ.get("NOTION_DASHBOARD_PAGE_ID", ""),
            oauth_client_id=os.environ.get("NOTION_OAUTH_CLIENT_ID", ""),
            oauth_client_secret=os.environ.get("NOTION_OAUTH_CLIENT_SECRET", ""),
        )
        self._token = self.config.integration_token or self.config.api_key
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self._token}",
            "Notion-Version": self.config.api_version,
            "Content-Type": "application/json",
        })
        self._rate_limit_remaining = 3
        self._rate_limit_reset = 0

    @property
    def is_configured(self) -> bool:
        return bool(self._token)

    @property
    def headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._token}",
            "Notion-Version": self.config.api_version,
            "Content-Type": "application/json",
        }

    def _request(self, method: str, endpoint: str, **kwargs) -> dict:
        url = f"{self.config.base_url}{endpoint}"
        if self._rate_limit_remaining <= 1:
            wait = max(0, self._rate_limit_reset - time.time())
            if wait > 0:
                time.sleep(wait)

        resp = self._session.request(method, url, **kwargs)
        self._rate_limit_remaining = int(resp.headers.get("X-Rate-Limit-Remaining", 3))
        reset = resp.headers.get("X-Rate-Limit-Reset")
        if reset:
            self._rate_limit_reset = float(reset)

        if resp.status_code == 429:
            retry_after = float(resp.headers.get("Retry-After", "1"))
            time.sleep(retry_after)
            return self._request(method, endpoint, **kwargs)

        resp.raise_for_status()
        return resp.json()

    def get(self, endpoint: str, **kwargs) -> dict:
        return self._request("GET", endpoint, **kwargs)

    def post(self, endpoint: str, **kwargs) -> dict:
        return self._request("POST", endpoint, **kwargs)

    def patch(self, endpoint: str, **kwargs) -> dict:
        return self._request("PATCH", endpoint, **kwargs)

    def delete(self, endpoint: str, **kwargs) -> dict:
        return self._request("DELETE", endpoint, **kwargs)

    def search(self, query: str = "", filter_type: str = "page", page_size: int = 100) -> dict:
        body = {"page_size": page_size}
        if query:
            body["query"] = query
        if filter_type:
            body["filter"] = {"value": filter_type, "property": "object"}
        return self.post("/search", json=body)

    def get_database(self, database_id: str) -> dict:
        return self.get(f"/databases/{database_id}")

    def create_database(self, parent_page_id: str, title: str, properties: dict) -> dict:
        body = {
            "parent": {"type": "page_id", "page_id": parent_page_id},
            "title": [{"type": "text", "text": {"content": title}}],
            "properties": properties,
        }
        return self.post("/databases", json=body)

    def query_database(self, database_id: str, filter_obj: Optional[dict] = None,
                       sorts: Optional[list] = None, page_size: int = 100) -> list:
        body: dict = {"page_size": page_size}
        if filter_obj:
            body["filter"] = filter_obj
        if sorts:
            body["sorts"] = sorts
        results = []
        while True:
            resp = self.post(f"/databases/{database_id}/query", json=body)
            results.extend(resp.get("results", []))
            if not resp.get("has_more"):
                break
            body["start_cursor"] = resp["next_cursor"]
        return results

    def create_page(self, parent: dict, properties: dict,
                    children: Optional[list] = None) -> dict:
        body: dict = {"parent": parent, "properties": properties}
        if children:
            body["children"] = children[:100]
        return self.post("/pages", json=body)

    def update_page(self, page_id: str, properties: dict) -> dict:
        return self.patch(f"/pages/{page_id}", json={"properties": properties})

    def get_page(self, page_id: str) -> dict:
        return self.get(f"/pages/{page_id}")

    def get_page_content(self, page_id: str, block_id: Optional[str] = None) -> dict:
        bid = block_id or page_id
        return self.get(f"/blocks/{bid}/children")

    def append_block_children(self, block_id: str, children: list) -> dict:
        return self.patch(f"/blocks/{block_id}/children", json={"children": children[:100]})

    def delete_block(self, block_id: str) -> dict:
        return self.delete(f"/blocks/{block_id}")

    def get_current_user(self) -> dict:
        return self.get("/users/me")

    def verify_webhook(self, body: bytes, signature: str, secret: str) -> bool:
        expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    def get_oauth_authorize_url(self, state: str = "") -> str:
        params = {
            "client_id": self.config.oauth_client_id,
            "redirect_uri": self.config.oauth_redirect_uri,
            "response_type": "code",
            "owner": "user",
        }
        if state:
            params["state"] = state
        return f"https://api.notion.com/v1/oauth/authorize?{urlencode(params)}"

    def exchange_code(self, code: str) -> dict:
        resp = requests.post(
            "https://api.notion.com/v1/oauth/token",
            json={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.config.oauth_redirect_uri,
            },
            auth=(self.config.oauth_client_id, self.config.oauth_client_secret),
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data.get("access_token", "")
        self._session.headers["Authorization"] = f"Bearer {self._token}"
        return data
