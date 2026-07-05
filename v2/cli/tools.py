"""Real-world tool integrations for autonomous agent.

Tools:
- GitHub API (repos, issues, PRs)
- Web search (DuckDuckGo, Brave)
- File operations (read, write, search)
- Shell commands (safe execution)
- HTTP requests (REST APIs)
"""
from __future__ import annotations
import os
import json
import requests
import subprocess
from pathlib import Path
from typing import Optional, Any


class GitHubTool:
    """GitHub API integration."""
    
    def __init__(self, token: Optional[str] = None):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.base_url = "https://api.github.com"
        self.headers = {}
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"
    
    def search_repos(self, query: str, limit: int = 10) -> list[dict]:
        """Search GitHub repositories."""
        url = f"{self.base_url}/search/repositories"
        params = {"q": query, "per_page": limit, "sort": "stars"}
        
        try:
            resp = requests.get(url, headers=self.headers, params=params, timeout=10)
            if resp.status_code == 200:
                return resp.json().get("items", [])
        except Exception:
            pass
        
        return []
    
    def get_repo(self, owner: str, repo: str) -> Optional[dict]:
        """Get repository information."""
        url = f"{self.base_url}/repos/{owner}/{repo}"
        
        try:
            resp = requests.get(url, headers=self.headers, timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        
        return None
    
    def list_issues(self, owner: str, repo: str, state: str = "open") -> list[dict]:
        """List repository issues."""
        url = f"{self.base_url}/repos/{owner}/{repo}/issues"
        params = {"state": state, "per_page": 20}
        
        try:
            resp = requests.get(url, headers=self.headers, params=params, timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        
        return []
    
    def create_issue(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        labels: Optional[list[str]] = None,
    ) -> Optional[dict]:
        """Create a new issue."""
        if not self.token:
            return None
        
        url = f"{self.base_url}/repos/{owner}/{repo}/issues"
        data = {"title": title, "body": body}
        if labels:
            data["labels"] = labels
        
        try:
            resp = requests.post(url, headers=self.headers, json=data, timeout=10)
            if resp.status_code == 201:
                return resp.json()
        except Exception:
            pass
        
        return None


class WebSearchTool:
    """Web search integration (DuckDuckGo)."""
    
    def search(self, query: str, limit: int = 10) -> list[dict]:
        """Search the web."""
        # Using DuckDuckGo Instant Answer API (no auth required)
        url = "https://api.duckduckgo.com/"
        params = {
            "q": query,
            "format": "json",
            "no_html": 1,
            "skip_disambig": 1,
        }
        
        try:
            resp = requests.get(url, params=params, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                results = []
                
                # Abstract
                if data.get("Abstract"):
                    results.append({
                        "title": data.get("Heading", ""),
                        "snippet": data.get("Abstract", ""),
                        "url": data.get("AbstractURL", ""),
                        "source": "duckduckgo",
                    })
                
                # Related topics
                for topic in data.get("RelatedTopics", [])[:limit]:
                    if isinstance(topic, dict) and "Text" in topic:
                        results.append({
                            "title": topic.get("FirstURL", "").split("/")[-1].replace("_", " "),
                            "snippet": topic.get("Text", ""),
                            "url": topic.get("FirstURL", ""),
                            "source": "duckduckgo",
                        })
                
                return results[:limit]
        except Exception:
            pass
        
        return []


class FileOperationsTool:
    """Safe file operations."""
    
    def __init__(self, allowed_dirs: Optional[list[str]] = None):
        self.allowed_dirs = [Path(d).resolve() for d in (allowed_dirs or ["."])]
    
    def _is_safe_path(self, path: str) -> bool:
        """Check if path is within allowed directories."""
        p = Path(path).resolve()
        return any(
            str(p).startswith(str(allowed)) 
            for allowed in self.allowed_dirs
        )
    
    def read_file(self, path: str, max_size: int = 1_000_000) -> Optional[str]:
        """Read a file safely."""
        if not self._is_safe_path(path):
            return None
        
        try:
            p = Path(path)
            if p.exists() and p.stat().st_size <= max_size:
                return p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass
        
        return None
    
    def write_file(self, path: str, content: str) -> bool:
        """Write to a file safely."""
        if not self._is_safe_path(path):
            return False
        
        try:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            return True
        except Exception:
            return False
    
    def list_files(self, directory: str, pattern: str = "*") -> list[str]:
        """List files in directory."""
        if not self._is_safe_path(directory):
            return []
        
        try:
            p = Path(directory)
            if p.is_dir():
                return [str(f.relative_to(p)) for f in p.glob(pattern) if f.is_file()]
        except Exception:
            pass
        
        return []
    
    def search_in_files(
        self,
        directory: str,
        pattern: str,
        file_pattern: str = "*.py",
    ) -> list[dict]:
        """Search for text pattern in files."""
        if not self._is_safe_path(directory):
            return []
        
        import re
        results = []
        
        try:
            p = Path(directory)
            for file_path in p.rglob(file_pattern):
                if file_path.is_file() and self._is_safe_path(str(file_path)):
                    try:
                        content = file_path.read_text(encoding="utf-8", errors="replace")
                        matches = list(re.finditer(pattern, content, re.IGNORECASE))
                        
                        if matches:
                            results.append({
                                "file": str(file_path.relative_to(p)),
                                "matches": len(matches),
                                "lines": [
                                    content[:match.start()].count('\n') + 1
                                    for match in matches[:5]
                                ],
                            })
                    except Exception:
                        pass
        except Exception:
            pass
        
        return results


class ShellTool:
    """Safe shell command execution."""
    
    ALLOWED_COMMANDS = {
        "ls", "cat", "grep", "find", "wc", "head", "tail",
        "git", "npm", "pip", "python", "node",
    }
    
    def execute(
        self,
        command: str,
        timeout: int = 30,
        cwd: Optional[str] = None,
    ) -> dict:
        """Execute shell command safely."""
        # Parse command
        parts = command.split()
        if not parts:
            return {"success": False, "error": "Empty command"}
        
        cmd_name = parts[0]
        
        # Security check
        if cmd_name not in self.ALLOWED_COMMANDS:
            return {"success": False, "error": f"Command '{cmd_name}' not allowed"}
        
        try:
            result = subprocess.run(
                parts,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
            )
            
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Command timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}


class HTTPTool:
    """HTTP request tool for REST APIs."""
    
    def request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        data: Optional[dict] = None,
        timeout: int = 30,
    ) -> dict:
        """Make HTTP request."""
        method = method.upper()
        
        if method not in {"GET", "POST", "PUT", "DELETE", "PATCH"}:
            return {"success": False, "error": f"Method '{method}' not supported"}
        
        try:
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=data if data else None,
                timeout=timeout,
            )
            
            # Try to parse JSON
            try:
                content = resp.json()
            except Exception:
                content = resp.text
            
            return {
                "success": resp.status_code < 400,
                "status_code": resp.status_code,
                "content": content,
                "headers": dict(resp.headers),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}


# Tool registry for agent
TOOLS = {
    "github": GitHubTool(),
    "web_search": WebSearchTool(),
    "file_ops": FileOperationsTool(),
    "shell": ShellTool(),
    "http": HTTPTool(),
}


def get_tool(name: str) -> Optional[Any]:
    """Get tool by name."""
    return TOOLS.get(name)


def list_tools() -> list[str]:
    """List available tools."""
    return list(TOOLS.keys())
