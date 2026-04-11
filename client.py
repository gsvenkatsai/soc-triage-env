"""
SOC Triage Environment — Client.

Provides a client class for connecting to a running SOC Triage
environment server via HTTP.

Usage:
    from client import SOCTriageClient

    client = SOCTriageClient("http://localhost:7860")
    obs = client.reset(task_id=1, seed=42)
    obs, reward, done, info = client.step("pull_logs auth.log")
    state = client.state()
"""

import requests
from typing import Optional, Tuple


class SOCTriageClient:
    """
    HTTP client for the SOC Triage Environment.

    Wraps the REST API for convenient Python usage.
    """

    def __init__(self, base_url: str = "http://localhost:7860"):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def reset(self, task_id: int = 1, seed: int = 42) -> dict:
        """
        Reset the environment and start a new episode.

        Args:
            task_id: 1 (easy), 2 (medium), or 3 (hard)
            seed: Random seed for reproducibility

        Returns:
            Initial observation dict
        """
        resp = self.session.post(
            f"{self.base_url}/reset",
            json={"task_id": task_id, "seed": seed},
        )
        resp.raise_for_status()
        return resp.json()

    def step(self, action: str) -> Tuple[dict, float, bool, dict]:
        """
        Execute one action.

        Args:
            action: Action string (e.g., "pull_logs auth.log")

        Returns:
            (observation, reward, done, info) tuple
        """
        resp = self.session.post(
            f"{self.base_url}/step",
            json={"action": action},
        )
        resp.raise_for_status()
        data = resp.json()
        return data["observation"], data["reward"], data["done"], data.get("info", {})

    def state(self) -> dict:
        """Get the current environment state."""
        resp = self.session.get(f"{self.base_url}/state")
        resp.raise_for_status()
        return resp.json()

    def health(self) -> dict:
        """Check server health."""
        resp = self.session.get(f"{self.base_url}/health")
        resp.raise_for_status()
        return resp.json()

    def close(self):
        """Close the HTTP session."""
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
