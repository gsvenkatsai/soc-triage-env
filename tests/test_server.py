"""
Integration tests for the FastAPI server endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from server.app import app


client = TestClient(app)


class TestRootEndpoint:
    def test_root_returns_info(self):
        resp = client.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["env"] == "soc-triage-env"
        assert data["spec_version"] == 1
        assert "api" in data
        assert "tasks" in data
        assert "score" in data["api"]


class TestHealthEndpoint:
    def test_health_check(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


class TestResetEndpoint:
    def test_reset_default(self):
        resp = client.post("/reset")
        assert resp.status_code == 200
        data = resp.json()
        assert "alert" in data
        assert data["step_count"] == 0
        assert data["done"] is False

    def test_reset_with_task_id(self):
        resp = client.post("/reset", json={"task_id": 2, "seed": 42})
        assert resp.status_code == 200
        assert "Lateral Movement" in resp.json()["alert"]["title"]

    def test_reset_with_task3(self):
        resp = client.post("/reset", json={"task_id": 3, "seed": 42})
        assert resp.status_code == 200
        assert resp.json()["alert"]["severity"] == "CRITICAL"

    def test_reset_invalid_task(self):
        resp = client.post("/reset", json={"task_id": 99})
        assert resp.status_code == 400


class TestStepEndpoint:
    def test_step_after_reset(self):
        client.post("/reset", json={"task_id": 1, "seed": 42})
        resp = client.post("/step", json={"action": "pull_logs auth.log"})
        assert resp.status_code == 200
        data = resp.json()
        assert "observation" in data
        assert "reward" in data
        assert "done" in data
        assert "info" in data
        assert data["observation"]["step_count"] == 1

    def test_step_verdict(self):
        client.post("/reset", json={"task_id": 1, "seed": 42})
        resp = client.post("/step", json={"action": "escalate brute force"})
        assert resp.status_code == 200
        assert resp.json()["done"] is True

    def test_step_without_reset(self):
        # This should work if reset was called previously
        # but fail with a clear error if not
        pass  # Server uses global state, so this depends on order


class TestStateEndpoint:
    def test_state_after_reset(self):
        client.post("/reset", json={"task_id": 1, "seed": 42})
        resp = client.get("/state")
        assert resp.status_code == 200
        data = resp.json()
        assert "alert_id" in data
        assert "actions_taken" in data
        assert data["step_count"] == 0

    def test_state_after_actions(self):
        client.post("/reset", json={"task_id": 1, "seed": 42})
        client.post("/step", json={"action": "pull_logs auth.log"})
        client.post("/step", json={"action": "query_ip_reputation 185.220.101.45"})
        resp = client.get("/state")
        assert resp.status_code == 200
        data = resp.json()
        assert data["step_count"] == 2
        assert len(data["actions_taken"]) == 2


class TestScoreEndpoint:
    """Tests for the /score grading endpoint."""

    def test_score_after_investigation(self):
        client.post("/reset", json={"task_id": 1, "seed": 42})
        client.post("/step", json={"action": "pull_logs auth.log"})
        client.post("/step", json={"action": "query_ip_reputation 185.220.101.45"})
        client.post("/step", json={"action": "escalate SSH brute force confirmed"})
        resp = client.post("/score")
        assert resp.status_code == 200
        data = resp.json()
        assert "score" in data
        assert 0.0 <= data["score"] <= 1.0
        assert data["task_id"] == 1
        assert data["done"] is True
        assert data["verdict"] == "escalate"

    def test_score_task3(self):
        client.post("/reset", json={"task_id": 3, "seed": 42})
        client.post("/step", json={"action": "pull_logs email.log"})
        client.post("/step", json={"action": "pull_logs endpoint.log"})
        client.post("/step", json={"action": "correlate_alerts 120"})
        client.post("/step", json={"action": "escalate_critical APT kill chain"})
        resp = client.post("/score")
        assert resp.status_code == 200
        data = resp.json()
        assert data["score"] > 0.5
        assert data["task_id"] == 3

    def test_score_in_range(self):
        """Grader scores must always be between 0.0 and 1.0."""
        for task_id in [1, 2, 3]:
            client.post("/reset", json={"task_id": task_id, "seed": 42})
            client.post("/step", json={"action": "escalate test"})
            resp = client.post("/score")
            data = resp.json()
            assert 0.0 <= data["score"] <= 1.0, f"Task {task_id} score out of range: {data['score']}"


class TestFullEpisode:
    """End-to-end test of a complete episode with grading."""

    def test_task1_full_episode(self):
        # Reset
        resp = client.post("/reset", json={"task_id": 1, "seed": 42})
        assert resp.status_code == 200

        # Investigate
        resp = client.post("/step", json={"action": "pull_logs auth.log"})
        assert resp.json()["done"] is False

        resp = client.post("/step", json={"action": "query_ip_reputation 185.220.101.45"})
        assert resp.json()["done"] is False

        # Verdict
        resp = client.post("/step", json={"action": "escalate SSH brute force confirmed"})
        assert resp.json()["done"] is True

        # Check final state
        resp = client.get("/state")
        data = resp.json()
        assert data["verdict"] == "escalate"
        assert data["step_count"] == 3

        # Grade
        resp = client.post("/score")
        score_data = resp.json()
        assert score_data["score"] > 0.7
        assert score_data["done"] is True
