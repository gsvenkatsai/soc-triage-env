"""
Tests for all task graders.

Verifies:
- Perfect score paths
- Zero/low score paths
- Partial credit scenarios
- Scores always in [0.0, 1.0]
- Deterministic scoring
"""

import pytest
from environment.env import SOCEnvironment
from graders.grader1 import Grader1
from graders.grader2 import Grader2
from graders.grader3 import Grader3


class TestGrader1:
    """Task 1 — SSH Brute Force grading."""

    def test_perfect_score(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        env.step("pull_logs auth.log")
        env.step("query_ip_reputation 185.220.101.45")
        env.step("escalate SSH brute force attack confirmed")
        score = Grader1().score(env.state_dict(), env.ground_truth)
        assert 0.0 <= score <= 1.0
        assert score > 0.7  # Good evidence + correct verdict + keywords

    def test_wrong_verdict(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        env.step("close_false_positive no threat detected")
        score = Grader1().score(env.state_dict(), env.ground_truth)
        assert score < 0.3

    def test_correct_verdict_no_evidence(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        env.step("escalate brute force")
        score = Grader1().score(env.state_dict(), env.ground_truth)
        # Correct verdict but no evidence and bad response quality
        assert 0.2 < score < 0.7

    def test_no_verdict(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        env.step("pull_logs auth.log")
        # Don't submit verdict — grader should give low score
        state = env.state_dict()
        state.done = True  # Simulate max steps
        score = Grader1().score(state, env.ground_truth)
        assert score < 0.5  # No verdict at all

    def test_score_in_range(self):
        env = SOCEnvironment()
        env.reset(task_id=1, seed=42)
        env.step("pull_logs auth.log")
        env.step("escalate something")
        score = Grader1().score(env.state_dict(), env.ground_truth)
        assert 0.0 <= score <= 1.0


class TestGrader2:
    """Task 2 — Lateral Movement grading."""

    def test_full_investigation(self):
        env = SOCEnvironment()
        env.reset(task_id=2, seed=42)
        env.step("pull_logs network.log")
        env.step("check_asset_criticality A005")  # Check the scanner
        env.step("check_asset_criticality A002")  # Check the target
        env.step("escalate lateral movement from dev workstation confirmed")
        score = Grader2().score(env.state_dict(), env.ground_truth)
        assert score > 0.7

    def test_full_score(self):
        env = SOCEnvironment()
        env.reset(task_id=2, seed=42)
        env.step("pull_logs network.log")
        env.step("check_asset_criticality vuln-scanner-01")  # Red herring check
        env.step("escalate lateral movement confirmed")
        score = Grader2().score(env.state_dict(), env.ground_truth)
        assert score >= 0.8

    def test_no_asset_check(self):
        env = SOCEnvironment()
        env.reset(task_id=2, seed=42)
        env.step("escalate lateral movement")
        score = Grader2().score(env.state_dict(), env.ground_truth)
        assert score < 0.5  # Missed red herring handling

    def test_wrong_verdict(self):
        env = SOCEnvironment()
        env.reset(task_id=2, seed=42)
        env.step("close_false_positive scanner traffic only")
        score = Grader2().score(env.state_dict(), env.ground_truth)
        assert score < 0.4

    def test_score_in_range(self):
        env = SOCEnvironment()
        env.reset(task_id=2, seed=42)
        for action in ["pull_logs network.log", "check_asset_criticality A002",
                       "escalate lateral movement"]:
            env.step(action)
        score = Grader2().score(env.state_dict(), env.ground_truth)
        assert 0.0 <= score <= 1.0


class TestGrader3:
    """Task 3 — APT Kill Chain grading."""

    def test_full_investigation(self):
        env = SOCEnvironment()
        env.reset(task_id=3, seed=42)
        env.step("pull_logs email.log")
        env.step("pull_logs endpoint.log")
        env.step("query_ip_reputation 194.165.16.72")
        env.step("correlate_alerts 120")
        env.step("lookup_user hr_alice")
        env.step("escalate_critical multi-stage APT kill chain with credential theft and exfiltration confirmed")
        score = Grader3().score(env.state_dict(), env.ground_truth)
        assert score > 0.8

    def test_perfect_score(self):
        env = SOCEnvironment()
        env.reset(task_id=3, seed=42)
        env.step("pull_logs email.log")
        env.step("pull_logs endpoint.log")
        env.step("pull_logs network.log")
        env.step("query_ip_reputation 194.165.16.72")
        env.step("correlate_alerts 120")
        env.step("escalate_critical APT kill chain confirmed with exfiltration and credential theft")
        score = Grader3().score(env.state_dict(), env.ground_truth)
        assert score >= 0.9

    def test_escalate_instead_of_critical(self):
        env = SOCEnvironment()
        env.reset(task_id=3, seed=42)
        env.step("pull_logs email.log")
        env.step("pull_logs endpoint.log")
        env.step("correlate_alerts 120")
        env.step("escalate suspicious activity detected")  # Wrong! Should be critical
        score = Grader3().score(env.state_dict(), env.ground_truth)
        assert score < 0.7  # Wrong verdict type

    def test_no_correlation(self):
        env = SOCEnvironment()
        env.reset(task_id=3, seed=42)
        env.step("escalate_critical something bad")
        score = Grader3().score(env.state_dict(), env.ground_truth)
        assert score < 0.5  # Missing correlation and kill chain evidence

    def test_small_correlation_window(self):
        env = SOCEnvironment()
        env.reset(task_id=3, seed=42)
        env.step("pull_logs email.log")
        env.step("pull_logs endpoint.log")
        env.step("query_ip_reputation 194.165.16.72")
        env.step("correlate_alerts 30")  # Too small window
        env.step("escalate_critical APT kill chain")
        score_small = Grader3().score(env.state_dict(), env.ground_truth)

        env2 = SOCEnvironment()
        env2.reset(task_id=3, seed=42)
        env2.step("pull_logs email.log")
        env2.step("pull_logs endpoint.log")
        env2.step("query_ip_reputation 194.165.16.72")
        env2.step("correlate_alerts 120")  # Good window
        env2.step("escalate_critical APT kill chain")
        score_large = Grader3().score(env2.state_dict(), env2.ground_truth)

        assert score_large > score_small  # Better window = better score

    def test_score_in_range(self):
        env = SOCEnvironment()
        env.reset(task_id=3, seed=42)
        env.step("pull_logs email.log")
        env.step("escalate_critical something")
        score = Grader3().score(env.state_dict(), env.ground_truth)
        assert 0.0 <= score <= 1.0

    def test_deterministic(self):
        """Same actions should always produce same score."""
        actions = [
            "pull_logs email.log",
            "pull_logs endpoint.log",
            "correlate_alerts 120",
            "escalate_critical APT confirmed",
        ]

        scores = []
        for _ in range(3):
            env = SOCEnvironment()
            env.reset(task_id=3, seed=42)
            for a in actions:
                env.step(a)
            score = Grader3().score(env.state_dict(), env.ground_truth)
            scores.append(score)

        assert all(s == scores[0] for s in scores)