from environment.env import SOCEnvironment
from graders.grader1 import Grader1
from graders.grader2 import Grader2
from graders.grader3 import Grader3


def test_grader1_perfect_score():
    env = SOCEnvironment()
    env.reset(task_id=1, seed=42)
    env.step("query_ip_reputation 185.220.101.45")
    env.step("pull_logs auth.log")
    env.step("escalate confirmed brute force")
    score = Grader1().score(env.state, env.ground_truth)
    assert 0.0 <= score <= 1.0
    assert score > 0.5


def test_grader1_wrong_verdict():
    env = SOCEnvironment()
    env.reset(task_id=1, seed=42)
    env.step("escalate_critical wrong verdict")
    score = Grader1().score(env.state, env.ground_truth)
    assert score < 0.5


def test_grader2_full_score():
    env = SOCEnvironment()
    env.reset(task_id=2, seed=42)
    env.step("pull_logs network.log")
    env.step("check_asset_criticality A002")
    env.step("escalate lateral movement confirmed")
    score = Grader2().score(env.state, env.ground_truth)
    assert score == 1.0


def test_grader2_no_asset_check():
    env = SOCEnvironment()
    env.reset(task_id=2, seed=42)
    env.step("escalate skipped asset check")
    score = Grader2().score(env.state, env.ground_truth)
    assert score < 0.6


def test_grader3_full_score():
    env = SOCEnvironment()
    env.reset(task_id=3, seed=42)
    env.step("pull_logs endpoint.log")
    env.step("query_ip_reputation 194.165.16.72")
    env.step("correlate_alerts 120")
    env.step("escalate_critical full apt kill chain confirmed")
    score = Grader3().score(env.state, env.ground_truth)
    assert score == 1.0


def test_grader3_no_correlation():
    env = SOCEnvironment()
    env.reset(task_id=3, seed=42)
    env.step("escalate_critical no correlation done")
    score = Grader3().score(env.state, env.ground_truth)
    assert score < 0.5