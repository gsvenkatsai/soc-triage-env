"""
FastAPI server for the SOC Triage Environment.

Exposes the OpenEnv-compatible HTTP API:
  POST /reset  — start a new episode
  POST /step   — execute an action
  GET  /state  — retrieve current state
  POST /score  — grade the current episode
  GET  /health — health check
  GET  /        — environment info
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional

from environment.env import SOCEnvironment
from graders.grader1 import Grader1
from graders.grader2 import Grader2
from graders.grader3 import Grader3

app = FastAPI(
    title="SOC Triage Environment",
    description="OpenEnv-compatible SOC alert triage environment for AI agent training and evaluation.",
    version="2.0.0",
)

# CORS for HF Spaces and external access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Single environment instance (stateful per session)
env = SOCEnvironment()

# Graders indexed by task_id
GRADERS = {1: Grader1(), 2: Grader2(), 3: Grader3()}

# Track current task_id for grading
_current_task_id: int = 1


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all handler to prevent environment crashes."""
    return JSONResponse(
        status_code=500,
        content={"error": str(exc), "detail": "Internal server error"},
    )


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class ResetRequest(BaseModel):
    task_id: int = Field(default=1, description="Task ID (1=easy, 2=medium, 3=hard)")
    seed: int = Field(default=42, description="Random seed for reproducibility")


class StepRequest(BaseModel):
    action: str = Field(..., description="Action string, e.g. 'pull_logs auth.log'")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/reset")
def reset(req: Optional[ResetRequest] = None):
    """Reset the environment and start a new episode."""
    global _current_task_id
    task_id = req.task_id if req else 1
    seed = req.seed if req else 42

    try:
        _current_task_id = task_id
        obs = env.reset(task_id=task_id, seed=seed)
        return obs.model_dump(mode="json")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/step")
def step(req: StepRequest):
    """Execute one action in the environment."""
    if env.state is None:
        raise HTTPException(
            status_code=400,
            detail="Environment not initialized. Call POST /reset first.",
        )
    try:
        obs, reward, done, info = env.step(req.action)
        return {
            "observation": obs.model_dump(mode="json"),
            "reward": reward,
            "done": done,
            "info": info,
        }
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/state")
def state():
    """Get the current environment state (for grading/debugging)."""
    if env.state is None:
        raise HTTPException(
            status_code=400,
            detail="Environment not initialized. Call POST /reset first."
        )
    return env.state_dict().model_dump(mode="json")


@app.post("/score")
def score():
    """
    Grade the current episode using the task-specific grader.

    Returns:
        JSON with grader score (0.0–1.0) and task metadata.
    """
    if env.state is None:
        raise HTTPException(
            status_code=400,
            detail="Environment not initialized. Call POST /reset first.",
        )

    grader = GRADERS.get(_current_task_id)
    if grader is None:
        raise HTTPException(
            status_code=400,
            detail=f"No grader for task_id={_current_task_id}.",
        )

    grader_score = grader.score(env.state_dict(), env.ground_truth)

    return {
        "score": round(grader_score, 4),
        "task_id": _current_task_id,
        "episode_id": env.state.episode_id,
        "done": env.done,
        "steps": env.state.step_count,
        "verdict": env.state.verdict,
    }


@app.get("/health")
def health():
    """Health check endpoint for Docker / HF Spaces."""
    return {"status": "healthy", "env": "soc-triage-env", "version": "2.0.0"}


@app.get("/")
def root():
    """Environment info and API documentation."""
    return {
        "status": "ok",
        "env": "soc-triage-env",
        "version": "2.0.0",
        "description": "SOC Alert Triage — OpenEnv Environment",
        "spec_version": 1,
        "api": {
            "reset": "POST /reset — {task_id: 1|2|3, seed: int}",
            "step": "POST /step — {action: str}",
            "state": "GET /state",
            "score": "POST /score — grade current episode",
            "health": "GET /health",
            "docs": "GET /docs — interactive API docs",
        },
        "tasks": {
            "1": "SSH Brute Force Detection (easy, max_steps=10)",
            "2": "Lateral Movement Investigation (medium, max_steps=12)",
            "3": "APT Kill Chain (hard, max_steps=15)",
        },
    }


def main():
    """Entry point for direct execution."""
    import uvicorn
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860)


if __name__ == "__main__":
    main()