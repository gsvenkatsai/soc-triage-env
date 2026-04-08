from fastapi import FastAPI
from pydantic import BaseModel

from environment.env import SOCEnvironment

app = FastAPI()

env = SOCEnvironment()


# -----------------------------
# Request schemas
# -----------------------------
class ResetRequest(BaseModel):
    task_id: int = 1
    seed: int = 42


class StepRequest(BaseModel):
    action: str


# -----------------------------
# Endpoints
# -----------------------------

from typing import Optional

@app.post("/reset")
def reset(req: Optional[ResetRequest] = None):
    task_id = req.task_id if req else 1
    seed = req.seed if req else 42
    obs = env.reset(task_id=task_id, seed=seed)
    return obs.dict()

@app.post("/step")
def step(req: StepRequest):
    obs, reward, done, info = env.step(req.action)

    return {
        "observation": obs.dict(),
        "reward": reward,
        "done": done,
        "info": info,
    }


@app.get("/state")
def state():
    if env.state is None:
        return {"error": "Environment not initialized. Call /reset first."}
    return env.state_dict().dict()

@app.get("/")
def root():
    return {"status": "ok", "env": "soc-triage-env", "endpoints": ["/reset", "/step", "/state"]}