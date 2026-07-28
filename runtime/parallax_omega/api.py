from __future__ import annotations

import hmac
import os
from dataclasses import asdict
from typing import Any
from uuid import uuid4

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Response
    from pydantic import BaseModel, ConfigDict, Field
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("Install the runtime extra: pip install -e '.[runtime]'") from exc

from .authority import ActionGovernor
from .claim_graph import ClaimGraph
from .memory import MemoryProtocolError, MemorySteward
from .models import ActionRequest, RiskLevel
from .policy import HostPolicyAdapter

app = FastAPI(title="PARALLAX Ω Advisory Actions API", version="1.0.0-rc.2")
graph = ClaimGraph()
governor = ActionGovernor()
steward = MemorySteward()


def authenticate(authorization: str | None = Header(default=None)) -> None:
    expected = os.getenv("PARALLAX_API_KEY")
    if not expected:
        raise HTTPException(status_code=503, detail="api_not_configured")
    supplied = authorization or ""
    if not hmac.compare_digest(supplied, f"Bearer {expected}"):
        raise HTTPException(status_code=401, detail="unauthorized")


class ActionProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_id: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=128)
    operation: str = Field(min_length=1, max_length=128)
    scope: str = Field(min_length=1, max_length=1024)
    risk: RiskLevel
    evidence_claim_ids: list[str] = Field(default_factory=list, max_length=64)
    irreversible: bool = False


class MemoryProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: str = Field(min_length=1, max_length=10000)
    purpose: str = Field(min_length=1, max_length=500)
    sensitivity: str = Field(default="normal", min_length=1, max_length=64)
    retention_days: int = Field(default=30, ge=1, le=365)
    target: str = Field(default="journal", min_length=1, max_length=64)
    deletion_path: str = Field(min_length=1, max_length=1024)


@app.middleware("http")
async def attach_request_id(request, call_next):  # type: ignore[no-untyped-def]
    request_id = request.headers.get("x-request-id") or str(uuid4())
    response: Response = await call_next(request)
    response.headers["x-request-id"] = request_id
    response.headers["cache-control"] = "no-store"
    return response


@app.get("/health")
def health() -> dict[str, Any]:
    adapter = HostPolicyAdapter.from_env()
    return {
        "ok": True,
        "service": "parallax-omega",
        "version": "1.0.0-rc.2",
        "memory": "disabled",
        "external_writes": "not_exposed",
        "policy_mode": adapter.mode.value,
    }


@app.post("/v1/actions/preflight", dependencies=[Depends(authenticate)])
def preflight_action(body: ActionProposal) -> dict[str, Any]:
    request = ActionRequest(
        action_id=body.action_id,
        tool=body.tool,
        operation=body.operation,
        scope=body.scope,
        risk=body.risk,
        evidence_claim_ids=tuple(body.evidence_claim_ids),
        irreversible=body.irreversible,
    )
    adapter = HostPolicyAdapter.from_env()
    decision = governor.decide(request, adapter.context_for(request), graph)
    return {
        "advisory": True,
        "execution_performed": False,
        "policy_mode": adapter.mode.value,
        "action_fingerprint": request.fingerprint(),
        "decision": asdict(decision),
    }


@app.post("/v1/memory/candidates", dependencies=[Depends(authenticate)])
def propose_memory(body: MemoryProposal) -> dict[str, Any]:
    try:
        candidate = steward.propose(**body.model_dump())
    except MemoryProtocolError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "persistent": False,
        "execution_performed": False,
        "candidate": asdict(candidate),
        "candidate_fingerprint": candidate.fingerprint(),
    }
