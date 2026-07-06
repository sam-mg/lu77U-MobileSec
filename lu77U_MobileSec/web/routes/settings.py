"""Settings, credentials, provider model listing, and connection testing."""

from typing import Any, Dict, Optional

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from pydantic import BaseModel

from ..services import settings_service

router = APIRouter(prefix="/api", tags=["settings"])

class SettingsUpdate(BaseModel):
    active_provider: Optional[str] = None
    jadx_path: Optional[str] = None
    output_dir: Optional[str] = None
    dynamic_verification: Optional[bool] = None
    agent_memory: Optional[bool] = None
    providers: Optional[Dict[str, Dict[str, Any]]] = None

class CredentialUpdate(BaseModel):
    provider: str
    api_key: Optional[str] = None

class TestRequest(BaseModel):
    provider: Optional[str] = None

class PromptUpdate(BaseModel):
    text: str

@router.get("/settings")
async def get_settings():
    return settings_service.get_settings()

@router.put("/settings")
async def update_settings(update: SettingsUpdate):
    try:
        return settings_service.update_settings(update.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(400, str(exc))

@router.post("/settings/credentials")
async def set_credentials(payload: CredentialUpdate):
    try:
        settings_service.set_credential(payload.provider, payload.api_key)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"ok": True, "provider": payload.provider}

@router.get("/settings/models/{provider}")
async def list_models(request: Request, provider: str):
    verbose = bool(getattr(request.app.state, "verbose", False))
    return {"provider": provider,
            "models": settings_service.list_models(provider, verbose=verbose)}

@router.post("/settings/test")
async def test_provider(request: Request, payload: TestRequest):
    verbose = bool(getattr(request.app.state, "verbose", False))
    return settings_service.test_provider(payload.provider, verbose=verbose)

@router.get("/settings/prompts")
async def list_prompts():
    return {"prompts": settings_service.list_prompts()}

@router.put("/settings/prompts/{prompt_id}")
async def save_prompt(prompt_id: str, payload: PromptUpdate):
    try:
        return settings_service.save_prompt(prompt_id, payload.text)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

@router.delete("/settings/prompts/{prompt_id}")
async def reset_prompt(prompt_id: str):
    try:
        return settings_service.reset_prompt(prompt_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

@router.get("/settings/skills")
async def list_skills():
    return {"skills": settings_service.list_skills()}

@router.post("/settings/skills")
async def upload_skill(file: UploadFile = File(...)):
    content = await file.read()
    try:
        return settings_service.save_skill(file.filename or "", content)
    except ValueError as exc:
        raise HTTPException(400, str(exc))