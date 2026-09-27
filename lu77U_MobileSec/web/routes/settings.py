#!/usr/bin/env python3
"""
Module: lu77U_MobileSec.web.routes.settings

Purpose:
    Expose the settings surface: provider selection and credentials, tool paths, feature toggles, prompt overrides and analysis skills.

Responsibilities:
    Validate request bodies and delegate to the settings service.

Dependencies:
    The settings service.

Security considerations:
    These endpoints write API keys and read them back for display. The reveal endpoint returns key material in full and exists because a user occasionally needs to check which key is stored -- every other path shows a masked form. The dashboard binds to loopback and is unauthenticated, so anything able to reach it can read the stored credentials. That is the reason the bind address is not configurable.
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from pydantic import BaseModel

from ..services import settings_service

router = APIRouter(prefix="/api", tags=["settings"])

class SettingsUpdate(BaseModel):
    """
    Purpose:
        Request body for updating tool paths, the active provider and feature toggles.

    Invariants:
        Validated by the framework before the handler runs, so a malformed body is rejected with a descriptive error rather than reaching the service layer.

    Thread-safety:
        A plain data model; instances are per-request.

    Implementation notes:
        Every field is optional, so the interface can send only what changed rather than the whole settings tree.
    """
    active_provider: Optional[str] = None
    jadx_path: Optional[str] = None
    blutter_path: Optional[str] = None
    hermes_decomp_path: Optional[str] = None
    rn_decompiler_path: Optional[str] = None
    output_dir: Optional[str] = None
    dynamic_verification: Optional[bool] = None
    agent_memory: Optional[bool] = None
    pdf_generation: Optional[bool] = None
    auto_resume: Optional[bool] = None
    agent_budget: Optional[Dict[str, int]] = None
    providers: Optional[Dict[str, Dict[str, Any]]] = None

class CredentialUpdate(BaseModel):
    """
    Purpose:
        Request body for adding or replacing a provider's API key.

    Invariants:
        Validated by the framework before the handler runs, so a malformed body is rejected with a descriptive error rather than reaching the service layer.

    Thread-safety:
        A plain data model; instances are per-request.
    """
    provider: str
    api_key: Optional[str] = None

class CredentialReveal(BaseModel):
    """
    Purpose:
        Request body for revealing one stored key by position.

    Invariants:
        Validated by the framework before the handler runs, so a malformed body is rejected with a descriptive error rather than reaching the service layer.

    Thread-safety:
        A plain data model; instances are per-request.

    Implementation notes:
        Identified by position rather than by value, so the interface never has to send a key back to ask about it.
    """
    index: int

class TestRequest(BaseModel):
    """
    Purpose:
        Request body for testing a provider's configuration.

    Invariants:
        Validated by the framework before the handler runs, so a malformed body is rejected with a descriptive error rather than reaching the service layer.

    Thread-safety:
        A plain data model; instances are per-request.

    Implementation notes:
        The provider is optional; omitting it tests the active one.
    """
    provider: Optional[str] = None

class PromptUpdate(BaseModel):
    """
    Purpose:
        Request body for replacing a built-in prompt with the user's own text.

    Invariants:
        Validated by the framework before the handler runs, so a malformed body is rejected with a descriptive error rather than reaching the service layer.

    Thread-safety:
        A plain data model; instances are per-request.
    """
    text: str

@router.get("/settings")
async def get_settings():
    """
    Purpose:
        Return the current settings, with credentials masked.

    Parameters:
        None.

    Returns:
        The JSON response body.
    """
    return settings_service.get_settings()

@router.put("/settings")
async def update_settings(update: SettingsUpdate):
    """
    Purpose:
        Apply a settings change.

    Parameters:
        update: The fields to change; omitted fields are left alone.

    Returns:
        The updated settings, with credentials masked.
    """
    try:
        return settings_service.update_settings(update.model_dump(exclude_none=True))
    except ValueError as exc:
        raise HTTPException(400, str(exc))

@router.post("/settings/credentials")
async def set_credentials(payload: CredentialUpdate):
    """
    Purpose:
        Store an API key for a provider.

    Parameters:
        payload: The provider and the key.

    Returns:
        The provider's masked key list.

    Side effects:
        Writes to the OS keychain, or to the encrypted fallback store.

    Security considerations:
        The key is never written to the settings file. The response carries only masked forms, so a key is not echoed back to the client that just sent it.
    """
    try:
        settings_service.set_credential(payload.provider, payload.api_key)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"ok": True, "provider": payload.provider}

@router.delete("/settings/credentials/{provider}/{index}")
async def remove_credential(provider: str, index: int):
    """
    Purpose:
        Remove one stored key.

    Parameters:
        provider: The provider.
        index: Position of the key to remove, as the interface lists them.

    Returns:
        The provider's remaining masked keys.

    Side effects:
        Rewrites the provider's stored keys.

    Security considerations:
        Removal is by position rather than by value, so the client never has to send a key back to delete it.
    """
    try:
        settings_service.remove_credential(provider, index)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"ok": True, "provider": provider}

@router.post("/settings/credentials/{provider}/reveal")
async def reveal_credential(provider: str, payload: CredentialReveal):
    """
    Purpose:
        Return one stored key in full.

    Parameters:
        provider: The provider.
        payload: The position to reveal.

    Returns:
        The JSON response body.

    Implementation notes:
        The one endpoint that returns key material unmasked. It exists so a user can verify which key is stored, and it is reachable only from loopback.
    """
    try:
        key = settings_service.reveal_credential(provider, payload.index)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"provider": provider, "index": payload.index, "key": key}

@router.get("/settings/models/{provider}")
async def list_models(request: Request, provider: str):
    """
    Purpose:
        List the models available for a provider, for the model chooser.

    Parameters:
        request: The incoming request.
        provider: The provider.

    Returns:
        The JSON response body.
    """
    verbose = bool(getattr(request.app.state, "verbose", False))
    return {"provider": provider,
            "models": settings_service.list_models(provider, verbose=verbose)}

@router.get("/settings/cli-status/{provider}")
async def cli_status(request: Request, provider: str):
    """
    Purpose:
        Report whether a CLI-backed provider is installed and signed in.

    Parameters:
        request: The incoming request.
        provider: The provider.

    Returns:
        The JSON response body.
    """
    verbose = bool(getattr(request.app.state, "verbose", False))
    try:
        return settings_service.get_cli_status(provider, verbose=verbose)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

@router.post("/settings/test")
async def test_provider(request: Request, payload: TestRequest):
    """
    Purpose:
        Test that a provider is configured and reachable.

    Parameters:
        request: The incoming request.
        payload: The provider to test, or none for the active one.

    Returns:
        The JSON response body.
    """
    verbose = bool(getattr(request.app.state, "verbose", False))
    return settings_service.test_provider(payload.provider, verbose=verbose)

@router.get("/settings/prompts")
async def list_prompts():
    """
    Purpose:
        List the built-in prompts with their labels, help text and any overrides.

    Parameters:
        None.

    Returns:
        The JSON response body.
    """
    return {"prompts": settings_service.list_prompts()}

@router.put("/settings/prompts/{prompt_id}")
async def save_prompt(prompt_id: str, payload: PromptUpdate):
    """
    Purpose:
        Replace a built-in prompt with the user's text.

    Parameters:
        prompt_id: The prompt identifier.
        payload: The replacement text.

    Returns:
        The JSON response body.

    Implementation notes:
        An override becomes the system prompt for analysis, so this endpoint changes what the tool looks for. It is a deliberate power-user capability and the text is not sanitised.
    """
    try:
        return settings_service.save_prompt(prompt_id, payload.text)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

@router.delete("/settings/prompts/{prompt_id}")
async def reset_prompt(prompt_id: str):
    """
    Purpose:
        Discard an override so the built-in prompt applies again.

    Parameters:
        prompt_id: The prompt identifier.

    Returns:
        The JSON response body.
    """
    try:
        return settings_service.reset_prompt(prompt_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))

@router.get("/settings/skills")
async def list_skills():
    """
    Purpose:
        List the analysis skills available to the agent.

    Parameters:
        None.

    Returns:
        The JSON response body.
    """
    return {"skills": settings_service.list_skills()}

@router.post("/settings/skills")
async def upload_skill(file: UploadFile = File(...)):
    """
    Purpose:
        Store an uploaded analysis skill.

    Parameters:
        file: The uploaded skill.

    Returns:
        The JSON response body.

    Implementation notes:
        The filename and contents are validated by the settings service before anything is written, because both come from the client.
    """
    content = await file.read()
    try:
        return settings_service.save_skill(file.filename or "", content)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
