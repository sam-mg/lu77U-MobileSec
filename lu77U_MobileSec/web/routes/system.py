"""System endpoints: health, version, and analysis readiness."""

from fastapi import APIRouter

from ... import __version__
from ...tools_checker.analysis_checker import get_analysis_status

router = APIRouter(prefix="/api", tags=["system"])

@router.get("/health")
async def health():
    return {"ok": True}

@router.get("/version")
async def version():
    return {"name": "lu77U-MobileSec", "version": __version__}

@router.get("/status")
async def status():
    return get_analysis_status()