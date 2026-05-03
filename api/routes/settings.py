from fastapi import APIRouter, Request

from modules.settings_io import get_settings_view, update_settings

router = APIRouter()


@router.get("")
def get_settings():
    return get_settings_view()


@router.put("")
async def put_settings(request: Request):
    """Body is a free-form JSON object. Allowed keys come from settings_io.SCHEMA;
    unknown keys are ignored. Pass null or '' for any key to clear it."""
    try:
        body = await request.json()
        if not isinstance(body, dict):
            body = {}
    except Exception:
        body = {}
    return update_settings(body)
