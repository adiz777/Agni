"""
System Settings Management Endpoints
"""
from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.core.config import get_settings
from app.core.security import record_audit_log
from app.models.audit import SystemSettingModel
from app.schemas.common import ApiResponse
from app.schemas.settings import SettingItem, SystemSettingsRead, SystemSettingsUpdate

router = APIRouter(prefix="/settings", tags=["Settings"])
app_settings = get_settings()


@router.get("", response_model=ApiResponse[SystemSettingsRead])
@router.get("/", response_model=ApiResponse[SystemSettingsRead])
def get_system_settings(db: Session = Depends(get_db)) -> ApiResponse[SystemSettingsRead]:
    """Retrieve current system configuration parameters."""
    items = db.query(SystemSettingModel).all()
    item_map = {item.key: item.value for item in items}

    res = SystemSettingsRead(
        telemetry_interval_seconds=int(item_map.get("telemetry_interval_seconds", app_settings.TELEMETRY_INTERVAL_SECONDS)),
        fim_poll_interval_seconds=int(item_map.get("fim_poll_interval_seconds", app_settings.FIM_POLL_INTERVAL_SECONDS)),
        network_poll_interval_seconds=int(item_map.get("network_poll_interval_seconds", app_settings.NETWORK_POLL_INTERVAL_SECONDS)),
        correlation_window_seconds=int(item_map.get("correlation_window_seconds", app_settings.CORRELATION_WINDOW_SECONDS)),
        event_retention_days=int(item_map.get("event_retention_days", app_settings.EVENT_RETENTION_DAYS)),
        demo_mode_enabled=item_map.get("demo_mode_enabled", "false").lower() == "true",
        ai_provider=item_map.get("ai_provider", "none"),
        ai_endpoint=item_map.get("ai_endpoint"),
        ai_consent_granted=item_map.get("ai_consent_granted", "false").lower() == "true",
        settings_items=[SettingItem.model_validate(it) for it in items],
    )
    return ApiResponse(data=res)


@router.put("", response_model=ApiResponse[SystemSettingsRead])
@router.put("/", response_model=ApiResponse[SystemSettingsRead])
def update_system_settings(
    settings_in: SystemSettingsUpdate,
    db: Session = Depends(get_db),
) -> ApiResponse[SystemSettingsRead]:
    """Update runtime configuration settings."""
    now = datetime.now(UTC)
    updates = settings_in.model_dump(exclude_unset=True)

    for k, v in updates.items():
        val_str = str(v).lower() if isinstance(v, bool) else str(v)
        existing = db.query(SystemSettingModel).filter(SystemSettingModel.key == k).first()
        if existing:
            existing.value = val_str
            existing.updated_at = now
        else:
            db.add(
                SystemSettingModel(
                    key=k,
                    value=val_str,
                    description=f"System setting for {k}",
                    updated_at=now,
                )
            )

    db.commit()

    record_audit_log(
        db,
        action="CONFIG_UPDATED",
        target_resource="system_settings",
        details=updates,
    )

    return get_system_settings(db)
