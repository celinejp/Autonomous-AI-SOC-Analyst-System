"""Organization profile API routes."""

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.database.postgres import get_db
from app.models.organization import OrganizationProfile
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()

_DEFAULT_PROFILE = OrganizationProfile(
    name="Default Organization",
    industry="technology",
    applicable_regulations=[],
    crown_jewels=[],
    risk_appetite="moderate",
    acceptable_downtime_hours={},
    incident_notification_contacts=[],
    internal_ip_ranges=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    trusted_domains=[],
    approved_cloud_services=[],
)


async def _load_from_db(db: AsyncSession) -> OrganizationProfile | None:
    """Load organization profile from database if table and row exist."""
    try:
        result = await db.execute(
            text("SELECT name, industry, regulations, risk_appetite, internal_ip_ranges, "
                 "trusted_domains, approved_cloud_services, crown_jewels, escalation_matrix, "
                 "notification_contacts, acceptable_downtime_hours, updated_at "
                 "FROM organization_profile LIMIT 1")
        )
        row = result.first()
        if not row:
            return None
        return OrganizationProfile(
            name=row.name or "Default",
            industry=row.industry or "technology",
            applicable_regulations=list(row.regulations or []),
            crown_jewels=row.crown_jewels or [],
            risk_appetite=row.risk_appetite or "moderate",
            acceptable_downtime_hours=dict(row.acceptable_downtime_hours or {}),
            incident_notification_contacts=row.notification_contacts or [],
            escalation_matrix=row.escalation_matrix,
            internal_ip_ranges=list(row.internal_ip_ranges or []),
            trusted_domains=list(row.trusted_domains or []),
            approved_cloud_services=list(row.approved_cloud_services or []),
            updated_at=row.updated_at,
        )
    except Exception:
        return None


async def _save_to_db(db: AsyncSession, profile: OrganizationProfile) -> None:
    """Upsert organization profile into database."""
    updated = datetime.utcnow()
    crown_jewels = [c.model_dump() if hasattr(c, "model_dump") else c for c in (profile.crown_jewels or [])]
    escalation = profile.escalation_matrix
    escalation_json = escalation.model_dump() if escalation and hasattr(escalation, "model_dump") else escalation
    contacts = [n.model_dump() if hasattr(n, "model_dump") else n for n in (profile.incident_notification_contacts or [])]
    await db.execute(
        text("""
            INSERT INTO organization_profile (
                name, industry, regulations, risk_appetite, internal_ip_ranges,
                trusted_domains, approved_cloud_services, crown_jewels,
                escalation_matrix, notification_contacts, acceptable_downtime_hours, updated_at
            ) VALUES (
                :name, :industry, :regulations, :risk_appetite, :internal_ip_ranges,
                :trusted_domains, :approved_cloud_services, :crown_jewels,
                :escalation_matrix, :notification_contacts, :acceptable_downtime_hours, :updated_at
            )
            ON CONFLICT (name) DO UPDATE SET
                industry = EXCLUDED.industry,
                regulations = EXCLUDED.regulations,
                risk_appetite = EXCLUDED.risk_appetite,
                internal_ip_ranges = EXCLUDED.internal_ip_ranges,
                trusted_domains = EXCLUDED.trusted_domains,
                approved_cloud_services = EXCLUDED.approved_cloud_services,
                crown_jewels = EXCLUDED.crown_jewels,
                escalation_matrix = EXCLUDED.escalation_matrix,
                notification_contacts = EXCLUDED.notification_contacts,
                acceptable_downtime_hours = EXCLUDED.acceptable_downtime_hours,
                updated_at = EXCLUDED.updated_at
        """),
        {
            "name": profile.name,
            "industry": profile.industry,
            "regulations": profile.applicable_regulations,
            "risk_appetite": profile.risk_appetite,
            "internal_ip_ranges": profile.internal_ip_ranges,
            "trusted_domains": profile.trusted_domains,
            "approved_cloud_services": profile.approved_cloud_services,
            "crown_jewels": crown_jewels,
            "escalation_matrix": escalation_json,
            "notification_contacts": contacts,
            "acceptable_downtime_hours": profile.acceptable_downtime_hours,
            "updated_at": updated,
        },
    )
    await db.commit()


@router.get("/profile")
async def get_organization_profile(db: AsyncSession = Depends(get_db)) -> OrganizationProfile:
    """Get organization profile for context-aware analysis."""
    loaded = await _load_from_db(db)
    if loaded is not None:
        return loaded
    return _DEFAULT_PROFILE


@router.put("/profile")
async def update_organization_profile(
    profile: OrganizationProfile,
    db: AsyncSession = Depends(get_db),
) -> OrganizationProfile:
    """Update organization profile."""
    from datetime import datetime
    profile.updated_at = datetime.utcnow()
    try:
        await _save_to_db(db, profile)
    except Exception as e:
        logger.warning("Could not persist organization profile to DB (table may not exist): %s", e)
    logger.info("Organization profile updated", profile_name=profile.name)
    return profile


@router.post("/profile")
async def create_organization_profile(
    profile: OrganizationProfile,
    db: AsyncSession = Depends(get_db),
) -> OrganizationProfile:
    """Create new organization profile."""
    return await update_organization_profile(profile, db)

