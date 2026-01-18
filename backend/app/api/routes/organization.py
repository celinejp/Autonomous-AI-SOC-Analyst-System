"""Organization profile API routes."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.postgres import get_db
from app.models.organization import OrganizationProfile
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()


# In-memory storage for demo (replace with database in production)
_organization_profile: OrganizationProfile | None = None


@router.get("/profile")
async def get_organization_profile() -> OrganizationProfile:
    """Get organization profile for context-aware analysis."""
    global _organization_profile
    
    if _organization_profile is None:
        # Return default profile if none exists
        return OrganizationProfile(
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
    
    return _organization_profile


@router.put("/profile")
async def update_organization_profile(
    profile: OrganizationProfile,
    db: AsyncSession = Depends(get_db),
) -> OrganizationProfile:
    """Update organization profile."""
    global _organization_profile
    
    try:
        # In production, save to database
        # For now, store in memory
        from datetime import datetime
        profile.updated_at = datetime.utcnow()
        _organization_profile = profile
        
        # TODO: Save to database
        # org_repo = OrganizationRepository(db)
        # await org_repo.save(profile)
        
        logger.info("Organization profile updated", profile_name=profile.name)
        
        return profile
    except Exception as e:
        logger.error(f"Failed to update organization profile: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/profile")
async def create_organization_profile(
    profile: OrganizationProfile,
    db: AsyncSession = Depends(get_db),
) -> OrganizationProfile:
    """Create new organization profile."""
    return await update_organization_profile(profile, db)

