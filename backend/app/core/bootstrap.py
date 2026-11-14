from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.permissions import ALL_ROLES
from app.core.security import hash_password
from app.db.session import set_organization_context
from app.detection.builtin_rules import BUILTIN_RULES
from app.models import DetectionRule, DetectionRuleVersion, Organization, Role, User, UserRole


def seed_roles(db: Session) -> None:
    existing = {role.name for role in db.scalars(select(Role)).all()}
    descriptions = {
        "administrator": "Full control of users, rules, and settings",
        "analyst": "Investigate events, detections, and cases; ingest data",
        "auditor": "Read-only access including audit logs",
        "ingestion_service": "Machine account limited to ingestion",
    }
    for name in ALL_ROLES:
        if name not in existing:
            db.add(Role(name=name, description=descriptions.get(name, "")))
    db.flush()


def seed_rules(db: Session) -> None:
    existing = {rule.rule_id: rule for rule in db.scalars(select(DetectionRule)).all()}
    for spec in BUILTIN_RULES:
        version = spec.get("version", 1)
        rule = existing.get(spec["rule_id"])
        if rule is not None:
            if rule.current_version >= version:
                continue
            rule.title = spec["title"]
            rule.description = spec["description"]
            rule.current_version = version
            existing_version = db.scalar(
                select(DetectionRuleVersion.id).where(
                    DetectionRuleVersion.rule_pk == rule.id,
                    DetectionRuleVersion.version == version,
                )
            )
            if existing_version is None:
                db.add(
                    DetectionRuleVersion(
                        rule_pk=rule.id,
                        version=version,
                        severity=spec["severity"],
                        spec=spec,
                    )
                )
            continue
        rule = DetectionRule(
            rule_id=spec["rule_id"],
            title=spec["title"],
            description=spec["description"],
            enabled=spec.get("default_enabled", True),
            current_version=version,
        )
        db.add(rule)
        db.flush()
        db.add(
            DetectionRuleVersion(
                rule_pk=rule.id,
                version=version,
                severity=spec["severity"],
                spec=spec,
            )
        )


def bootstrap_admin(db: Session) -> None:
    if db.scalar(select(User).limit(1)):
        return
    if not settings.bootstrap_admin_email or not settings.bootstrap_admin_password:
        return
    admin_role = db.scalar(select(Role).where(Role.name == "administrator"))
    user = User(
        organization_id=db.info["organization_id"],
        email=settings.bootstrap_admin_email.lower(),
        hashed_password=hash_password(settings.bootstrap_admin_password),
        full_name="Bootstrap Administrator",
        is_active=True,
    )
    db.add(user)
    db.flush()
    if admin_role:
        db.add(UserRole(user_id=user.id, role_id=admin_role.id))


def initialize_data(db: Session) -> None:
    seed_roles(db)
    organization = db.scalar(
        select(Organization).where(Organization.slug == settings.default_organization_slug)
    )
    if organization is None:
        organization = Organization(
            slug=settings.default_organization_slug,
            name=settings.default_organization_name,
        )
        db.add(organization)
        db.flush()
    if not organization.is_active:
        raise RuntimeError("The configured default organization is inactive")
    set_organization_context(db, organization.id)
    seed_rules(db)
    bootstrap_admin(db)
    db.commit()


if __name__ == "__main__":
    from app.db.session import SessionLocal

    session = SessionLocal()
    try:
        initialize_data(session)
        print("Bootstrap complete")
    finally:
        session.close()
