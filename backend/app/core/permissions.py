ADMIN = "administrator"
ANALYST = "analyst"
AUDITOR = "auditor"
INGESTION = "ingestion_service"

ALL_ROLES = (ADMIN, ANALYST, AUDITOR, INGESTION)

READ_EVENTS = {ADMIN, ANALYST, AUDITOR}
INGEST = {ADMIN, ANALYST, INGESTION}
MUTATE_CASES = {ADMIN, ANALYST}
MANAGE_RULES = {ADMIN}
MANAGE_USERS = {ADMIN}
READ_AUDIT = {ADMIN, AUDITOR}
MANAGE_SETTINGS = {ADMIN}


def has_any(user_roles: list[str], allowed: set[str]) -> bool:
    return bool(set(user_roles) & allowed)
