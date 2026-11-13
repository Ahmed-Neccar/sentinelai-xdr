import re

from app.api.v1.auth import LoginRequest
from app.api.v1.users import UserCreate
from app.response.enrollment import SENSOR_DOMAIN, account_slug, new_sensor_login


def test_slug_is_safe_whatever_the_computer_is_called() -> None:
    assert account_slug("Muhasebe PC #2") == "muhasebe-pc-2"
    assert account_slug("  Ahmed'in Dizüstü  ") == "ahmed-in-diz-st"
    assert account_slug("../../etc/passwd") == "etc-passwd"
    assert account_slug("@@@") == "computer"
    assert len(account_slug("x" * 200)) == 24
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", account_slug("a  --  b"))


def test_generated_login_is_unique_strong_and_accepted_by_the_api_schemas() -> None:
    first_email, first_password = new_sensor_login("Lab PC")
    second_email, second_password = new_sensor_login("Lab PC")
    assert first_email != second_email and first_password != second_password
    assert first_email.startswith("sensor-lab-pc-") and first_email.endswith("@" + SENSOR_DOMAIN)
    assert len(first_password) >= 40
    # The same values must pass the validation used at account creation and sign-in.
    UserCreate(email=first_email, password=first_password, roles=["ingestion_service"])
    LoginRequest(email=first_email, password=first_password)
