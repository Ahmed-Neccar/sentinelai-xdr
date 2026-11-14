"""Rules for a new password, shared by sign-up, self-service change and administrator reset."""

import re

from app.core.errors import AppError

MIN_LENGTH = 12
MAX_LENGTH = 128

# Words people reach for first. Compared after dropping digits, case and punctuation, so
# "Password1234!" and "p@ssw0rd" style variants of these are refused too.
_COMMON_WORDS = {
    "password", "passw", "passwort", "passphrase", "letmein", "welcome", "qwerty", "qwertyuiop",
    "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm", "iloveyou", "administrator", "admin", "adminadmin",
    "changeme", "changemenow", "sentinel", "sentinelai", "sentinelxdr", "secret", "monkey",
    "dragon", "football", "baseball", "abcdef", "abcdefgh", "abcdefghijkl", "trustno",
    "sifre", "parola", "sifresifre", "parolaparola",
}  # fmt: skip


def check_new_password(
    password: str, *, email: str | None = None, current: str | None = None
) -> None:
    """Raise a 400 AppError with a message the person can act on when the password is weak."""
    if len(password) < MIN_LENGTH:
        raise AppError(
            400, "weak_password", f"Use at least {MIN_LENGTH} characters for the password"
        )
    if len(password) > MAX_LENGTH:
        raise AppError(400, "weak_password", f"Use at most {MAX_LENGTH} characters")
    if current is not None and password == current:
        raise AppError(400, "weak_password", "Choose a password different from the current one")
    if len(set(password)) < 6:
        raise AppError(400, "weak_password", "The password repeats too few different characters")
    has_letter = any(ch.isalpha() for ch in password)
    has_other = any(not ch.isalpha() for ch in password)
    mixed_case = any(ch.islower() for ch in password) and any(ch.isupper() for ch in password)
    if not has_letter or not (has_other or mixed_case):
        raise AppError(400, "weak_password", "Mix letters with digits or symbols")
    letters = re.sub(r"[^a-z]", "", password.lower())
    if letters in _COMMON_WORDS:
        raise AppError(400, "weak_password", "That password is too easy to guess")
    if email:
        local = email.split("@", 1)[0].lower()
        if len(local) >= 3 and local in password.lower():
            raise AppError(400, "weak_password", "The password must not contain the account name")
