import pytest
from app.core.mfa import (
    decrypt_totp_secret,
    encrypt_totp_secret,
    find_recovery_code,
    generate_recovery_codes,
    recovery_code_hash,
    totp_counter,
)
from cryptography.exceptions import InvalidTag


def test_totp_matches_rfc_6238_sha1_vector() -> None:
    # RFC 6238 Appendix B, SHA1, T=59 seconds.
    totp_key = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert totp_counter("287082", totp_key, timestamp=59) == 1
    assert totp_counter("287082", totp_key, timestamp=59 + 30) == 1
    assert totp_counter("287082", totp_key, timestamp=59 + 60) is None


def test_totp_secret_is_encrypted_and_tamper_evident() -> None:
    totp_key = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    ciphertext = encrypt_totp_secret(totp_key)
    assert ciphertext != totp_key
    assert decrypt_totp_secret(ciphertext) == totp_key
    damaged = ciphertext[:-4] + "AAAA"
    with pytest.raises(InvalidTag):
        decrypt_totp_secret(damaged)


def test_recovery_codes_are_random_hashed_and_one_time_lookupable() -> None:
    codes = generate_recovery_codes()
    hashes = [recovery_code_hash(code) for code in codes]
    assert len(codes) == 10
    assert len(set(codes)) == len(codes)
    assert all(code not in hashes for code in codes)
    assert find_recovery_code(codes[0].replace("-", " "), hashes) == 0
    assert find_recovery_code("NOT-A-VALID-CODE", hashes) is None
