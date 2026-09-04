"""Tests for the ledger scrubber."""

from guardrail_cascade.scrub import scrub, scrub_text


def test_masks_email():
    assert scrub_text("reach me at john.doe@example.com now") == "reach me at [EMAIL] now"


def test_masks_phone_ssn_and_card():
    assert "[PHONE]" in scrub_text("call 555-123-4567")
    assert "[SSN]" in scrub_text("ssn 123-45-6789")
    assert "[CARD]" in scrub_text("card 4111-1111-1111-1111")


def test_masks_secret_shapes():
    assert scrub_text("key AKIAIOSFODNN7EXAMPLE") == "key [SECRET]"
    assert scrub_text("token " + "ghp_" + "a" * 36) == "token [SECRET]"
    assert scrub_text("-----BEGIN RSA PRIVATE KEY-----") == "[SECRET]"


def test_masks_jwt_stripe_and_aws_secret_key():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"
    assert scrub_text("bearer " + jwt) == "bearer [SECRET]"
    assert scrub_text("sk_live_4eC39HqLyjWDarjt") == "[SECRET]"
    # The name that introduces the key stays, because it is the only reason the
    # 40 characters after it are readable as a key at all.
    masked = scrub_text("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    assert masked == "aws_secret_access_key = [SECRET]"


def test_leaves_a_lone_base64_blob_alone():
    # Forty base64 characters with no key name beside them are as likely to be a
    # hash or an id, and the log is more useful with them in it.
    text = "digest YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWY="
    assert scrub_text(text) == text


def test_leaves_clean_text_untouched():
    text = "the quarterly report is ready for review"
    assert scrub_text(text) == text


def test_scrub_walks_nested_structures():
    value = {
        "reason": "found a@b.com",
        "detail": {"note": "key AKIAIOSFODNN7EXAMPLE", "labels": ["EMAIL"]},
        "items": ["ping 555-123-4567", "clean"],
    }
    scrubbed = scrub(value)
    assert scrubbed["reason"] == "found [EMAIL]"
    assert scrubbed["detail"]["note"] == "key [SECRET]"
    assert scrubbed["detail"]["labels"] == ["EMAIL"]  # a label is not a raw value
    assert scrubbed["items"] == ["ping [PHONE]", "clean"]


def test_scrub_walks_tuples_and_keeps_the_type():
    scrubbed = scrub(("mail a@b.com", "clean", {"note": "key AKIAIOSFODNN7EXAMPLE"}))
    assert isinstance(scrubbed, tuple)
    assert scrubbed == ("mail [EMAIL]", "clean", {"note": "key [SECRET]"})


def test_scrub_leaves_non_strings_intact():
    value = {"count": 3, "rate": 0.5, "ok": True, "missing": None}
    assert scrub(value) == value
