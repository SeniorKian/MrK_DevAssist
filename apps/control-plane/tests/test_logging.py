from mrk_control_plane.logging_config import redact_text


def test_redact_text_removes_common_secret_shapes() -> None:
    value = (
        "Authorization: Bearer abc.def.ghi "
        "password=super-secret token: mrk_abcdefghijklmnopqrstuvwxyz "
        "https://alice:private@example.com/path"
    )
    redacted = redact_text(value)

    assert "abc.def.ghi" not in redacted
    assert "super-secret" not in redacted
    assert "abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "alice:private" not in redacted
    assert redacted.count("[REDACTED]") >= 4
