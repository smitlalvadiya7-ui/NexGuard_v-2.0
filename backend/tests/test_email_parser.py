"""
email_parser.parse_email — decode-failure handling (old ROADMAP Phase 2:
no bare excepts). A part that cannot be decoded is skipped and the rest of
the mail still parses, but only real errors are swallowed — a
KeyboardInterrupt during decode must propagate, never vanish.
"""

from unittest.mock import patch

import email.message

import email_parser


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_bytes(text.encode("utf-8"))
    return str(p)


def test_undecodable_part_is_skipped_but_good_parts_survive(tmp_path):
    eml = (
        "From: a@example.com\n"
        "Subject: mixed\n"
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/alternative; boundary="B"\n'
        "\n"
        "--B\n"
        'Content-Type: text/plain; charset="utf-8"\n'
        "\n"
        "readable body line\n"
        "--B\n"
        'Content-Type: text/plain; charset="x-no-such-charset"\n'
        "\n"
        "unreadable part\n"
        "--B--\n"
    )
    result = email_parser.parse_email(_write(tmp_path, "mixed.eml", eml))
    assert "readable body line" in result["body"]
    assert not result["body"].startswith("Email parse failed")


def test_decode_keyboard_interrupt_is_never_swallowed(tmp_path):
    eml = (
        "From: a@example.com\n"
        "Subject: plain\n"
        "\n"
        "hello\n"
    )
    path = _write(tmp_path, "plain.eml", eml)
    with patch.object(email.message.EmailMessage, "get_content",
                      side_effect=KeyboardInterrupt):
        try:
            email_parser.parse_email(path)
            swallowed = True
        except KeyboardInterrupt:
            swallowed = False
    assert not swallowed, "bare except swallowed KeyboardInterrupt"
