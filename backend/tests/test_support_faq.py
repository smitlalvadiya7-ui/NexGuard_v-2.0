"""
Built-in FAQ assistant (WORK_PLAN Task 12): a no-API-key helper that answers
questions about the NexGuard tools by keyword-scoring a curated FAQ. Real
Claude AI can be swapped in later; this must work offline with zero cost.
"""

from support_faq import FAQ, answer_question


def test_faq_has_entries_for_every_tool():
    topics = " ".join((e["question"] + " " + e["answer"]).lower() for e in FAQ)
    for tool in ("url", "qr", "email", "gmail", "voice", "screenshot", "batch"):
        assert tool in topics, tool


def test_matches_a_relevant_faq_with_confidence():
    res = answer_question("how does the voice scanner detect scam calls?")
    assert res["matched"] is True
    assert res["confidence"] >= 0.3
    assert "voice" in res["answer"].lower() or "call" in res["answer"].lower()
    assert res["question"]  # the matched FAQ question is returned


def test_verified_sender_question_matches_origin_faq():
    res = answer_question("what does verified sender mean on an email?")
    assert res["matched"] is True
    assert "sender" in res["answer"].lower()


def test_unrelated_question_falls_back_to_contact():
    res = answer_question("what is the capital of France?")
    assert res["matched"] is False
    assert "contact" in res["answer"].lower() or "support" in res["answer"].lower()
    assert res["confidence"] < 0.3


def test_empty_question_is_handled():
    res = answer_question("")
    assert res["matched"] is False


def test_related_suggestions_are_offered():
    res = answer_question("is my email safe")
    # a helpful bot offers a few other questions the user might mean
    assert isinstance(res["related"], list)
    assert len(res["related"]) >= 1
