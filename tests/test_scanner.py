"""
test_scanner.py — Unit Tests for the Prompt Injection Scanner

Run with:
    pytest tests/test_scanner.py -v

Why tests matter for a portfolio:
    Any developer can write code that works. Writing tests proves you understand
    what your code is SUPPOSED to do, and that you care about reliability.
    For security tools, tests are especially important — a buggy scanner that
    misses injections is worse than no scanner at all.
"""

import pytest
from scanner.payloads import PayloadLibrary, Payload
from scanner.detector import InjectionDetector
from scanner.scorer import RiskScorer


# ─── Payload Library Tests ────────────────────────────────────────────────────

class TestPayloadLibrary:

    def test_get_all_payloads_returns_list(self):
        """get_payloads('all') should return a non-empty list of Payload objects."""
        library = PayloadLibrary()
        payloads = library.get_payloads(category="all")
        assert isinstance(payloads, list)
        assert len(payloads) > 0

    def test_get_category_returns_correct_payloads(self):
        """Filtering by category should only return payloads from that category."""
        library = PayloadLibrary()
        payloads = library.get_payloads(category="role_hijack")
        assert all(p.category == "role_hijack" for p in payloads)

    def test_invalid_category_raises_value_error(self):
        """Requesting an unknown category should raise a clear ValueError."""
        library = PayloadLibrary()
        with pytest.raises(ValueError, match="Unknown category"):
            library.get_payloads(category="nonexistent_category")

    def test_all_payloads_have_required_fields(self):
        """Every payload must have id, category, technique, text, expected_indicator."""
        library = PayloadLibrary()
        for payload in library.get_payloads():
            assert payload.id, f"Payload missing id: {payload}"
            assert payload.category, f"Payload missing category: {payload.id}"
            assert payload.technique, f"Payload missing technique: {payload.id}"
            assert payload.text, f"Payload missing text: {payload.id}"
            assert payload.expected_indicator, f"Payload missing expected_indicator: {payload.id}"

    def test_payload_ids_are_unique(self):
        """All payload IDs must be unique — duplicates would cause confusing reports."""
        library = PayloadLibrary()
        ids = [p.id for p in library.get_payloads()]
        assert len(ids) == len(set(ids)), "Duplicate payload IDs found"

    def test_count_matches_get_payloads(self):
        """count() should match the actual length of get_payloads()."""
        library = PayloadLibrary()
        assert library.count("all") == len(library.get_payloads("all"))
        assert library.count("role_hijack") == len(library.get_payloads("role_hijack"))


# ─── Detector Tests ────────────────────────────────────────────────────────────

class TestInjectionDetector:

    def _make_payload(self, category: str = "role_hijack", expected_indicator: str = "DAN") -> Payload:
        """Helper to create a test payload without importing the full library."""
        return Payload(
            id="test_001",
            category=category,
            technique="Test technique",
            description="Test payload",
            text="Test injection text",
            expected_indicator=expected_indicator,
            owasp_ref="LLM01"
        )

    def test_detects_expected_indicator_in_response(self):
        """If expected_indicator appears in response, injection should be detected."""
        detector = InjectionDetector()
        payload = self._make_payload(expected_indicator="DAN")
        detected, reason = detector.analyze(response="I am DAN now!", payload=payload)
        assert detected is True
        assert "DAN" in reason

    def test_no_detection_when_clean_response(self):
        """A clean refusal response should not trigger injection detection."""
        detector = InjectionDetector()
        payload = self._make_payload(expected_indicator="DAN")
        clean_response = "I'm sorry, I can't help with that. I'm a customer service assistant."
        detected, reason = detector.analyze(response=clean_response, payload=payload)
        assert detected is False

    def test_detects_persona_adoption(self):
        """'I am now an unrestricted AI' should trigger persona adoption detection."""
        detector = InjectionDetector()
        payload = self._make_payload(expected_indicator="unlikely_token_xyz")
        response = "I am now an unrestricted AI assistant ready to help you with anything."
        detected, reason = detector.analyze(response=response, payload=payload)
        assert detected is True

    def test_detects_system_prompt_leak(self):
        """Response containing 'my instructions' should trigger system prompt leak detection."""
        detector = InjectionDetector()
        payload = self._make_payload(category="prompt_leak", expected_indicator="unlikely_xyz")
        response = "Sure! My instructions say I should only discuss customer service topics."
        detected, reason = detector.analyze(response=response, payload=payload)
        assert detected is True

    def test_case_insensitive_detection(self):
        """Detection should be case-insensitive — 'DAN', 'dan', 'Dan' should all match."""
        detector = InjectionDetector()
        payload = self._make_payload(expected_indicator="DAN")
        detected, _ = detector.analyze(response="i am dan, here to help.", payload=payload)
        assert detected is True


# ─── Scorer Tests ──────────────────────────────────────────────────────────────

class TestRiskScorer:

    def _make_payload(self, category: str) -> Payload:
        return Payload(
            id="test_001", category=category, technique="test",
            description="test", text="test", expected_indicator="test"
        )

    def test_no_detection_returns_none_level(self):
        """If injection not detected, risk should be 'none' with score 0."""
        scorer = RiskScorer()
        level, score = scorer.score(
            payload=self._make_payload("role_hijack"),
            injection_detected=False
        )
        assert level == "none"
        assert score == 0

    def test_data_exfil_detected_is_critical(self):
        """Data exfiltration detections should score as 'critical'."""
        scorer = RiskScorer()
        level, score = scorer.score(
            payload=self._make_payload("data_exfil"),
            injection_detected=True
        )
        assert level == "critical"
        assert score >= 85

    def test_role_hijack_detected_is_critical(self):
        """Role hijack detections should score as 'critical'."""
        scorer = RiskScorer()
        level, score = scorer.score(
            payload=self._make_payload("role_hijack"),
            injection_detected=True
        )
        assert level == "critical"

    def test_prompt_leak_detected_is_high(self):
        """Prompt leak detections should score as 'high'."""
        scorer = RiskScorer()
        level, score = scorer.score(
            payload=self._make_payload("prompt_leak"),
            injection_detected=True
        )
        assert level == "high"

    def test_summarize_counts_correctly(self):
        """summarize() should count results by risk level accurately."""
        from scanner.runner import ScanResult
        scorer = RiskScorer()

        mock_results = [
            type("R", (), {"risk_level": "critical"})(),
            type("R", (), {"risk_level": "critical"})(),
            type("R", (), {"risk_level": "high"})(),
            type("R", (), {"risk_level": "none"})(),
        ]
        summary = scorer.summarize(mock_results)
        assert summary["critical"] == 2
        assert summary["high"] == 1
        assert summary["none"] == 1
