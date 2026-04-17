"""Property-based tests for deterministic policy rules using hypothesis."""

from hypothesis import given, settings
from hypothesis import strategies as st

from vindicara.engine.rules.deterministic import (
    KeywordBlocklistRule,
    PIIDetectionRule,
    RegexRule,
)
from vindicara.sdk.types import Severity


class TestRegexRulePropertyBased:
    """Fuzz RegexRule with arbitrary inputs to verify it never crashes."""

    @given(text=st.text(min_size=0, max_size=10_000))
    @settings(max_examples=200)
    def test_regex_rule_never_crashes(self, text: str) -> None:
        rule = RegexRule(
            rule_id="test-regex",
            pattern=r"(?i)(password|secret)\s*[:=]\s*\S+",
            severity=Severity.CRITICAL,
            message="credential leak",
        )
        result = rule.evaluate(text)
        assert result.rule_id == "test-regex"
        assert isinstance(result.triggered, bool)

    @given(text=st.text(min_size=0, max_size=5_000))
    @settings(max_examples=200)
    def test_prompt_injection_regex_never_crashes(self, text: str) -> None:
        rule = RegexRule(
            rule_id="ignore-instructions",
            pattern=r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|above|prior)\s+(instructions?|prompts?|context)",
            severity=Severity.CRITICAL,
            message="injection detected",
        )
        result = rule.evaluate(text)
        assert isinstance(result.triggered, bool)

    @given(text=st.from_regex(r"password\s*[:=]\s*\S+", fullmatch=False))
    @settings(max_examples=100)
    def test_credential_pattern_always_triggers(self, text: str) -> None:
        rule = RegexRule(
            rule_id="cred-leak",
            pattern=r"(?i)(password|api[_\s]?key|secret[_\s]?key|token)\s*[:=]\s*\S+",
            severity=Severity.CRITICAL,
            message="credential leak",
        )
        result = rule.evaluate(text)
        assert result.triggered is True


class TestKeywordBlocklistPropertyBased:
    """Fuzz KeywordBlocklistRule with arbitrary inputs."""

    @given(text=st.text(min_size=0, max_size=10_000))
    @settings(max_examples=200)
    def test_keyword_rule_never_crashes(self, text: str) -> None:
        rule = KeywordBlocklistRule(
            rule_id="test-kw",
            keywords=["how to hack", "how to exploit", "how to bypass security"],
            severity=Severity.HIGH,
            message="harmful content",
        )
        result = rule.evaluate(text)
        assert isinstance(result.triggered, bool)

    @given(
        keyword=st.sampled_from(["how to hack", "how to exploit"]),
        prefix=st.text(min_size=0, max_size=100),
        suffix=st.text(min_size=0, max_size=100),
    )
    @settings(max_examples=100)
    def test_keyword_always_detected_when_present(self, keyword: str, prefix: str, suffix: str) -> None:
        text = prefix + keyword + suffix
        rule = KeywordBlocklistRule(
            rule_id="test-kw",
            keywords=["how to hack", "how to exploit"],
            severity=Severity.HIGH,
            message="harmful",
        )
        result = rule.evaluate(text)
        assert result.triggered is True

    @given(text=st.text(alphabet=st.characters(categories=("Nd",)), min_size=1, max_size=500))
    @settings(max_examples=100)
    def test_numeric_only_input_never_triggers(self, text: str) -> None:
        rule = KeywordBlocklistRule(
            rule_id="test-kw",
            keywords=["how to hack", "how to exploit"],
            severity=Severity.HIGH,
            message="harmful",
        )
        result = rule.evaluate(text)
        assert result.triggered is False


class TestPIIDetectionPropertyBased:
    """Fuzz PIIDetectionRule with arbitrary and adversarial inputs."""

    @given(text=st.text(min_size=0, max_size=10_000))
    @settings(max_examples=200)
    def test_pii_rule_never_crashes(self, text: str) -> None:
        rule = PIIDetectionRule(rule_id="pii-test", severity=Severity.CRITICAL)
        result = rule.evaluate(text)
        assert isinstance(result.triggered, bool)

    @given(
        ssn_area=st.integers(min_value=100, max_value=999),
        ssn_group=st.integers(min_value=10, max_value=99),
        ssn_serial=st.integers(min_value=1000, max_value=9999),
        sep=st.sampled_from(["-", " ", ""]),
    )
    @settings(max_examples=100)
    def test_ssn_pattern_always_detected(self, ssn_area: int, ssn_group: int, ssn_serial: int, sep: str) -> None:
        ssn = f"{ssn_area}{sep}{ssn_group}{sep}{ssn_serial}"
        text = f"The patient SSN is {ssn} on file."
        rule = PIIDetectionRule(rule_id="pii-test", severity=Severity.CRITICAL)
        result = rule.evaluate(text)
        assert result.triggered is True
        assert "SSN" in result.metadata.get("pii_types", "")

    @given(
        groups=st.tuples(
            st.integers(min_value=1000, max_value=9999),
            st.integers(min_value=1000, max_value=9999),
            st.integers(min_value=1000, max_value=9999),
            st.integers(min_value=1000, max_value=9999),
        ),
        sep=st.sampled_from(["-", " ", ""]),
    )
    @settings(max_examples=100)
    def test_credit_card_pattern_always_detected(self, groups: tuple[int, int, int, int], sep: str) -> None:
        cc = sep.join(str(g) for g in groups)
        text = f"Card: {cc}"
        rule = PIIDetectionRule(rule_id="pii-test", severity=Severity.CRITICAL)
        result = rule.evaluate(text)
        assert result.triggered is True
        assert "credit card" in result.metadata.get("pii_types", "")

    @given(text=st.text(alphabet="abcdefghijklmnopqrstuvwxyz ", min_size=1, max_size=500))
    @settings(max_examples=100)
    def test_alpha_only_never_triggers_pii(self, text: str) -> None:
        rule = PIIDetectionRule(rule_id="pii-test", severity=Severity.CRITICAL)
        result = rule.evaluate(text)
        assert result.triggered is False
