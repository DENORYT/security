"""Small, explainable request-risk model for a defensive WAF exercise.

The model is deliberately local and transparent. It is not a reverse proxy and
must not be treated as a production WAF.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import math
import re
from typing import Mapping
from urllib.parse import unquote_plus

FEATURE_NAMES = (
    "sql_syntax",
    "xss_marker",
    "path_traversal",
    "sensitive_path_probe",
    "encoded_payload",
    "unusual_method",
    "automation_fingerprint",
)

_REASON_LABELS = {
    "sql_syntax": "SQL-like query syntax detected",
    "xss_marker": "script-like markup detected",
    "path_traversal": "path traversal sequence detected",
    "sensitive_path_probe": "sensitive application path requested",
    "encoded_payload": "heavily encoded request content detected",
    "unusual_method": "unusual HTTP method for an application endpoint",
    "automation_fingerprint": "automated scanner-like user agent detected",
}

_SQL_PATTERN = re.compile(
    r"(?:\bunion\s+(?:all\s+)?select\b|\binformation_schema\b|\bdrop\s+table\b|\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
    re.IGNORECASE,
)
_XSS_PATTERN = re.compile(r"(?:<\s*script\b|on(?:error|load|click)\s*=|javascript\s*:)", re.IGNORECASE)
_SENSITIVE_PATH_PATTERN = re.compile(r"(?:^|/)(?:\.git|\.env|wp-admin|phpmyadmin|server-status)(?:/|$)", re.IGNORECASE)
_AUTOMATION_PATTERN = re.compile(r"(?:sqlmap|nikto|nmap|masscan|zgrab|curl/7\.)", re.IGNORECASE)


@dataclass(frozen=True)
class HTTPRequest:
    """A minimal HTTP request representation that can be supplied as JSON."""

    method: str
    path: str
    query: str = ""
    headers: Mapping[str, str] = field(default_factory=dict)
    body: str = ""

    def inspection_text(self) -> str:
        header_text = " ".join(f"{key}: {value}" for key, value in self.headers.items())
        # Bound inspection work and avoid holding unexpectedly large request bodies.
        return " ".join((self.path, self.query, header_text, self.body[:16_384]))


@dataclass(frozen=True)
class Decision:
    action: str
    risk_score: float
    model_probability: float
    reasons: tuple[str, ...]
    features: Mapping[str, bool]

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["reasons"] = list(self.reasons)
        result["features"] = dict(self.features)
        return result


class BernoulliRiskModel:
    """A tiny Bernoulli Naive Bayes classifier with explainable contributions."""

    def __init__(self, feature_probabilities: Mapping[bool, Mapping[str, float]], priors: Mapping[bool, float]) -> None:
        self._feature_probabilities = feature_probabilities
        self._priors = priors

    @classmethod
    def from_training_rows(
        cls,
        rows: list[tuple[Mapping[str, bool], bool]],
        malicious_base_rate: float = 0.03,
    ) -> "BernoulliRiskModel":
        if not rows:
            raise ValueError("At least one training row is required")
        if not 0 < malicious_base_rate < 0.5:
            raise ValueError("malicious_base_rate must be between 0 and 0.5")
        counts = {False: 0, True: 0}
        positive_counts = {False: {name: 0 for name in FEATURE_NAMES}, True: {name: 0 for name in FEATURE_NAMES}}
        for feature_row, label in rows:
            counts[label] += 1
            for name in FEATURE_NAMES:
                positive_counts[label][name] += int(bool(feature_row.get(name, False)))

        probabilities: dict[bool, dict[str, float]] = {False: {}, True: {}}
        for label in (False, True):
            # Laplace smoothing avoids zero likelihoods on small, curated data.
            probabilities[label] = {
                name: (positive_counts[label][name] + 1) / (counts[label] + 2)
                for name in FEATURE_NAMES
            }
        # Curated training rows are intentionally balanced enough to teach each
        # signal, not to represent production traffic. Use a conservative
        # operational base rate instead of inheriting that artificial balance.
        priors = {True: malicious_base_rate, False: 1 - malicious_base_rate}
        return cls(probabilities, priors)

    def probability_malicious(self, features: Mapping[str, bool]) -> tuple[float, dict[str, float]]:
        scores: dict[bool, float] = {}
        contributions: dict[str, float] = {}
        for label in (False, True):
            score = math.log(self._priors[label])
            for name in FEATURE_NAMES:
                probability = self._feature_probabilities[label][name]
                score += math.log(probability if features.get(name, False) else 1 - probability)
            scores[label] = score

        for name in FEATURE_NAMES:
            value = bool(features.get(name, False))
            malicious_p = self._feature_probabilities[True][name]
            benign_p = self._feature_probabilities[False][name]
            contributions[name] = math.log(
                (malicious_p if value else 1 - malicious_p) / (benign_p if value else 1 - benign_p)
            )

        # Numerically stable conversion of two log-probabilities into P(malicious).
        normalizer = max(scores.values())
        malicious = math.exp(scores[True] - normalizer)
        benign = math.exp(scores[False] - normalizer)
        return malicious / (malicious + benign), contributions


def extract_features(request: HTTPRequest) -> dict[str, bool]:
    """Extract intentionally reviewable binary signals from a request."""

    text = request.inspection_text()
    decoded = unquote_plus(text)
    lowered = decoded.lower()
    percent_escapes = len(re.findall(r"%[0-9a-fA-F]{2}", text))
    user_agent = next((value for key, value in request.headers.items() if key.lower() == "user-agent"), "")

    return {
        "sql_syntax": bool(_SQL_PATTERN.search(decoded)),
        "xss_marker": bool(_XSS_PATTERN.search(decoded)),
        "path_traversal": "../" in decoded or "..\\" in decoded or "%2e%2e" in lowered,
        "sensitive_path_probe": bool(_SENSITIVE_PATH_PATTERN.search(request.path)),
        "encoded_payload": percent_escapes >= 5,
        "unusual_method": request.method.upper() in {"TRACE", "CONNECT"},
        "automation_fingerprint": bool(_AUTOMATION_PATTERN.search(user_agent)),
    }


def _training_rows() -> list[tuple[Mapping[str, bool], bool]]:
    normal = {name: False for name in FEATURE_NAMES}
    return [
        (normal, False),
        ({**normal, "encoded_payload": True}, False),
        ({**normal, "automation_fingerprint": True}, False),
        ({**normal, "sql_syntax": True}, True),
        ({**normal, "xss_marker": True}, True),
        ({**normal, "path_traversal": True}, True),
        ({**normal, "sensitive_path_probe": True}, True),
        ({**normal, "encoded_payload": True, "automation_fingerprint": True}, True),
        ({**normal, "sql_syntax": True, "encoded_payload": True}, True),
        ({**normal, "unusual_method": True, "sensitive_path_probe": True}, True),
    ]


class WAFPolicy:
    """Combine the classifier with conservative, easy-to-audit policy gates."""

    def __init__(self, model: BernoulliRiskModel, challenge_threshold: float = 0.42, block_threshold: float = 0.78) -> None:
        if not 0 < challenge_threshold < block_threshold < 1:
            raise ValueError("Thresholds must satisfy 0 < challenge < block < 1")
        self._model = model
        self._challenge_threshold = challenge_threshold
        self._block_threshold = block_threshold

    def evaluate(self, request: HTTPRequest) -> Decision:
        features = extract_features(request)
        model_probability, contributions = self._model.probability_malicious(features)
        detected = [name for name in FEATURE_NAMES if features[name]]
        # Fixed guardrail weights keep high-confidence signatures actionable
        # even when a deliberately small training set has sparse examples.
        guardrail_weights = {
            "sql_syntax": 0.92,
            "xss_marker": 0.65,
            "path_traversal": 0.90,
            "sensitive_path_probe": 0.62,
            "encoded_payload": 0.24,
            "unusual_method": 0.30,
            "automation_fingerprint": 0.18,
        }
        rule_score = min(1.0, sum(guardrail_weights[name] for name in detected))
        risk_score = max(model_probability, rule_score)

        hard_block = features["sql_syntax"] or features["path_traversal"]
        if hard_block or risk_score >= self._block_threshold:
            action = "BLOCK"
        elif risk_score >= self._challenge_threshold:
            action = "CHALLENGE"
        else:
            action = "ALLOW"

        reasons = tuple(_REASON_LABELS[name] for name in detected)
        if not reasons:
            reasons = ("No configured high-risk indicators detected",)
        return Decision(
            action=action,
            risk_score=round(risk_score, 4),
            model_probability=round(model_probability, 4),
            reasons=reasons,
            features=features,
        )


def build_default_policy() -> WAFPolicy:
    """Create the reproducible policy used by the CLI and tests."""

    return WAFPolicy(BernoulliRiskModel.from_training_rows(_training_rows()))
