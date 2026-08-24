from __future__ import annotations

import unittest

from projects.waf_guard import HTTPRequest, build_default_policy


class WAFGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = build_default_policy()

    def test_allows_a_normal_catalog_request(self) -> None:
        decision = self.policy.evaluate(
            HTTPRequest(
                method="GET",
                path="/catalog/items",
                query="category=books&page=2",
                headers={"User-Agent": "Mozilla/5.0"},
            )
        )
        self.assertEqual("ALLOW", decision.action)
        self.assertLess(decision.risk_score, 0.42)
        self.assertIn("No configured high-risk indicators detected", decision.reasons)

    def test_blocks_path_traversal(self) -> None:
        decision = self.policy.evaluate(HTTPRequest(method="GET", path="/files/../../private/notes"))
        self.assertEqual("BLOCK", decision.action)
        self.assertTrue(decision.features["path_traversal"])
        self.assertIn("path traversal sequence detected", decision.reasons)

    def test_blocks_sql_like_query_and_explains_it(self) -> None:
        decision = self.policy.evaluate(HTTPRequest(method="GET", path="/records", query="id=1 OR 1=1"))
        self.assertEqual("BLOCK", decision.action)
        self.assertTrue(decision.features["sql_syntax"])
        benign_probability = self.policy.evaluate(HTTPRequest(method="GET", path="/records")).model_probability
        self.assertGreater(decision.model_probability, benign_probability)
        self.assertGreaterEqual(decision.risk_score, 0.9)

    def test_serializable_decision_has_explanation_fields(self) -> None:
        decision = self.policy.evaluate(HTTPRequest(method="TRACE", path="/status"))
        payload = decision.to_dict()
        self.assertEqual({"action", "risk_score", "model_probability", "reasons", "features"}, set(payload))
        self.assertTrue(payload["features"]["unusual_method"])


if __name__ == "__main__":
    unittest.main()
