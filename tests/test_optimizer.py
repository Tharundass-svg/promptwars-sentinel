import unittest
from core.optimizer import optimize_prompt

class TestOptimizer(unittest.TestCase):
    def test_optimize_empty(self):
        res = optimize_prompt("")
        self.assertIn("error", res)

    def test_optimize_prompt_hardening(self):
        raw = "Write a python script that connects to database."
        res = optimize_prompt(raw, persona="developer")
        
        self.assertIn("hardened_prompt", res)
        self.assertIn("IMMUTABLE SYSTEM INSTRUCTION", res["hardened_prompt"])
        self.assertIn("<user_input>", res["hardened_prompt"])
        self.assertGreater(len(res["improvements"]), 0)
        
        # Optimized prompt must score higher in Elo than original
        self.assertGreaterEqual(
            res["after_scores"]["overall_elo"],
            res["before_scores"]["overall_elo"]
        )

if __name__ == "__main__":
    unittest.main()
