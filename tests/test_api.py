import unittest
import json
from io import BytesIO
from server import PromptWarsHandler

class DummyServer:
    def __init__(self):
        pass

class DummyRequest:
    def __init__(self, request_bytes):
        self.rfile = BytesIO(request_bytes)
        self.wfile = BytesIO()

    def makefile(self, mode, *args, **kwargs):
        if 'r' in mode:
            return self.rfile
        elif 'w' in mode or 'b' in mode:
            return self.wfile

class TestServerLogic(unittest.TestCase):
    def test_handler_sanitization(self):
        from core.security import sanitize_input
        self.assertEqual(sanitize_input("test\x00"), "test")

    def test_api_analyze_dispatch(self):
        from core.analyzer import analyze_prompt
        res = analyze_prompt("You are a helpful coding assistant.", "developer")
        self.assertIn("scores", res)
        self.assertIn("overall_elo", res["scores"])
        self.assertEqual(res["persona_applied"], "developer")

    def test_api_battle_dispatch(self):
        from core.adversary import conduct_prompt_battle
        res = conduct_prompt_battle("You are an assistant.")
        self.assertIn("verdict", res)
        self.assertEqual(len(res["battle_rounds"]), 5)

    def test_api_optimize_dispatch(self):
        from core.optimizer import optimize_prompt
        res = optimize_prompt("Help me calculate tax.", "developer")
        self.assertIn("hardened_prompt", res)
        self.assertIn("improvements", res)

if __name__ == "__main__":
    unittest.main()
