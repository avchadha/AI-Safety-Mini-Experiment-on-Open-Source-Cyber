import io
import json
import unittest
from unittest import mock

from cyberdetect.actor.model_client import OpenAICompatibleClient, _parse_choice


def _fake_response(payload: dict):
    body = json.dumps(payload).encode()
    resp = io.BytesIO(body)
    resp.__enter__ = lambda: resp  # type: ignore[attr-defined]
    resp.__exit__ = lambda *a: False  # type: ignore[attr-defined]
    return resp


class ModelClientTests(unittest.TestCase):
    def test_request_includes_user_agent_and_extra_body(self) -> None:
        client = OpenAICompatibleClient(
            base_url="https://example.invalid/v1",
            api_key="secret",
            model="test-model",
            revision="r",
            extra_body={"chat_template_kwargs": {"enable_thinking": False}},
        )
        captured = {}

        def fake_urlopen(request, timeout=0):
            captured["headers"] = {k.lower(): v for k, v in request.header_items()}
            captured["body"] = json.loads(request.data.decode())
            return _fake_response({"choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 1, "completion_tokens": 1}})

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            client.complete([{"role": "user", "content": "hi"}], None)

        self.assertEqual(captured["headers"].get("User-agent".lower()), "cyberdetect/0.1")
        self.assertNotIn("python-urllib", captured["headers"].get("User-agent".lower(), "").lower())
        self.assertEqual(captured["body"]["chat_template_kwargs"], {"enable_thinking": False})

    def test_extra_body_does_not_override_explicit_fields(self) -> None:
        client = OpenAICompatibleClient(
            base_url="https://example.invalid/v1",
            api_key="secret",
            model="test-model",
            revision="r",
            temperature=0.0,
            extra_body={"temperature": 0.9},  # must not clobber the configured value
        )
        captured = {}

        def fake_urlopen(request, timeout=0):
            captured["body"] = json.loads(request.data.decode())
            return _fake_response({"choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}], "usage": {}})

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            client.complete([{"role": "user", "content": "hi"}], None)
        self.assertEqual(captured["body"]["temperature"], 0.0)


if __name__ == "__main__":
    unittest.main()
