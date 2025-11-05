from gradio_client import Client
import requests

BASE = "http://localhost:7860"


def get_api_name(base_url: str) -> str:
    try:
        info = requests.get(f"{base_url}/gradio_api/info", timeout=5).json()
        keys = list(info.get("named_endpoints", {}).keys())
        if keys:
            return keys[0]
    except Exception:
        pass
    return "/gr_submit"


def test_support_message_for_first():
    api = get_api_name(BASE)
    c = Client(BASE)
    out = c.predict("I want to check_balance at First", [], {}, api_name=api)
    chat = out[1]
    assert isinstance(chat, list) and len(chat) >= 1
    last_bot = chat[-1][1]
    assert isinstance(last_bot, str) and last_bot.strip() != ""
    print("[PoC] Context reply:\n", last_bot[:300])


if __name__ == "__main__":
    test_support_message_for_first()
    print("Chat context (PoC) OK")


