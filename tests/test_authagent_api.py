import requests
from gradio_client import Client


def get_api_name(base_url: str) -> str:
    try:
        info = requests.get(f"{base_url}/gradio_api/info", timeout=5).json()
        keys = list(info.get("named_endpoints", {}).keys())
        if keys:
            return keys[0]
    except Exception:
        pass
    return "/gr_submit"


def test_authagent_basic_flow():
    base = "http://localhost:7860"
    api = get_api_name(base)
    client = Client(base)

    message = "I want to check_balance at First"
    out = client.predict(message, [], {}, api_name=api)
    assert isinstance(out, (list, tuple)) and len(out) >= 2
    chat = out[1]
    assert isinstance(chat, list) and len(chat) >= 1
    last_bot = chat[-1][1]
    assert isinstance(last_bot, str) and last_bot.strip() != ""
    print("[PoC] AuthAgent reply:\n", last_bot[:300])


if __name__ == "__main__":
    test_authagent_basic_flow()
    print("AuthAgent basic API (PoC) OK")


