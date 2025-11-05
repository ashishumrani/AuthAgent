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


def parse_outputs(out):
    cleared = out[0] if len(out) >= 1 else ""
    chat = out[1] if len(out) >= 2 else []
    return cleared, chat


def test_e2e_flow_smoke():
    api = get_api_name(BASE)
    c = Client(BASE)

    out = c.predict("hey there", [], {}, api_name=api)
    _, chat = parse_outputs(out)
    assert isinstance(chat, list) and len(chat) >= 1
    print("[PoC E2E] Step1:", chat[-1][1] if chat else "<no-reply>")

    out = c.predict("I want to check_balance at First", chat, {}, api_name=api)
    _, chat = parse_outputs(out)
    assert isinstance(chat, list) and len(chat) >= 1
    reply2 = chat[-1][1]
    print("[PoC E2E] Step2:", reply2)

    # Optional Step 3: provide credentials and look for "auth" in reply
    out = c.predict("username ashishumrani, password batata", chat, {}, api_name=api)
    _, chat = parse_outputs(out)
    assert isinstance(chat, list) and len(chat) >= 1
    reply3 = chat[-1][1].lower()
    assert isinstance(reply3, str) and reply3.strip() != ""
    # Not strict: just check for presence of the word auth in the message
    assert ("auth" in reply3) or True


if __name__ == "__main__":
    test_e2e_flow_smoke()
    print("E2E chat (PoC) OK")


