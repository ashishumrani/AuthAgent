from gradio_client import Client
import requests

BASE = "http://localhost:7860"


def get_api_name():
    try:
        info = requests.get(f"{BASE}/gradio_api/info", timeout=5).json()
        keys = list(info.get("named_endpoints", {}).keys())
        if keys:
            return keys[0]
    except Exception:
        pass
    return "/gr_submit"


def parse(out):
    cleared = out[0] if len(out)>=1 else ""
    chat = out[1] if len(out)>=2 else []
    return cleared, chat


def test_org_variants_smoke():
    api = get_api_name()
    c = Client(BASE)
    variants = ["1stBank", "firstbank", "1st bank", "first bank", "First"]
    for v in variants:
        out = c.predict(f"I want to check_balance at {v}", [], {}, api_name=api)
        _, chat = parse(out)
        assert isinstance(chat, list) and len(chat) >= 1
        print(f"[PoC Variants] {v} → reply: ", chat[-1][1][:120])


if __name__ == "__main__":
    test_org_variants_smoke()
    print("Variants smoke test OK")


