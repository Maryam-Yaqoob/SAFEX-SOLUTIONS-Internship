"""check_gemini.py - Stage 1 smoke test: .env + Gemini API key + model name.

Sends ONE tiny request to Gemini and reports exactly what went wrong if it fails.
Run from the project folder (venv active):  python check_gemini.py

ASSUMPTIONS (flagged):
  1. SDK is google-genai 2.27.0 (import: `from google import genai`). Exception
     classes/attributes (errors.APIError.code/.message, ClientError, ServerError)
     were checked against that exact version.
  2. .env lives next to this file and defines GEMINI_API_KEY (required) and
     GEMINI_MODEL (optional; falls back to DEFAULT_MODEL with a visible notice).
  3. DEFAULT_MODEL "gemini-3.5-flash" comes from Google's current docs, but its
     availability on the FREE tier is NOT confirmed. This script is the real test.
  4. HTTP code mapping: 429 = rate limit/quota, 404 = model not found,
     key problem = 401/403 only when Google's status is UNAUTHENTICATED or
     PERMISSION_DENIED, or 400 when the message mentions the API key. Any other
     403 (e.g. a proxy/firewall/region block) is shown raw as [API ERROR].
  5. The API key is never printed; it is also redacted from error messages.
  6. No generation config is set (defaults), to stay compatible across models.

Exit codes: 0 ok | 1 config | 2 key/permission | 3 model not found |
            4 rate limit/quota | 5 other API error | 6 network/unexpected
"""
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import errors

DEFAULT_MODEL = "gemini-3.5-flash"
PROMPT = "Reply with exactly one word: OK"


def redact(text, secret):
    """Remove the API key from any text before printing it."""
    return text.replace(secret, "***") if secret else text


def main():
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        print(f"[CONFIG] {env_path} not found. Copy .env.example to .env and set GEMINI_API_KEY.")
        return 1
    load_dotenv(env_path)

    api_key = (os.getenv("GEMINI_API_KEY") or "").strip()
    if not api_key:
        print("[CONFIG] GEMINI_API_KEY is empty or missing in .env.")
        return 1

    model = (os.getenv("GEMINI_MODEL") or "").strip()
    if not model:
        model = DEFAULT_MODEL
        print(f"[NOTICE] GEMINI_MODEL not set in .env, using default: {model}")

    print(f"Key loaded : yes ({len(api_key)} chars, value hidden)")
    print(f"Model      : {model}")
    print("Sending one tiny request...")

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(model=model, contents=PROMPT)
    except errors.ClientError as e:
        msg = redact(str(e.message or e), api_key)
        if e.code == 429:
            print(f"[RATE LIMIT] 429 - quota/rate limit hit for '{model}'. Wait a minute and retry, or try another Flash model.\n  {msg}")
            return 4
        if e.code == 404:
            print(f"[MODEL] 404 - model '{model}' not found for this key/API version. Fix GEMINI_MODEL in .env.\n  {msg}")
            return 3
        if e.status in ("UNAUTHENTICATED", "PERMISSION_DENIED") or (
            e.code == 400 and "api key" in msg.lower()
        ):
            print(f"[KEY] {e.code} - key invalid or not permitted. Regenerate it in Google AI Studio.\n  {msg}")
            return 2
        print(f"[API ERROR] {e.code} {e.status}: {msg}")
        return 5
    except errors.ServerError as e:
        print(f"[API ERROR] {e.code} server-side error, retry later: {redact(str(e.message or e), api_key)}")
        return 5
    except Exception as e:  # network down, DNS, proxy, SDK-level problems
        print(f"[NETWORK/UNEXPECTED] {type(e).__name__}: {redact(str(e), api_key)}")
        return 6

    text = (response.text or "").strip()
    if not text:
        print("[WARN] Call succeeded but returned no text (possibly blocked or empty candidate).")
        print(f"  Raw response: {redact(str(response), api_key)[:300]}")
        return 5
    print(f"Response   : {text}")
    print("OK - .env, API key and model all work.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
