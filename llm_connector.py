from openai import OpenAI
import os
import json

# load .env if python-dotenv available, else rely on shell env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

print("[llm_connector] module imported. NVIDIA_API_KEY present:", bool(os.getenv("NVIDIA_API_KEY")))

_client = None

def _get_client():
    global _client
    if _client is None:
        api_key = os.getenv("NVIDIA_API_KEY")
        print("[llm_connector] _get_client: NVIDIA_API_KEY present:", bool(api_key))
        if not api_key:
            raise RuntimeError("NVIDIA_API_KEY not set in environment or .env")
        print("[llm_connector] creating OpenAI client")
        _client = OpenAI(
            base_url="https://integrate.api.nvidia.com/v1",
            api_key=api_key
        )
    return _client

MODEL = "z-ai/glm-5.1"

def ask_llm(system_prompt, user_prompt):
    print(f"[llm_connector] ask_llm: model={MODEL}, system_len={len(system_prompt)}, user_len={len(user_prompt)}")
    response = _get_client().chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0
    )
    content = response.choices[0].message.content
    print("[llm_connector] ask_llm: response_len=", len(content), "snippet=", content[:200].replace("\n"," "))
    return content


def ask_llm_json(system_prompt, user_prompt):
    """Ask LLM, extract JSON from response. Returns dict or None on failure."""
    prompt = user_prompt + "\n\nRespond with valid JSON only. No markdown, no explanation."
    print(f"[llm_connector] ask_llm_json: model={MODEL}, system_len={len(system_prompt)}, prompt_len={len(prompt)}")
    response = _get_client().chat.completions.create(
        model=MODEL,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        temperature=0
    )
    content = response.choices[0].message.content.strip()
    if content.startswith("```"):
        content = content.split("```")[1]
        if content.startswith("json"):
            content = content[4:]
    print("[llm_connector] ask_llm_json: raw_content_snippet=", content[:200].replace("\n"," "))
    try:
        return json.loads(content.strip())
    except (json.JSONDecodeError, KeyError):
        print("[llm_connector] ask_llm_json: JSON parse failed")
        return None
