import os
import ssl
import urllib.request
import json

from core.env import load_dotenv

project_root = os.path.dirname(os.path.abspath(__file__))
load_dotenv(project_root)

api_key = os.environ.get('GROQ_API_KEY')
print("API Key starts with:", api_key[:4] if api_key else "None")
print("API Key len:", len(api_key) if api_key else 0)

url = "https://api.groq.com/openai/v1/chat/completions"
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {api_key}",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}
payload = {
    "model": "llama-3.3-70b-versatile",
    "messages": [{"role": "user", "content": "Hello"}],
    "temperature": 0.2,
    "max_tokens": 10
}
try:
    data_bytes = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
        res_body = response.read().decode("utf-8")
        print("Success:", json.loads(res_body)["choices"][0]["message"]["content"])
except Exception as e:
    print("Error:", e)
