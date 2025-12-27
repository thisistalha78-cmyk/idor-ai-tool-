import os
import re
import requests
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

app = FastAPI()
templates = Jinja2Templates(directory="templates")

HEADERS_BASE = {
    "User-Agent": "IDOR-Research-Tool/1.0 (BugBounty Safe)",
    "Accept": "application/json"
}

def find_id_in_url(url: str):
    match = re.search(r"/(\d+)(?!.*\d)", url)
    return match.group(1) if match else None

def change_id(original_id: str):
    return str(int(original_id) + 1)

def deepseek_analyze(resp_a: str, resp_b: str):
    prompt = f"""
You are a security analyst.

Compare the two API responses below.

Response A:
{resp_a}

Response B:
{resp_b}

Tasks:
1. Check if Response B appears to expose data of a different object/user.
2. Identify sensitive fields if present.
3. Give an IDOR likelihood score from 0 to 100.
4. Brief explanation.

Do NOT assume. Analyze strictly from content.
"""

    payload = {
        "model": "deepseek/deepseek-chat",
        "messages": [
            {"role": "user", "content": prompt}
        ]
    }

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }

    r = requests.post(
        "https://openrouter.ai/api/v1/chat/completions",
        json=payload,
        headers=headers,
        timeout=30
    )

    return r.json()["choices"][0]["message"]["content"]

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan", response_class=HTMLResponse)
async def scan(
    request: Request,
    target_url: str = Form(...),
    cookie: str = Form("")
):
    original_id = find_id_in_url(target_url)

    if not original_id:
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "result": "❌ No numeric ID found in URL"}
        )

    modified_id = change_id(original_id)
    modified_url = target_url.replace(original_id, modified_id, 1)

    headers = HEADERS_BASE.copy()
    if cookie.strip():
        headers["Cookie"] = cookie.strip()

    try:
        r1 = requests.get(target_url, headers=headers, timeout=15)
        r2 = requests.get(modified_url, headers=headers, timeout=15)
    except Exception as e:
        return templates.TemplateResponse(
            "index.html",
            {"request": request, "result": f"Request error: {e}"}
        )

    analysis = deepseek_analyze(r1.text[:3000], r2.text[:3000])

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "result": analysis,
            "url_a": target_url,
            "url_b": modified_url
        }
    )
