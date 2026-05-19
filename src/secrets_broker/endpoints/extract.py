"""Local-Qwen-backed text extraction + web fetch + web search synthesis.

All three endpoints share the pattern: large blob in, small answer out, and
the blob NEVER enters the caller's process. The caller asks a question; only
the answer comes back. Saves expensive-model context tokens.

Requires: local Ollama running with a Qwen model installed
          (default qwen2.5:14b-instruct for /extract, qwen3:30b-a3b for
          web fetch + search), and local SearXNG for /search/web.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request

from ..config import USER_AGENT

SEARXNG_URL = "http://127.0.0.1:8888"


def _qwen_extract(text: str, question: str, *,
                  model: str = "qwen2.5:14b-instruct",
                  max_tokens: int = 800,
                  system_extra: str = "") -> tuple[str | None, str | None]:
    """Run Qwen with a system prompt asking for extraction.
    Returns (answer, error). answer is None on error."""
    sys_prompt = (
        "Answer the user's question using only the text they provide. "
        "Be concise (1-3 short sentences). No preamble, no meta-commentary. "
        "If the answer is not in the text, reply exactly: NOT FOUND. "
        f"{system_extra}"
    )
    user_prompt = f"Question: {question}\n\nText:\n{text}"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "options": {"temperature": 0.0, "num_predict": max_tokens},
        "stream": False,
    }
    req = urllib.request.Request(
        "http://127.0.0.1:11434/api/chat",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            d = json.loads(resp.read())
        answer = (d.get("message") or {}).get("content", "").strip()
        return answer or None, None
    except urllib.error.URLError as e:
        return None, f"ollama_unreachable: {e}"
    except urllib.error.HTTPError as e:
        return None, f"upstream_error {e.code}: {e.read().decode(errors='replace')[:200]}"


def _html_to_text(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = raw.decode("latin-1", errors="replace")
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def handle_extract(body: dict) -> tuple[int, dict]:
    """Generic 'big text → small answer' extractor via local Qwen.
    Body: {text, question, max_tokens?=800, model?=qwen2.5:14b-instruct}.
    Use whenever the caller would otherwise pull a large blob into an
    expensive model's context just to extract a specific fact."""
    text = body.get("text")
    question = body.get("question")
    if not text or not question:
        return 400, {"error": "missing_arg", "detail": "text and question required"}
    answer, err = _qwen_extract(
        text=text,
        question=question,
        model=body.get("model", "qwen2.5:14b-instruct"),
        max_tokens=int(body.get("max_tokens", 800)),
    )
    if err:
        return 502, {"error": err}
    return 200, {"answer": answer, "tokens_in_estimate": len(text) // 4}


def handle_web_fetch_and_extract(body: dict) -> tuple[int, dict]:
    """Fetch a URL and extract an answer from its content via Qwen.
    Body: {url, question, max_tokens?=2000, max_bytes?=2_000_000}.
    Page content never enters the caller's context — only the extracted answer."""
    url = body.get("url")
    question = body.get("question")
    if not url or not question:
        return 400, {"error": "missing_arg", "detail": "url and question required"}
    if not (url.startswith("http://") or url.startswith("https://")):
        return 400, {"error": "bad_url", "detail": "url must start with http:// or https://"}
    max_bytes = int(body.get("max_bytes", 2_000_000))

    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "text/html,text/plain,application/json,*/*",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            content_type = resp.headers.get("Content-Type", "")
            raw = resp.read(max_bytes + 1)
    except urllib.error.URLError as e:
        return 502, {"error": "fetch_failed", "url": url, "detail": str(e)[:200]}
    except urllib.error.HTTPError as e:
        return 502, {"error": "fetch_http_error", "url": url, "status": e.code}

    truncated = len(raw) > max_bytes
    if truncated:
        raw = raw[:max_bytes]

    if "html" in content_type.lower() or raw.lstrip().startswith(b"<"):
        body_text = _html_to_text(raw)
    else:
        try:
            body_text = raw.decode("utf-8", errors="replace")
        except Exception:
            body_text = raw.decode("latin-1", errors="replace")

    # Cap text fed to Qwen at ~50K chars (~12K tokens) — its sweet spot
    if len(body_text) > 50000:
        body_text = body_text[:50000]

    answer, err = _qwen_extract(
        text=body_text,
        question=question,
        # qwen3:30b-a3b with thinking enabled — quality matters more than speed
        # for noisy/long web pages. message.thinking is discarded.
        # num_predict bumped to 2000 because thinking + answer share the same
        # generation budget.
        model=body.get("model", "qwen3:30b-a3b"),
        max_tokens=int(body.get("max_tokens", 2000)),
    )
    if err:
        return 502, {"error": err, "url": url}
    return 200, {
        "answer": answer,
        "url": url,
        "fetched_bytes": len(raw),
        "content_type": content_type,
        "truncated": truncated,
    }


def _searxng_query(query: str, num_results: int = 5) -> list[dict]:
    """Run a query against local SearXNG. Returns list of {title, url, content}."""
    params = urllib.parse.urlencode({"q": query, "format": "json"})
    req = urllib.request.Request(
        f"{SEARXNG_URL}/search?{params}",
        headers={"User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())
    results = []
    for r in data.get("results", [])[:num_results]:
        results.append({
            "title": r.get("title", ""),
            "url": r.get("url", ""),
            "content": r.get("content", "")[:500],
        })
    return results


def handle_search_web(body: dict) -> tuple[int, dict]:
    """Search the web + synthesize an answer via local Qwen.
    Body: {query, question?, num_results?=5, fetch_pages?=True, max_tokens?=3000}.
    If question is omitted, returns just the search results (for the caller to triage).
    Otherwise: fetches top results, synthesizes the answer.
    Search results + page bodies NEVER enter the caller's context — only the answer."""
    query = body.get("query")
    if not query:
        return 400, {"error": "missing_arg", "detail": "query required"}
    question = body.get("question")
    num_results = min(int(body.get("num_results", 5)), 10)
    fetch_pages = bool(body.get("fetch_pages", True))

    try:
        results = _searxng_query(query, num_results)
    except urllib.error.URLError as e:
        return 502, {"error": "search_unreachable", "detail": str(e)[:200],
                     "hint": "is SearXNG running on 127.0.0.1:8888?"}
    if not results:
        return 200, {"answer": "NOT FOUND", "sources": [], "query": query}

    # If no question, return raw results — let the caller pick what to fetch
    if not question:
        return 200, {"results": results, "query": query}

    # Otherwise: fetch top 3 pages, combine with snippets, synthesize
    pages_text = ""
    fetched_urls = []
    if fetch_pages:
        for r in results[:3]:
            try:
                req = urllib.request.Request(r["url"], headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,text/plain,*/*",
                })
                with urllib.request.urlopen(req, timeout=15) as resp:
                    raw = resp.read(500_000)
                text = _html_to_text(raw)
                pages_text += f"\n--- {r['url']} ---\n{text[:15000]}\n"
                fetched_urls.append(r["url"])
            except Exception:
                continue

    snippets = "\n".join(
        f"[{i + 1}] {r['title']} — {r['url']}\n    {r['content']}"
        for i, r in enumerate(results)
    )
    combined = (
        f"SEARCH RESULT SNIPPETS:\n{snippets}\n\n"
        f"FULL PAGE CONTENT (top 3):\n{pages_text}"
    )
    if len(combined) > 60000:
        combined = combined[:60000]

    answer, err = _qwen_extract(
        text=combined,
        question=question,
        # qwen3:30b-a3b with thinking — multi-source synthesis benefits most.
        # num_predict bumped to 3000 because thinking can be lengthy on
        # ~60K combined input and it counts against the same budget.
        model=body.get("model", "qwen3:30b-a3b"),
        max_tokens=int(body.get("max_tokens", 3000)),
    )
    if err:
        return 502, {"error": err, "query": query}
    return 200, {
        "answer": answer,
        "query": query,
        "sources": [r["url"] for r in results],
        "fetched_pages": fetched_urls,
    }


ENDPOINTS = {
    "/extract": handle_extract,
    "/web/fetch-and-extract": handle_web_fetch_and_extract,
    "/search/web": handle_search_web,
}
