#!/usr/bin/env python3
"""USERTRACE — best-effort public username availability checker."""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import aiohttp
from colorama import Fore, Style, init as colorama_init

VERSION = "1.0.0"
TIMEOUT_SECONDS = 5.5
MAX_CONCURRENCY = 10
USER_AGENT = "USERTRACE/1.0 (public-profile availability checker; no authentication)"
CATALOG_PATH = Path(__file__).resolve().parent / "data" / "platforms.json"
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,29}$")
ANTI_BOT_MARKERS = (
    "verify you are human", "verify you're human", "captcha", "checking your browser",
    "unusual traffic", "automated requests", "security challenge", "access denied",
    "enable javascript and cookies to continue",
)
LOGIN_MARKERS = ("/login", "/signin", "/sign-in", "/auth/login", "/accounts/login")

BANNER = r"""██╗   ██╗███████╗███████╗██████╗ ████████╗██████╗  █████╗  ██████╗███████╗
██║   ██║██╔════╝██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
██║   ██║███████╗█████╗  ██████╔╝   ██║   ██████╔╝███████║██║     █████╗
██║   ██║╚════██║██╔══╝  ██╔══██╗   ██║   ██╔══██╗██╔══██║██║     ██╔══╝
╚██████╔╝███████║███████╗██║  ██║   ██║   ██║  ██║██║  ██║╚██████╗███████╗
 ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
                      USERTRACE v1.0 — Username OSINT Scanner
                   (Use only for lawful, authorized research)"""


def validate_username(username: str) -> bool:
    return bool(USERNAME_RE.fullmatch(username))


def load_catalog() -> list[dict[str, Any]]:
    try:
        with CATALOG_PATH.open("r", encoding="utf-8") as f:
            catalog = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not load platform catalog at {CATALOG_PATH}: {exc}") from exc
    if not isinstance(catalog, list) or not catalog:
        raise RuntimeError("Platform catalog is empty or invalid.")
    return catalog


def classify_response(platform: dict[str, Any], status: int, final_url: str, body: str) -> tuple[str, str]:
    """Conservatively classify a response; never treat an ambiguous soft-404 as a match."""
    text = body.casefold()
    if status == 429:
        return "UNCERTAIN", "rate-limited"
    if status in (401, 403):
        return "UNCERTAIN", "access restricted"
    if 500 <= status <= 599:
        return "UNCERTAIN", "upstream server error"
    if any(marker in text for marker in ANTI_BOT_MARKERS):
        return "UNCERTAIN", "anti-bot challenge"

    original = urlparse(platform["url_template"].format(username="sample-user"))
    final = urlparse(final_url)
    if final.netloc.casefold() != original.netloc.casefold() and any(m in final.path.casefold() for m in LOGIN_MARKERS):
        return "UNCERTAIN", "redirected to sign-in"
    if any(m in final.path.casefold() for m in LOGIN_MARKERS):
        return "UNCERTAIN", "redirected to sign-in"

    if status == 404 or status == int(platform.get("error_code", 404)):
        return "NOT FOUND", "profile not found (HTTP status)"
    not_found = [s.casefold() for s in platform.get("not_found_strings", []) if s]
    if any(marker in text for marker in not_found):
        return "NOT FOUND", "profile-not-found marker"

    if 200 <= status < 300:
        if platform.get("detection_method") == "error_message":
            found = [s.casefold() for s in platform.get("found_strings", []) if s]
            if any(marker in text for marker in found):
                return "FOUND", "profile marker detected; verify manually"
            return "UNCERTAIN", "soft-404, no reliable profile marker"
        return "FOUND", "HTTP success; verify manually"
    return "UNCERTAIN", f"ambiguous response (HTTP {status})"


async def check_platform(session: aiohttp.ClientSession, semaphore: asyncio.Semaphore,
                         platform: dict[str, Any], username: str) -> dict[str, str]:
    url = platform["url_template"].format(username=username)
    try:
        async with semaphore:
            async with session.get(url, allow_redirects=True) as response:
                # Bound memory use and avoid downloading large media pages.
                raw = await response.content.read(512 * 1024)
                body = raw.decode(response.charset or "utf-8", errors="replace")
                result, reason = classify_response(platform, response.status, str(response.url), body)
                return {"name": platform["name"], "category": platform["category"],
                        "url": url, "status": result, "reason": reason,
                        "high_difficulty": str(bool(platform.get("high_difficulty", False))).lower()}
    except asyncio.TimeoutError:
        reason = "request timed out"
    except aiohttp.ClientConnectorError:
        reason = "connection failed"
    except aiohttp.ClientError as exc:
        reason = f"network error: {type(exc).__name__}"
    except Exception as exc:  # Keep one broken endpoint from stopping the scan.
        reason = f"request error: {type(exc).__name__}"
    return {"name": platform["name"], "category": platform["category"], "url": url,
            "status": "UNCERTAIN", "reason": reason,
            "high_difficulty": str(bool(platform.get("high_difficulty", False))).lower()}


def paint(text: str, color: str, no_color: bool) -> str:
    return text if no_color else f"{color}{text}{Style.RESET_ALL}"


def clear_progress(no_color: bool) -> None:
    sys.stdout.write("\r" + (" " * 120 if no_color else "\033[2K\r"))
    sys.stdout.flush()


def format_result(result: dict[str, str], no_color: bool) -> str:
    name = result["name"]
    status = result["status"]
    if status == "FOUND":
        prefix = paint("[+] FOUND", Fore.GREEN, no_color)
        return f"{prefix:<22} {name:<20} -> {result['url']}"
    if status == "UNCERTAIN":
        detail = result["reason"]
        if result["high_difficulty"] == "true":
            detail += "; known anti-bot platform — verify manually"
        prefix = paint("[!] UNCERTAIN", Fore.YELLOW, no_color)
        return f"{prefix:<22} {name:<20} -> {detail}"
    prefix = paint("[-] NOT FOUND", Fore.RED + Style.DIM, no_color)
    return f"{prefix:<22} {name:<20} -> not found"


def progress_line(done: int, total: int, found: int, uncertain: int, no_color: bool) -> None:
    msg = f"Scanning... [{done}/{total}] checked | {found} found | {uncertain} uncertain"
    sys.stdout.write("\r" + msg + " " * 8)
    sys.stdout.flush()


async def scan(username: str, platforms: list[dict[str, Any]], results: list[dict[str, str]],
               found_only: bool, no_color: bool) -> None:
    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENCY, ssl=True)
    tasks: list[asyncio.Task[dict[str, str]]] = []
    async with aiohttp.ClientSession(timeout=timeout, connector=connector,
                                     headers={"User-Agent": USER_AGENT}) as session:
        tasks = [asyncio.create_task(check_platform(session, semaphore, p, username)) for p in platforms]
        found = uncertain = done = 0
        try:
            for future in asyncio.as_completed(tasks):
                result = await future
                results.append(result)
                done += 1
                found += result["status"] == "FOUND"
                uncertain += result["status"] == "UNCERTAIN"
                clear_progress(no_color)
                if not found_only or result["status"] == "FOUND":
                    print(format_result(result, no_color), flush=True)
                progress_line(done, len(platforms), found, uncertain, no_color)
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        finally:
            clear_progress(no_color)


def print_summary(username: str, results: list[dict[str, str]], total: int, no_color: bool,
                  partial: bool = False, found_only: bool = False) -> None:
    found = [r for r in results if r["status"] == "FOUND"]
    uncertain = [r for r in results if r["status"] == "UNCERTAIN"]
    not_found = max(0, total - len(found) - len(uncertain))
    title = "PARTIAL SCAN" if partial else "SCAN COMPLETE"
    print("=" * 60)
    print(f" {title}: {username}")
    print(f" Found on {len(found)} / {total} platforms | {len(uncertain)} uncertain | {not_found} not found")
    print("=" * 60)
    if found:
        print("\n[FOUND]")
        for r in sorted(found, key=lambda x: x["name"].casefold()):
            print(f" {r['name']:<20} -> {r['url']}  (verify manually)")
    if uncertain and not found_only:
        print("\n[UNCERTAIN] (manual check recommended)")
        for r in sorted(uncertain, key=lambda x: x["name"].casefold()):
            detail = r["reason"]
            if r["high_difficulty"] == "true":
                detail += "; known anti-bot platform — verify manually"
            print(f" {r['name']:<20} -> {r['url']} ({detail})")
    if partial:
        print("\nScan interrupted; results above include completed checks only.")


def export_results(username: str, results: list[dict[str, str]], fmt: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_user = re.sub(r"[^A-Za-z0-9._-]", "_", username)
    path = Path.cwd() / f"usertrace_{safe_user}_{stamp}.{fmt}"
    payload = [{**r, "manual_verification_recommended": True} for r in results]
    if fmt == "json":
        path.write_text(json.dumps({"username": username, "generated_at": stamp,
                                    "results": payload}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    else:
        with path.open("w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=["name", "category", "url", "status", "reason",
                                                   "high_difficulty", "manual_verification_recommended"])
            writer.writeheader()
            writer.writerows(payload)
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="usertrace", description="Best-effort public username availability checker.")
    parser.add_argument("username", nargs="?", help="username to check (1–30 permitted characters)")
    parser.add_argument("--found-only", action="store_true", help="show only FOUND results during the scan")
    parser.add_argument("--category", help="scan only one category (see --list-categories)")
    parser.add_argument("--export", choices=("json", "csv"), help="export results in the current directory")
    parser.add_argument("--no-color", action="store_true", help="disable colored terminal output")
    parser.add_argument("--list-categories", action="store_true", help="list catalog categories and exit")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        catalog = load_catalog()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.list_categories:
        for category in sorted({p["category"] for p in catalog}):
            print(category)
        return 0
    if not args.username:
        parser.error("username is required unless --list-categories is used")
    if not validate_username(args.username):
        print("ERROR: username must be 1–30 characters, start with a letter or digit, and contain only letters, digits, dots, underscores, or hyphens.", file=sys.stderr)
        return 2
    platforms = catalog
    if args.category:
        requested = args.category.casefold()
        platforms = [p for p in catalog if p["category"].casefold() == requested]
        if not platforms:
            available = ", ".join(sorted({p["category"] for p in catalog}))
            print(f"ERROR: unknown or empty category '{args.category}'. Available: {available}", file=sys.stderr)
            return 2

    colorama_init(autoreset=True, strip=bool(args.no_color))
    banner_lines = BANNER.splitlines()
    print(paint("\n".join(banner_lines[:6]), Fore.GREEN + Style.BRIGHT, args.no_color))
    print(paint("\n".join(banner_lines[6:]), Fore.CYAN + Style.BRIGHT, args.no_color))
    print(f"\nTarget username: {args.username} | Platforms: {len(platforms)} | Concurrency: {MAX_CONCURRENCY}\n")
    results: list[dict[str, str]] = []
    interrupted = False
    try:
        asyncio.run(scan(args.username, platforms, results, args.found_only, args.no_color))
    except KeyboardInterrupt:
        interrupted = True
    print_summary(args.username, results, len(platforms), args.no_color,
                  partial=interrupted, found_only=args.found_only)
    if args.export:
        try:
            output = export_results(args.username, results, args.export)
            print(f"\nExported {len(results)} results to {output}")
        except OSError as exc:
            print(f"ERROR: could not write export: {exc}", file=sys.stderr)
            return 1
    if not results and not interrupted:
        print("\nNo checks completed. Check your internet connection and try again.", file=sys.stderr)
        return 1
    network_failure = bool(results) and all(
        r["status"] == "UNCERTAIN" and
        (r["reason"] in ("connection failed", "request timed out") or
         r["reason"].startswith("network error:")) for r in results
    )
    if network_failure:
        print("\nERROR: all requests failed or timed out; check your internet connection.", file=sys.stderr)
        return 1
    return 130 if interrupted else 0


if __name__ == "__main__":
    raise SystemExit(main())
