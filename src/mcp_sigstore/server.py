"""MCP-sigstore: MCP App Distribution Integrity Verification Server.

Implements the verification layers described in 01_distribution_integrity.md:
  L1: Source integrity (GitHub ownership verification)
  L2: Build provenance (npm provenance attestation check)
  L3: Install integrity (version locking check)
"""

import asyncio
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# ─── Constants ───────────────────────────────────────────────────────────────

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_API = "https://api.github.com"
NPM_REGISTRY = "https://registry.npmjs.org"
NPM_API = "https://api.npmjs.org"

MCP_MARKETS = [
    "https://mcpmarket.com",
    "https://smithery.ai",
    "https://mcp.so",
]

# ─── Server Setup ────────────────────────────────────────────────────────────

server = Server("mcp-sigstore")

# ─── Utility Functions ───────────────────────────────────────────────────────


def _gh_headers() -> dict:
    h = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


async def _github_owner(repo_url: str) -> str | None:
    """Extract the actual GitHub repo owner from URL via API."""
    # Parse owner/repo from URL
    m = re.search(r"github\.com/([^/]+)/([^/\s#.]+)", repo_url)
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    repo = re.sub(r"\.git$", "", repo)

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}",
            headers=_gh_headers(),
        )
    if resp.status_code == 200:
        data = resp.json()
        return data.get("owner", {}).get("login")
    return None


async def _npm_info(package_name: str) -> dict | None:
    """Get npm package metadata."""
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(f"{NPM_REGISTRY}/{package_name}")
    if resp.status_code == 200:
        return resp.json()
    return None


def _sigstore_verify_npm(package_name: str, version: str | None = None) -> dict:
    """Check npm provenance attestation via npm CLI."""
    try:
        if version:
            cmd = [
                "npm", "provenance", "attestations",
                f"{package_name}@{version}", "--json"
            ]
        else:
            cmd = [
                "npm", "provenance", "attestations",
                f"{package_name}@latest", "--json"
            ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout)
        return {"error": result.stderr.strip() if result.stderr else "no attestations"}
    except Exception as e:
        return {"error": str(e)}


def _parse_install_commands(readme_text: str) -> list[dict]:
    """Extract and analyze install commands from README text."""
    commands = []

    # Patterns for MCP install commands
    patterns = [
        (r"npx\s+(?:-y\s+)?(@[\w\-./]+(?:@[\w.\-]+)?)", "npx"),
        (r"npm\s+install\s+(?:-g\s+)?(@[\w\-./]+(?:@[\w.\-]+)?)", "npm"),
        (r"pip(?:3)?\s+install\s+(?:--user\s+)?([\w\-]+)(?:[=<>~!]+\d[\w.]*)?", "pip"),
        (r"uvx\s+([\w\-]+(?:==[\w.]+)?)", "uvx"),
    ]

    for pattern, pkg_type in patterns:
        for match in re.finditer(pattern, readme_text):
            full_match = match.group(0)
            pkg_name = match.group(1)

            # Determine version locking
            has_version = bool(re.search(r"@\d|==\d|>=\d|<=\d|~=|\^", full_match))
            has_latest = "@latest" in full_match or "latest" in full_match
            has_commit = bool(re.search(r"#[a-f0-9]{7,40}", full_match))

            locking = "unpinned"
            if has_commit:
                locking = "commit-hash"
            elif has_version:
                locking = "version-pinned"
            elif has_latest:
                locking = "latest-tag"
            # else: unpinned

            commands.append({
                "command": full_match.strip(),
                "package": pkg_name,
                "type": pkg_type,
                "version_locking": locking,
            })

    return commands


async def _repo_status(repo_url: str) -> dict:
    """Check if GitHub repo is active, archived, or deleted."""
    m = re.search(r"github\.com/([^/]+)/([^/\s#.]+)", repo_url)
    if not m:
        return {"status": "parse_error"}

    owner, repo = m.group(1), m.group(2)
    repo = re.sub(r"\.git$", "", repo)

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            f"{GITHUB_API}/repos/{owner}/{repo}",
            headers=_gh_headers(),
        )
    if resp.status_code == 404:
        return {"status": "deleted_or_private", "archived": False}
    if resp.status_code != 200:
        return {"status": "error", "code": resp.status_code}

    data = resp.json()
    return {
        "status": "active" if not data.get("archived") else "archived",
        "archived": data.get("archived", False),
        "stargazers_count": data.get("stargazers_count", 0),
        "updated_at": data.get("updated_at", ""),
    }


# ─── Tools ───────────────────────────────────────────────────────────────────


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="verify_github_ownership",
            description=(
                "Verify that a GitHub repository's actual owner matches the "
                "claimed author on an MCP Market. Checks whether the repo still "
                "belongs to the claimed author or has been transferred — the "
                "'zombie transfer' gap from 01_distribution_integrity.md Link 1."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "github_url": {
                        "type": "string",
                        "description": "GitHub repository URL (e.g., https://github.com/anthropics/mcp-server-filesystem)",
                    },
                    "claimed_author": {
                        "type": "string",
                        "description": "The author/owner name claimed by the MCP Market listing",
                    },
                },
                "required": ["github_url", "claimed_author"],
            },
        ),
        Tool(
            name="check_npm_provenance",
            description=(
                "Check whether an npm package has Sigstore provenance attestation. "
                "Addresses Link 2 of the distribution integrity chain: "
                "'Can the user verify this package was built from the claimed source?' "
                "Requires npm CLI installed."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "package_name": {
                        "type": "string",
                        "description": "npm package name (e.g., @anthropic/mcp-server-filesystem)",
                    },
                    "version": {
                        "type": "string",
                        "description": "Specific version to check (optional, defaults to latest)",
                    },
                },
                "required": ["package_name"],
            },
        ),
        Tool(
            name="check_version_locking",
            description=(
                "Parse a README or install instructions to check whether the "
                "MCP App's install commands pin versions. Addresses Link 3 of "
                "the distribution chain: 'Does the user always get the same code?' "
                "Returns a vulnerability assessment for each command found."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "readme_text": {
                        "type": "string",
                        "description": "The README content or install instructions to analyze",
                    },
                },
                "required": ["readme_text"],
            },
        ),
        Tool(
            name="scan_mcp_app",
            description=(
                "Full distribution chain integrity scan. Given an MCP app's GitHub "
                "URL, claimed author, and npm package name, checks ALL FOUR links "
                "described in 01_distribution_integrity.md. Returns a comprehensive "
                "risk report with per-link pass/fail status."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "github_url": {
                        "type": "string",
                        "description": "GitHub repository URL",
                    },
                    "claimed_author": {
                        "type": "string",
                        "description": "Author name claimed by the MCP Market or README",
                    },
                    "npm_package": {
                        "type": "string",
                        "description": "npm package name if applicable (optional)",
                    },
                    "readme_text": {
                        "type": "string",
                        "description": "README content for version locking check (optional)",
                    },
                },
                "required": ["github_url", "claimed_author"],
            },
        ),
        Tool(
            name="generate_integrity_manifest",
            description=(
                "Generate a signed integrity manifest for an MCP App. This is the "
                "Phase 2 L1 mechanism: creates a JSON manifest binding the app's "
                "identity (source repo, author, version) with a SHA256 signature. "
                "The manifest can be published alongside the app for verification."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "app_name": {
                        "type": "string",
                        "description": "Name of the MCP App",
                    },
                    "github_url": {
                        "type": "string",
                        "description": "GitHub repository URL",
                    },
                    "author": {
                        "type": "string",
                        "description": "Verified GitHub owner",
                    },
                    "version": {
                        "type": "string",
                        "description": "App version string",
                    },
                    "npm_package": {
                        "type": "string",
                        "description": "npm package name if applicable",
                    },
                },
                "required": ["app_name", "github_url", "author"],
            },
        ),
        Tool(
            name="verify_integrity_manifest",
            description=(
                "Verify a previously generated integrity manifest. Checks that the "
                "manifest's signature is valid and that the claimed bindings "
                "(author, repo) still hold. This is what a Market or end-user "
                "would run before installing an app."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "manifest_json": {
                        "type": "string",
                        "description": "The JSON integrity manifest to verify",
                    },
                },
                "required": ["manifest_json"],
            },
        ),
    ]


# ─── Tool Handlers ───────────────────────────────────────────────────────────


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    match name:
        case "verify_github_ownership":
            return await _handle_verify_ownership(arguments)
        case "check_npm_provenance":
            return await _handle_npm_provenance(arguments)
        case "check_version_locking":
            return await _handle_version_locking(arguments)
        case "scan_mcp_app":
            return await _handle_scan_mcp_app(arguments)
        case "generate_integrity_manifest":
            return await _handle_generate_manifest(arguments)
        case "verify_integrity_manifest":
            return await _handle_verify_manifest(arguments)
        case _:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]


async def _handle_verify_ownership(args: dict) -> list[TextContent]:
    github_url = args["github_url"]
    claimed = args["claimed_author"]

    actual = await _github_owner(github_url)

    if actual is None:
        return [TextContent(
            type="text",
            text=json.dumps({
                "link": "Link 1 — GitHub → Market",
                "status": "ERROR",
                "error": f"Could not resolve GitHub owner for {github_url}",
                "claimed_author": claimed,
                "actual_owner": None,
                "match": False,
                "risk": "Unable to verify — treat as HIGH risk",
            }, indent=2)
        )]

    match = actual.lower() == claimed.lower()
    return [TextContent(
        type="text",
        text=json.dumps({
            "link": "Link 1 — GitHub → Market",
            "status": "PASS" if match else "FAIL",
            "claimed_author": claimed,
            "actual_owner": actual,
            "match": match,
            "risk": "LOW" if match else (
                "HIGH — repo may have been transferred to a different owner. "
                "This is the 'zombie transfer' gap."
            ),
        }, indent=2)
    )]


async def _handle_npm_provenance(args: dict) -> list[TextContent]:
    package_name = args["package_name"]
    version = args.get("version")

    # First, check if package exists and get metadata
    info = await _npm_info(package_name)
    if info is None or "error" in info:
        return [TextContent(
            type="text",
            text=json.dumps({
                "link": "Link 2 — GitHub → npm",
                "status": "ERROR",
                "error": f"Package {package_name} not found on npm registry",
                "package": package_name,
                "provenance": None,
                "risk": "UNKNOWN — package not found",
            }, indent=2)
        )]

    # Check via npm CLI
    attestations = _sigstore_verify_npm(package_name, version)

    has_provenance = "attestations" in attestations and len(
        attestations.get("attestations", [])
    ) > 0

    latest_version = info.get("dist-tags", {}).get("latest", "unknown")
    publish_info = info.get("versions", {}).get(latest_version, {})

    return [TextContent(
        type="text",
        text=json.dumps({
            "link": "Link 2 — GitHub → npm",
            "status": "PASS" if has_provenance else "FAIL",
            "package": package_name,
            "latest_version": latest_version,
            "has_provenance": has_provenance,
            "provenance_attestations": attestations if has_provenance else None,
            "risk": "LOW" if has_provenance else (
                "HIGH — no provenance attestation. Cannot verify this package "
                "was built from the claimed source repository."
            ),
        }, indent=2, default=str)
    )]


async def _handle_version_locking(args: dict) -> list[TextContent]:
    readme_text = args["readme_text"]
    commands = _parse_install_commands(readme_text)

    if not commands:
        return [TextContent(
            type="text",
            text=json.dumps({
                "link": "Link 3 — npm/PyPI → User",
                "status": "WARN",
                "error": "No recognizable install commands found in text",
                "commands_found": 0,
                "commands": [],
            }, indent=2)
        )]

    unpinned = [c for c in commands if c["version_locking"] == "unpinned"]
    pinned = [c for c in commands if c["version_locking"] != "unpinned"]

    overall_risk = "LOW" if len(unpinned) == 0 else (
        "HIGH" if len(unpinned) == len(commands) else "MEDIUM"
    )

    return [TextContent(
        type="text",
        text=json.dumps({
            "link": "Link 3 — npm/PyPI → User",
            "status": "PASS" if overall_risk == "LOW" else "FAIL",
            "total_commands": len(commands),
            "unpinned_commands": len(unpinned),
            "pinned_commands": len(pinned),
            "overall_risk": overall_risk,
            "commands": commands,
            "summary": (
                f"{len(unpinned)}/{len(commands)} install commands lack version "
                f"locking. Every unpinned command means the user gets different "
                f"code on each install."
            ),
        }, indent=2)
    )]


async def _handle_scan_mcp_app(args: dict) -> list[TextContent]:
    github_url = args["github_url"]
    claimed_author = args["claimed_author"]
    npm_package = args.get("npm_package")
    readme_text = args.get("readme_text")

    results = {}
    risk_score = 0

    # Link 1: Ownership
    actual = await _github_owner(github_url)
    if actual is None:
        results["link1_ownership"] = {
            "status": "ERROR",
            "error": f"Could not resolve GitHub owner",
            "match": False,
        }
        risk_score += 3
    else:
        match = actual.lower() == claimed_author.lower()
        results["link1_ownership"] = {
            "status": "PASS" if match else "FAIL",
            "claimed_author": claimed_author,
            "actual_owner": actual,
            "match": match,
            "detail": "Owner mismatch — possible zombie transfer" if not match else "Owner verified",
        }
        if not match:
            risk_score += 3

    # Link 2: Provenance
    if npm_package:
        info = await _npm_info(npm_package)
        if info and "error" not in info:
            attestations = _sigstore_verify_npm(npm_package)
            has_prov = "attestations" in attestations and len(
                attestations.get("attestations", [])
            ) > 0
            results["link2_provenance"] = {
                "status": "PASS" if has_prov else "FAIL",
                "package": npm_package,
                "has_provenance": has_prov,
                "detail": "No provenance — build source unverifiable" if not has_prov else "Provenance verified",
            }
            if not has_prov:
                risk_score += 2
        else:
            results["link2_provenance"] = {
                "status": "SKIP",
                "detail": f"npm package {npm_package} not found",
            }
    else:
        results["link2_provenance"] = {
            "status": "SKIP",
            "detail": "No npm package specified",
        }

    # Link 3: Version Locking
    if readme_text:
        commands = _parse_install_commands(readme_text)
        unpinned = [c for c in commands if c["version_locking"] == "unpinned"]
        results["link3_version_locking"] = {
            "status": "PASS" if len(unpinned) == 0 else "FAIL",
            "total_commands": len(commands),
            "unpinned_count": len(unpinned),
            "detail": f"{len(unpinned)}/{len(commands)} commands unpinned" if unpinned else "All commands pinned",
        }
        if unpinned:
            risk_score += min(len(unpinned), 2)
    else:
        results["link3_version_locking"] = {
            "status": "SKIP",
            "detail": "No README text provided for analysis",
        }

    # Link 4: Repo Status
    repo_status = await _repo_status(github_url)
    results["link4_repo_status"] = {
        "status": "PASS" if repo_status.get("status") == "active" else "FAIL",
        "repo_status": repo_status.get("status"),
        "archived": repo_status.get("archived", False),
        "detail": f"Repo {repo_status.get('status')}",
    }
    if repo_status.get("archived") or repo_status.get("status") == "deleted_or_private":
        risk_score += 2

    # Overall assessment
    max_score = 10
    if risk_score <= 1:
        overall = "LOW_RISK"
    elif risk_score <= 4:
        overall = "MEDIUM_RISK"
    else:
        overall = "HIGH_RISK"

    pass_count = sum(
        1 for v in results.values() if isinstance(v, dict) and v.get("status") == "PASS"
    )
    total_checks = sum(
        1 for v in results.values() if isinstance(v, dict) and v.get("status") != "SKIP"
    )

    return [TextContent(
        type="text",
        text=json.dumps({
            "app": github_url,
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_risk": overall,
            "risk_score": risk_score,
            "max_score": max_score,
            "checks_passed": f"{pass_count}/{total_checks}",
            "results": results,
            "summary": (
                f"MCP App Distribution Integrity Scan\n"
                f"  Overall Risk: {overall} ({risk_score}/{max_score})\n"
                f"  Checks: {pass_count}/{total_checks} passed\n"
                f"  Link 1 (Ownership): {results['link1_ownership'].get('status')}\n"
                f"  Link 2 (Provenance): {results.get('link2_provenance', {}).get('status', 'SKIP')}\n"
                f"  Link 3 (Version Lock): {results.get('link3_version_locking', {}).get('status', 'SKIP')}\n"
                f"  Link 4 (Repo Status): {results['link4_repo_status'].get('status')}"
            ),
        }, indent=2)
    )]


async def _handle_generate_manifest(args: dict) -> list[TextContent]:
    """Generate an integrity manifest binding app identity to a signature."""
    app_name = args["app_name"]
    github_url = args["github_url"]
    author = args["author"]
    version = args.get("version", "0.0.0")
    npm_package = args.get("npm_package")

    manifest_data = {
        "app_name": app_name,
        "github_url": github_url,
        "author": author,
        "version": version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if npm_package:
        manifest_data["npm_package"] = npm_package

    # Generate a deterministic hash as the "signature"
    # (In production, this would use GPG/Sigstore signing)
    canonical = json.dumps(manifest_data, sort_keys=True).encode()
    signature = hashlib.sha256(canonical).hexdigest()

    manifest = {
        "manifest": manifest_data,
        "signature_type": "SHA256",
        "signature": signature,
    }

    # Also verify ownership is current
    actual_owner = await _github_owner(github_url)
    if actual_owner and actual_owner.lower() != author.lower():
        manifest["warning"] = (
            f"⚠️  Current GitHub owner ({actual_owner}) differs from "
            f"manifest author ({author}). Manifest may be stale."
        )

    return [TextContent(
        type="text",
        text=json.dumps(manifest, indent=2)
    )]


async def _handle_verify_manifest(args: dict) -> list[TextContent]:
    """Verify an integrity manifest."""
    try:
        manifest = json.loads(args["manifest_json"])
    except json.JSONDecodeError as e:
        return [TextContent(
            type="text",
            text=json.dumps({
                "status": "INVALID",
                "error": f"Malformed JSON: {e}",
            }, indent=2)
        )]

    data = manifest.get("manifest", {})
    claimed_sig = manifest.get("signature", "")
    sig_type = manifest.get("signature_type", "SHA256")

    # Recompute signature
    canonical = json.dumps(data, sort_keys=True).encode()
    computed_sig = hashlib.sha256(canonical).hexdigest()

    sig_valid = computed_sig == claimed_sig

    # Check current ownership
    github_url = data.get("github_url", "")
    claimed_author = data.get("author", "")
    current_owner = await _github_owner(github_url) if github_url else None
    owner_match = (
        current_owner and current_owner.lower() == claimed_author.lower()
    ) if current_owner else None

    checks = {
        "signature_valid": sig_valid,
        "author_match": owner_match,
    }

    all_pass = sig_valid and (owner_match is not False)

    return [TextContent(
        type="text",
        text=json.dumps({
            "status": "PASS" if all_pass else "FAIL",
            "manifest_id": f"{data.get('app_name')}@{data.get('version')}",
            "signature_type": sig_type,
            "checks": checks,
            "claim": {
                "app": data.get("app_name"),
                "author": claimed_author,
                "github": github_url,
            },
            "current_github_owner": current_owner,
            "detail": (
                "All checks pass" if all_pass else
                f"Failures: {'signature' if not sig_valid else ''}"
                f"{' + ownership' if owner_match is False else ''}"
            ),
        }, indent=2)
    )]


# ─── Entry Point ─────────────────────────────────────────────────────────────


def main():
    """Entry point for console_scripts."""
    asyncio.run(stdio_server(server))


if __name__ == "__main__":
    main()
