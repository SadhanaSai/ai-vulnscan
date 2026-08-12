"""Default `validate` depth — cve-agent-spec.md §8.7, "1. Default — pattern
confirmation."

Installs the exact affected `package==version` (validation/image_cache.py —
network access confined to that one-time, cached build step), then in a
fresh, single-use, no-network container confirms the flagged vulnerable code
shape is physically present in the *installed* artifact — not just in the
GitHub source read statically in §8.4/§8.5, which can differ (sdist/wheel
builds sometimes exclude files; a git tag can lag or lead the published
release).

Scope, stated precisely: this confirms *presence* of the vulnerable code
shape's keywords in the shipped package at the affected version. It does
not prove the code path is reachable from an entry point or exploitable —
that is what `--class {name}` (validation/harnesses/) checks, once the
researcher supplies the concrete target. No payload runs here; nothing is
triggered — this is a grep against installed files, executed from inside
the sandbox only because "the installed files" only exist there.
"""

from __future__ import annotations

import json

from hunter.scanner import load_vulnerability_classes
from llm.router import DEFAULT_SCAN_CONFIG_PATH
from state.db import Finding
from validation._shared import ValidationOutcome
from validation.classify import infer_vulnerability_classes
from validation.image_cache import ImageBuildError, ensure_install_image
from validation.sandbox import SandboxConfig, run_in_sandbox

MAX_KEYWORDS = 12
DEFAULT_TIMEOUT_SECONDS = 120

# Static driver scripts — no per-run string interpolation. All dynamic
# values (package name, keyword list) cross into the sandbox exclusively
# via SandboxConfig.env, never by being spliced into this source text, so
# there is no shell/script-injection surface here regardless of what a
# package name or keyword string contains.
_PYTHON_SHAPE_CHECK = """
import json, os, subprocess, sys

package = os.environ["CVE_PACKAGE"]
keywords = json.loads(os.environ["CVE_KEYWORDS"])

try:
    out = subprocess.run(["pip", "show", "-f", package], capture_output=True, text=True, timeout=30)
except Exception as exc:
    print("ERROR: " + str(exc))
    sys.exit(0)

if out.returncode != 0:
    print("NOT_INSTALLED")
    sys.exit(0)

location = None
files = []
in_files = False
for line in out.stdout.splitlines():
    if line.startswith("Location:"):
        location = line.split(":", 1)[1].strip()
    elif line.startswith("Files:"):
        in_files = True
    elif in_files and line.startswith("  "):
        files.append(line.strip())

if not location or not files:
    print("NOT_INSTALLED")
    sys.exit(0)

hits = []
for rel in files:
    if not rel.endswith(".py"):
        continue
    path = os.path.join(location, rel)
    try:
        with open(path, "r", errors="ignore") as fh:
            content = fh.read().lower()
    except OSError:
        continue
    for kw in keywords:
        if kw.lower() in content:
            hits.append(rel + ": " + kw)
            break

if hits:
    print("SHAPE_FOUND")
    for h in hits[:10]:
        print(h)
else:
    print("SHAPE_NOT_FOUND")
"""

_NODE_SHAPE_CHECK = """
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const pkg = process.env.CVE_PACKAGE;
const keywords = JSON.parse(process.env.CVE_KEYWORDS);

let root;
try {
  root = execSync("npm root -g").toString().trim();
} catch (e) {
  console.log("ERROR: " + e.message);
  process.exit(0);
}

const pkgDir = path.join(root, pkg);
if (!fs.existsSync(pkgDir)) {
  console.log("NOT_INSTALLED");
  process.exit(0);
}

const SKIP_DIRS = new Set(["node_modules", "test", "tests", ".git"]);
const files = [];
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full);
    else if (/\\.(js|ts|mjs|cjs)$/.test(entry.name)) files.push(full);
  }
}
walk(pkgDir);

const hits = [];
for (const f of files) {
  let content;
  try { content = fs.readFileSync(f, "utf8").toLowerCase(); } catch (e) { continue; }
  for (const kw of keywords) {
    if (content.includes(kw.toLowerCase())) {
      hits.push(f + ": " + kw);
      break;
    }
  }
}

if (hits.length) {
  console.log("SHAPE_FOUND");
  hits.slice(0, 10).forEach((h) => console.log(h));
} else {
  console.log("SHAPE_NOT_FOUND");
}
"""


async def confirm_pattern(
    finding: Finding,
    *,
    package: str,
    ecosystem: str,
    version: str,
    config_path: str = DEFAULT_SCAN_CONFIG_PATH,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> ValidationOutcome:
    classes = infer_vulnerability_classes(finding, config_path=config_path)
    if not classes:
        return ValidationOutcome(
            result="inconclusive",
            summary=(
                "No harness-eligible vulnerability class could be inferred from this "
                "finding's CWE(s) — nothing to search for."
            ),
            log="",
        )

    vuln_classes = load_vulnerability_classes(config_path)
    keywords: list[str] = []
    for cls in classes:
        keywords += vuln_classes.get(cls, {}).get("keywords", [])
    keywords = keywords[:MAX_KEYWORDS]

    try:
        image = await ensure_install_image(package=package, ecosystem=ecosystem, version=version)
    except ImageBuildError as exc:
        return ValidationOutcome(result="error", summary=f"Could not install {package}=={version}: {exc}", log=str(exc))

    if ecosystem == "pypi":
        command = ["python3", "-c", _PYTHON_SHAPE_CHECK]
    elif ecosystem == "npm":
        command = ["node", "-e", _NODE_SHAPE_CHECK]
    else:
        return ValidationOutcome(result="error", summary=f"Unsupported ecosystem {ecosystem!r}", log="")

    config = SandboxConfig(
        image=image,
        command=command,
        network_mode="none",
        timeout_seconds=timeout_seconds,
        env={"CVE_PACKAGE": package, "CVE_KEYWORDS": json.dumps(keywords)},
    )
    result = await run_in_sandbox(config)
    log = f"$ {' '.join(result.command_run)}\n--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"

    if result.timed_out:
        return ValidationOutcome(result="error", summary="Sandbox timed out during pattern confirmation.", log=log)
    if "SHAPE_FOUND" in result.stdout:
        return ValidationOutcome(
            result="confirmed",
            summary=f"Vulnerable code shape for {', '.join(classes)} found in the installed {package}=={version} artifact.",
            log=log,
        )
    if "SHAPE_NOT_FOUND" in result.stdout:
        return ValidationOutcome(
            result="not_confirmed",
            summary=f"No match for {', '.join(classes)} keywords in the installed {package}=={version} artifact.",
            log=log,
        )
    if "NOT_INSTALLED" in result.stdout:
        return ValidationOutcome(
            result="inconclusive",
            summary=f"{package}=={version} did not resolve to an installed package inside the sandbox.",
            log=log,
        )
    return ValidationOutcome(result="inconclusive", summary="Unexpected sandbox output.", log=log)
