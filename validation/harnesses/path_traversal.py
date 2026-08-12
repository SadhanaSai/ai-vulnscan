"""path_traversal harness — cve-agent-spec.md §8.7 table: "Read a benign
marker file placed outside the intended directory."

Non-destructive proof: plants a random marker token in a file under `/tmp`
(outside the container's `/sandbox` working directory), then calls the
researcher-supplied `target_module.target_callable` with a traversal path
aimed at that marker file. If the marker text comes back, the target reads
outside its intended containment directory — confirmed. Nothing is deleted,
overwritten, or executed beyond that one read attempt.

This is the reference implementation other harnesses in this package
mirror: static driver scripts (no per-run string interpolation — all
dynamic values cross via SandboxConfig.env), installed-image caching via
validation.image_cache, single-use no-network execution via
validation.sandbox.
"""

from __future__ import annotations

from state.db import Finding
from validation._shared import ValidationOutcome
from validation.harnesses._shared import (
    DEFAULT_TIMEOUT_SECONDS,
    build_image,
    format_log,
    random_marker,
    require_target,
)
from validation.sandbox import SandboxConfig, run_in_sandbox

_PYTHON_DRIVER = """
import importlib, os, sys

target_module = os.environ["CVE_TARGET_MODULE"]
target_callable = os.environ["CVE_TARGET_CALLABLE"]
target_param = os.environ.get("CVE_TARGET_PARAM") or None
marker = os.environ["CVE_MARKER"]

marker_path = "/tmp/" + marker + ".txt"
with open(marker_path, "w") as f:
    f.write(marker)

try:
    mod = importlib.import_module(target_module)
except Exception as exc:
    print("MISSING_TARGET: import failed: " + str(exc))
    sys.exit(0)

obj = mod
try:
    for part in target_callable.split("."):
        obj = getattr(obj, part)
except Exception as exc:
    print("MISSING_TARGET: attribute lookup failed: " + str(exc))
    sys.exit(0)


def _try_call(value):
    try:
        if target_param:
            return True, obj(**{target_param: value})
        return True, obj(value)
    except Exception as exc:
        return False, exc


base_dir = "/sandbox"
payload = os.path.relpath(marker_path, base_dir)

ok, res = False, None
for candidate in (payload, marker_path):
    ok, res = _try_call(candidate)
    if ok:
        if isinstance(res, (bytes, bytearray)):
            text = res.decode(errors="replace")
        else:
            text = res if isinstance(res, str) else str(res)
        if marker in text:
            print("TRIGGERED")
            print("payload=" + candidate)
            sys.exit(0)

if ok:
    print("NOT_TRIGGERED")
else:
    print("CALL_ERROR: " + str(res)[:500])
"""

# Note: if target_callable returns a Promise (async function), this driver
# does not await it — the returned value will be a Promise object, not the
# resolved result, and marker detection will fail even on a truly vulnerable
# target. Documented limitation, not a silent gap: an async npm target needs
# a hand-adapted driver, out of scope for the fixed six-harness set.
_NODE_DRIVER = """
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const targetModule = process.env.CVE_TARGET_MODULE;
const targetCallable = process.env.CVE_TARGET_CALLABLE;
const targetParam = process.env.CVE_TARGET_PARAM || null;
const marker = process.env.CVE_MARKER;

const markerPath = "/tmp/" + marker + ".txt";
fs.writeFileSync(markerPath, marker);

let root;
try {
  root = execSync("npm root -g").toString().trim();
} catch (e) {
  console.log("MISSING_TARGET: npm root -g failed: " + e.message);
  process.exit(0);
}

let mod;
try {
  mod = require(path.join(root, targetModule));
} catch (e) {
  console.log("MISSING_TARGET: require failed: " + e.message);
  process.exit(0);
}

let obj = mod;
try {
  for (const part of targetCallable.split(".")) {
    obj = obj[part];
  }
} catch (e) {
  console.log("MISSING_TARGET: attribute lookup failed: " + e.message);
  process.exit(0);
}

const baseDir = "/sandbox";
const payload = path.relative(baseDir, markerPath);

function tryCall(value) {
  try {
    const res = targetParam ? obj({ [targetParam]: value }) : obj(value);
    return [true, res];
  } catch (e) {
    return [false, e];
  }
}

let ok = false;
let res = null;
for (const candidate of [payload, markerPath]) {
  [ok, res] = tryCall(candidate);
  if (ok) {
    const text = typeof res === "string" ? res : Buffer.isBuffer(res) ? res.toString() : String(res);
    if (text.includes(marker)) {
      console.log("TRIGGERED");
      console.log("payload=" + candidate);
      process.exit(0);
    }
  }
}

if (ok) {
  console.log("NOT_TRIGGERED");
} else {
  console.log("CALL_ERROR: " + String(res).slice(0, 500));
}
"""


async def run(
    finding: Finding,
    *,
    package: str,
    ecosystem: str,
    version: str,
    target_module: str | None,
    target_callable: str | None,
    target_param: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> ValidationOutcome:
    require_target(target_module, target_callable)

    image, err = await build_image(package, ecosystem, version)
    if err:
        return err

    if ecosystem == "pypi":
        command = ["python3", "-c", _PYTHON_DRIVER]
    elif ecosystem == "npm":
        command = ["node", "-e", _NODE_DRIVER]
    else:
        return ValidationOutcome(result="error", summary=f"Unsupported ecosystem {ecosystem!r}", log="")

    marker = random_marker()
    config = SandboxConfig(
        image=image,
        command=command,
        network_mode="none",
        timeout_seconds=timeout_seconds,
        env={
            "CVE_TARGET_MODULE": target_module,
            "CVE_TARGET_CALLABLE": target_callable,
            "CVE_TARGET_PARAM": target_param or "",
            "CVE_MARKER": marker,
        },
    )
    result = await run_in_sandbox(config)
    log = format_log(result)

    if result.timed_out:
        return ValidationOutcome(result="error", summary="Sandbox timed out during path_traversal probe.", log=log)
    if "NOT_TRIGGERED" in result.stdout:
        return ValidationOutcome(
            result="not_confirmed",
            summary=f"{target_module}.{target_callable} did not return the marker — traversal not reproduced with the supplied target/param.",
            log=log,
        )
    if "TRIGGERED" in result.stdout:
        return ValidationOutcome(
            result="confirmed",
            summary=f"{target_module}.{target_callable} returned a marker planted outside its intended directory — path traversal confirmed.",
            log=log,
        )
    if "MISSING_TARGET" in result.stdout:
        return ValidationOutcome(
            result="inconclusive",
            summary="Could not resolve --target-module/--target-callable inside the installed package.",
            log=log,
        )
    if "CALL_ERROR" in result.stdout:
        return ValidationOutcome(
            result="inconclusive",
            summary="Target callable raised an exception rather than returning — see log.",
            log=log,
        )
    return ValidationOutcome(result="inconclusive", summary="Unexpected sandbox output.", log=log)
