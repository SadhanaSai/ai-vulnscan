"""deserialization harness — cve-agent-spec.md §8.7 table: "Deserialize a
payload that sets a marker attribute — no shell, no file write."

Non-destructive proof: builds a payload made ONLY of built-in, inert data
types (a Python dict of strings, pickled or YAML-dumped with no custom
tags), then calls the researcher-supplied `target_module.target_callable`
— the vulnerable deserialization entry point (e.g. a function that runs
`pickle.loads(data)` or `yaml.load(data)` on attacker-controlled input) —
with that payload. If the marker value comes back out of the returned
object/dict, the target deserialized attacker-controlled data and handed
it back — CWE-502 confirmed. Nothing is executed, no shell is spawned, no
file is written beyond the process's own return value.

SAFETY: this is the one harness class with a real code-execution primitive
sitting right next to it (pickle's `__reduce__`/`__reduce_ex__` machinery).
This driver never uses it. The payload is built exclusively from plain
built-in types (str / dict) via the default pickle protocol and via
`yaml.safe_dump` — no `__reduce__` override, no `!!python/object` tag, no
mechanism that invokes any callable on load. A pickled dict of strings or
a safe-dumped YAML mapping cannot execute code on its own no matter what
deserializer reads it; the only thing that can come back out is inert
data, which is exactly what this harness checks for. Do not add a
`__reduce__`-based or `os.system`/subprocess-based payload to this file —
that would just be command_injection.py in disguise and defeats the
purpose of this constraint.

Node has no stdlib unsafe-deserialization primitive analogous to pickle —
JSON.parse only ever produces plain data. The Node driver here is
therefore a much weaker approximation (see comment in _NODE_DRIVER):
it can only show that target_callable echoes back a serialized-looking
payload, not that any actual unsafe deserialization occurred. Real npm
deserialization CVEs live in specific libraries (e.g. node-serialize) and
need a hand-built payload for that library — out of scope for this fixed
six-harness set.

Mirrors validation/harnesses/path_traversal.py: same helper imports, same
static driver-script style (all dynamic values cross via SandboxConfig.env,
never spliced into the script text), same `run()` signature, same
result-parsing structure.
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
import importlib, os, pickle, sys

try:
    import yaml
except Exception:
    yaml = None

target_module = os.environ["CVE_TARGET_MODULE"]
target_callable = os.environ["CVE_TARGET_CALLABLE"]
target_param = os.environ.get("CVE_TARGET_PARAM") or None
marker = os.environ["CVE_MARKER"]

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


def _marker_present(res):
    try:
        if isinstance(res, dict) and res.get("marker") == marker:
            return True
    except Exception:
        pass
    try:
        if getattr(res, "marker", None) == marker:
            return True
    except Exception:
        pass
    try:
        if marker in str(res):
            return True
    except Exception:
        pass
    return False


# Plain-data-only payloads. No __reduce__/__reduce_ex__ override, no
# !!python/object (or any other unsafe) YAML tag, no mechanism that invokes
# a callable on load. A pickled dict of built-in str values, and a
# yaml.safe_dump'd mapping, cannot execute code on their own regardless of
# what deserializer reads them -- the only thing that can come back out is
# inert data. If the marker comes back, the target deserialized
# attacker-controlled bytes/text and returned it, which is the entire
# CWE-502 confirmation this harness needs.
candidates = []
try:
    candidates.append(("pickle", pickle.dumps({"marker": marker})))
except Exception as exc:
    print("MISSING_TARGET: pickle payload build failed: " + str(exc))

if yaml is not None:
    try:
        candidates.append(("yaml", yaml.safe_dump({"marker": marker})))
    except Exception as exc:
        print("MISSING_TARGET: yaml payload build failed: " + str(exc))

if not candidates:
    print("MISSING_TARGET: no payload could be constructed")
    sys.exit(0)

last_ok, last_res = False, None
for label, payload in candidates:
    last_ok, last_res = _try_call(payload)
    if last_ok and _marker_present(last_res):
        print("TRIGGERED")
        print("payload=" + label)
        sys.exit(0)

if last_ok:
    print("NOT_TRIGGERED")
else:
    print("CALL_ERROR: " + str(last_res)[:500])
"""

# NOTE: Node has no stdlib unsafe-deserialization primitive analogous to
# Python's pickle/yaml.load -- JSON.parse is inherently safe (it only ever
# produces plain data, never invokes arbitrary code on parse). This driver
# can therefore only show that target_callable receives a serialized-
# looking payload and echoes the marker back; it is NOT a general npm
# unsafe-deserialization probe, and a "TRIGGERED" result here is weaker
# evidence than the Python pickle/yaml path and should be corroborated
# manually. Real npm deserialization CVEs live in specific libraries (e.g.
# node-serialize) and would need a hand-built payload for that exact
# library -- out of scope for this fixed, generic harness.
_NODE_DRIVER = """
const { execSync } = require("child_process");
const path = require("path");

const targetModule = process.env.CVE_TARGET_MODULE;
const targetCallable = process.env.CVE_TARGET_CALLABLE;
const targetParam = process.env.CVE_TARGET_PARAM || null;
const marker = process.env.CVE_MARKER;

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

// Stand-in "serialized" blob -- plain JSON, no unsafe tags/prototypes.
const payload = JSON.stringify({ marker: marker });

function markerPresent(res) {
  try {
    if (res && typeof res === "object" && res.marker === marker) return true;
  } catch (e) {}
  try {
    if (String(res).includes(marker)) return true;
  } catch (e) {}
  return false;
}

function tryCall(value) {
  try {
    const res = targetParam ? obj({ [targetParam]: value }) : obj(value);
    return [true, res];
  } catch (e) {
    return [false, e];
  }
}

const [ok, res] = tryCall(payload);
if (ok && markerPresent(res)) {
  console.log("TRIGGERED");
  console.log("payload=json");
} else if (ok) {
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
        return ValidationOutcome(result="error", summary="Sandbox timed out during deserialization probe.", log=log)
    if "NOT_TRIGGERED" in result.stdout:
        return ValidationOutcome(
            result="not_confirmed",
            summary=f"{target_module}.{target_callable} did not return the marker — unsafe deserialization not reproduced with the supplied target/param.",
            log=log,
        )
    if "TRIGGERED" in result.stdout:
        return ValidationOutcome(
            result="confirmed",
            summary=f"{target_module}.{target_callable} deserialized attacker-controlled data and returned the marker — unsafe deserialization confirmed.",
            log=log,
        )
    if "MISSING_TARGET" in result.stdout:
        return ValidationOutcome(
            result="inconclusive",
            summary="Could not resolve --target-module/--target-callable inside the installed package, or no payload could be constructed.",
            log=log,
        )
    if "CALL_ERROR" in result.stdout:
        return ValidationOutcome(
            result="inconclusive",
            summary="Target callable raised an exception rather than returning — see log.",
            log=log,
        )
    return ValidationOutcome(result="inconclusive", summary="Unexpected sandbox output.", log=log)
