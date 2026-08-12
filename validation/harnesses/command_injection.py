"""command_injection harness — cve-agent-spec.md §8.7 table: "Echo a random
marker string via the injection point."

Non-destructive proof: builds a shell-injection payload around a random
marker token — e.g. `"; echo " + marker + " #"` — and passes it to the
researcher-supplied `target_module.target_callable`. If the target passes
the value unsanitized into a shell (os.system/subprocess with shell=True in
Python; child_process.exec in Node), the marker gets echoed back out. If the
marker text turns up anywhere the driver can observe — the target's return
value, or the driver process's own stdout/stderr (many injection-vulnerable
functions call os.system()/subprocess.run() without capturing output, so the
echoed marker lands on the driver's own stdout rather than being returned) —
the injection is confirmed. The payload only ever echoes; it never deletes,
writes outside `/sandbox`/`/tmp`, or attempts network egress.

Mirrors validation/harnesses/path_traversal.py: static driver scripts (no
per-run string interpolation — all dynamic values cross via SandboxConfig.env),
installed-image caching via validation.image_cache, single-use no-network
execution via validation.sandbox.
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

# The driver captures its own stdout/stderr around the call (many injection-
# vulnerable targets shell out via os.system()/subprocess.run() without
# capturing output, so the echoed marker lands on the driver process's own
# stdout rather than in whatever the target callable returns) and also
# stringifies the return value, checking the marker against both.
_PYTHON_DRIVER = """
import contextlib, importlib, io, os, sys

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
    buf_out, buf_err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            if target_param:
                res = obj(**{target_param: value})
            else:
                res = obj(value)
        return True, res, buf_out.getvalue(), buf_err.getvalue()
    except Exception as exc:
        return False, exc, buf_out.getvalue(), buf_err.getvalue()


# A single, benign echo. Combines a semicolon-terminated command and a
# backtick/$() substitution variant into one payload so it round-trips
# whichever shell-invocation style (os.system, subprocess with shell=True,
# etc.) the target uses — nothing here writes, deletes, or reaches the
# network, it only ever echoes the marker back out.
payload = "; echo " + marker + " #"
alt_payload = "`echo " + marker + "`"

ok, res, out, err = False, None, "", ""
for candidate in (payload, alt_payload):
    ok, res, out, err = _try_call(candidate)
    captured = out + err
    return_text = res if isinstance(res, str) else str(res)
    if marker in captured or marker in return_text:
        print("TRIGGERED")
        print("payload=" + candidate)
        sys.exit(0)

if ok:
    print("NOT_TRIGGERED")
else:
    print("CALL_ERROR: " + str(res)[:500])
"""

# Note: Node's child_process.exec/execSync writes the child's output either
# to a captured buffer (execSync's return value, or exec's callback args) or,
# if the target discards those and only forwards its own inherited stdio,
# straight past this driver entirely — Node has no built-in equivalent of
# Python's contextlib.redirect_stdout for a child process's *inherited*
# stdio short of monkey-patching process.stdout.write before the call, so
# this driver only checks the stringified return value. A target that shells
# out via execSync but discards/ignores the return value and never surfaces
# the marker in it will read as NOT_TRIGGERED even if it is actually
# vulnerable — documented limitation, same in spirit to the async-Promise
# limitation in path_traversal.py's Node driver, not a silent gap.
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

// A single, benign echo — semicolon-terminated command plus a backtick
// substitution variant, so it round-trips whichever shell-invocation style
// (child_process.exec, execSync, etc.) the target uses. Nothing here writes,
// deletes, or reaches the network, it only ever echoes the marker back out.
const payload = "; echo " + marker + " #";
const altPayload = "`echo " + marker + "`";

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
for (const candidate of [payload, altPayload]) {
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
        return ValidationOutcome(result="error", summary="Sandbox timed out during command_injection probe.", log=log)
    if "NOT_TRIGGERED" in result.stdout:
        return ValidationOutcome(
            result="not_confirmed",
            summary=f"{target_module}.{target_callable} did not echo the marker — command injection not reproduced with the supplied target/param.",
            log=log,
        )
    if "TRIGGERED" in result.stdout:
        return ValidationOutcome(
            result="confirmed",
            summary=f"{target_module}.{target_callable} echoed the marker via the injection point — command injection confirmed.",
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
