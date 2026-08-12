"""arbitrary_file_rw harness — cve-agent-spec.md §8.7 table: "Write/read a
marker file at an unintended path."

CWE-73, closely related to path_traversal (CWE-22) but distinct: a
target_callable for this class could expose either a WRITE primitive
(attacker-controlled content written to an attacker-controlled path) or a
READ primitive (attacker-controlled path read back to the caller). This
harness supports both, selected via the optional `target_mode` parameter
("write" | "read", default "write" — documented below).

READ MODE mirrors path_traversal.py almost exactly: plant a marker file
under /tmp, call the target with that path, check whether the marker comes
back in the return value.

WRITE MODE is the new logic: call the target with a marker-bearing content
value and a destination path outside any plausible intended/hardcoded
output subdirectory (e.g. "/sandbox/uploads/"), then check — from the
driver itself, reading the file back off disk — whether the target
actually wrote the marker to that unintended path. The container's own
writable surface is only /tmp and /sandbox (validation/sandbox.py's
--tmpfs mounts), so this isn't proving container escape; it's proving the
target honors a caller-supplied path rather than confining writes to an
expected subdirectory.

Reference implementation mirrored: validation/harnesses/path_traversal.py —
same helper imports, same static driver-script strings (all dynamic values
cross via SandboxConfig.env, never spliced into script text), same `run()`
shape, same result-parsing structure.
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
target_mode = os.environ.get("CVE_TARGET_MODE") or "write"
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

if target_mode == "write":
    # Prove the target honors a caller-supplied path outside any expected/
    # hardcoded output subdirectory (e.g. "/sandbox/uploads/") rather than
    # confining writes to it. Both /tmp and /sandbox are writable inside
    # this container (validation/sandbox.py tmpfs mounts) — the point isn't
    # container escape, it's confirming the target doesn't constrain the
    # destination path itself.
    dest_path = "/tmp/unintended_" + marker + ".txt"

    def _try_write():
        # First attempt: content= kwarg convention alongside the path kwarg.
        try:
            if target_param:
                obj(**{target_param: dest_path}, content=marker)
            else:
                obj(dest_path, content=marker)
            return True, None
        except TypeError as exc:
            return False, exc
        except Exception as exc:
            return False, exc

    ok, err = _try_write()
    if not ok:
        # Fall back: positional (path, content).
        try:
            obj(dest_path, marker)
            ok, err = True, None
        except Exception as exc:
            ok, err = False, exc

    if not ok:
        print("CALL_ERROR: " + str(err)[:500])
        sys.exit(0)

    if os.path.exists(dest_path):
        try:
            with open(dest_path, "r") as f:
                written = f.read()
        except Exception as exc:
            print("CALL_ERROR: could not read back " + dest_path + ": " + str(exc))
            sys.exit(0)
        if marker in written:
            print("TRIGGERED")
            print("mode=write")
            print("path=" + dest_path)
            sys.exit(0)

    print("NOT_TRIGGERED")

else:
    # Read mode — near-identical to path_traversal.py's driver.
    marker_path = "/tmp/" + marker + ".txt"
    with open(marker_path, "w") as f:
        f.write(marker)

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
                print("mode=read")
                print("path=" + candidate)
                sys.exit(0)

    if ok:
        print("NOT_TRIGGERED")
    else:
        print("CALL_ERROR: " + str(res)[:500])
"""

# Note: if target_callable returns a Promise (async function), this driver
# does not await it — the returned value/side effect will not be observed
# reliably, and marker detection will fail even on a truly vulnerable
# target. Documented limitation, not a silent gap: an async npm target
# needs a hand-adapted driver, out of scope for the fixed six-harness set.
#
# JS signature-detection note: unlike Python, calling a JS function with an
# unexpected object shape or wrong arity does not reliably throw a
# TypeError — extra object keys are silently ignored and missing
# positional args just become `undefined`. So instead of trying to detect
# a TypeError to decide whether to fall back, this driver tries the
# object-call form first, checks on disk whether the write actually
# happened, and only if it didn't, tries the positional form and checks
# again. If neither attempt produces the file (and neither throws), the
# result is NOT_TRIGGERED rather than inferring a signature mismatch.
_NODE_DRIVER = """
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const targetModule = process.env.CVE_TARGET_MODULE;
const targetCallable = process.env.CVE_TARGET_CALLABLE;
const targetParam = process.env.CVE_TARGET_PARAM || null;
const targetMode = process.env.CVE_TARGET_MODE || "write";
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

if (targetMode === "write") {
  const destPath = "/tmp/unintended_" + marker + ".txt";

  function attempt(fn) {
    try {
      fn();
      return null;
    } catch (e) {
      return e;
    }
  }

  // Attempt 1: object-call form ({[targetParam]: path, content: marker}).
  let err = attempt(() => {
    if (targetParam) {
      obj({ [targetParam]: destPath, content: marker });
    } else {
      obj(destPath, marker);
    }
  });

  let written = fs.existsSync(destPath) && fs.readFileSync(destPath, "utf8").includes(marker);

  if (!written) {
    // Attempt 2: positional (path, content) form.
    const err2 = attempt(() => obj(destPath, marker));
    if (err === null) err = err2;
    written = fs.existsSync(destPath) && fs.readFileSync(destPath, "utf8").includes(marker);
  }

  if (written) {
    console.log("TRIGGERED");
    console.log("mode=write");
    console.log("path=" + destPath);
    process.exit(0);
  }

  if (err !== null && !fs.existsSync(destPath)) {
    console.log("CALL_ERROR: " + String(err.message || err).slice(0, 500));
    process.exit(0);
  }

  console.log("NOT_TRIGGERED");

} else {
  // Read mode — near-identical to path_traversal.py's Node driver.
  const markerPath = "/tmp/" + marker + ".txt";
  fs.writeFileSync(markerPath, marker);

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
        console.log("mode=read");
        console.log("path=" + candidate);
        process.exit(0);
      }
    }
  }

  if (ok) {
    console.log("NOT_TRIGGERED");
  } else {
    console.log("CALL_ERROR: " + String(res).slice(0, 500));
  }
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
    target_mode: str | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> ValidationOutcome:
    require_target(target_module, target_callable)

    mode = target_mode or "write"
    if mode not in ("write", "read"):
        return ValidationOutcome(
            result="error",
            summary=f"target_mode must be 'write' or 'read' — got {target_mode!r}.",
            log="",
        )

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
            "CVE_TARGET_MODE": mode,
            "CVE_MARKER": marker,
        },
    )
    result = await run_in_sandbox(config)
    log = format_log(result)

    direction = "write" if "mode=write" in result.stdout else "read" if "mode=read" in result.stdout else mode

    if result.timed_out:
        return ValidationOutcome(result="error", summary="Sandbox timed out during arbitrary_file_rw probe.", log=log)
    if "NOT_TRIGGERED" in result.stdout:
        return ValidationOutcome(
            result="not_confirmed",
            summary=(
                f"{target_module}.{target_callable} did not demonstrate an arbitrary file "
                f"{direction} at an unintended path with the supplied target/param (mode={mode})."
            ),
            log=log,
        )
    if "TRIGGERED" in result.stdout:
        return ValidationOutcome(
            result="confirmed",
            summary=(
                f"{target_module}.{target_callable} confirmed arbitrary file {direction}: "
                f"a marker was {'written to' if direction == 'write' else 'read back from'} "
                "a path outside its intended directory."
            ),
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
            summary="Target callable raised an exception rather than completing — see log.",
            log=log,
        )
    return ValidationOutcome(result="inconclusive", summary="Unexpected sandbox output.", log=log)
