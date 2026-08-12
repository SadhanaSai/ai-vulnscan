"""ssrf harness — cve-agent-spec.md §8.7 table: "Confirm a request arrives
at a throwaway 127.0.0.1 listener started just for the run."

Non-destructive proof: starts a minimal HTTP listener bound to 127.0.0.1 on
an OS-assigned port, inside the same sandbox container the target package is
installed in, then calls the researcher-supplied `target_module.target_callable`
with a URL pointing at that listener. If the listener records an incoming
request (ideally with the embedded marker still present in the request
path), the target made an outbound request to an address it was handed at
runtime — SSRF confirmed. The listener never forwards, proxies, or acts on
the request beyond recording that it arrived and returning a bare 200 — it
is a dead end, not a redirector, so nothing the target does with the
"response" can be used to reach anywhere else.

This is the one harness of the six that needs *some* loopback networking
(a listener plus a request reaching it). That still fits under
network_mode="none": per validation/sandbox.py, `--network none` removes the
container's external network stack entirely but the container keeps its own
private loopback interface — confirmed by
tests/test_sandbox.py::test_sandbox_none_network_has_no_loopback_reachable_service,
which only asserts no eth0/external interface is reachable, not that
loopback itself is gone. Both the listener and the call that is supposed to
reach it happen inside that same single container, so there is no external
routing involved at any point — "isolated" (which spins up a whole extra
per-run docker network) would buy nothing here and is deliberately not used.

Mirrors validation/harnesses/path_traversal.py's shape: static driver
scripts (no per-run string interpolation — all dynamic values cross via
SandboxConfig.env), installed-image caching via validation.image_cache,
single-use execution via validation.sandbox.
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
import importlib, os, sys, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer

target_module = os.environ["CVE_TARGET_MODULE"]
target_callable = os.environ["CVE_TARGET_CALLABLE"]
target_param = os.environ.get("CVE_TARGET_PARAM") or None
marker = os.environ["CVE_MARKER"]

hits = []
hit_lock = threading.Lock()


class _Handler(BaseHTTPRequestHandler):
    def _record(self):
        with hit_lock:
            hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._record()

    def do_POST(self):
        self._record()

    def do_PUT(self):
        self._record()

    def do_HEAD(self):
        self._record()

    def log_message(self, *args):
        pass  # keep the sandbox's captured stdout limited to our own sentinels


server = HTTPServer(("127.0.0.1", 0), _Handler)
port = server.server_address[1]
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()

payload_url = "http://127.0.0.1:" + str(port) + "/" + marker

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

call_error = None
try:
    if target_param:
        obj(**{target_param: payload_url})
    else:
        obj(payload_url)
except Exception as exc:
    call_error = exc

# target_callable may block until its own request completes, or may kick the
# request off asynchronously and return immediately — poll briefly either way.
deadline = time.monotonic() + 5.0
matched_path = None
while time.monotonic() < deadline:
    with hit_lock:
        for path in hits:
            if marker in path:
                matched_path = path
                break
        if matched_path is None and hits:
            matched_path = hits[0]
    if matched_path is not None:
        break
    time.sleep(0.25)

if matched_path is not None:
    print("TRIGGERED")
    print("path=" + matched_path)
elif call_error is not None:
    print("CALL_ERROR: " + str(call_error)[:500])
else:
    print("NOT_TRIGGERED")
"""

# Note: if target_callable returns a Promise (async function), this driver
# does not await it — the call may still schedule the outbound request (in
# which case the listener can still record it during the poll window), but
# any exception the async function raises internally will not surface here
# as a synchronous throw. Documented limitation, not a silent gap: an async
# npm target needing its rejection observed needs a hand-adapted driver, out
# of scope for the fixed six-harness set.
_NODE_DRIVER = """
const { execSync } = require("child_process");
const http = require("http");
const path = require("path");

const targetModule = process.env.CVE_TARGET_MODULE;
const targetCallable = process.env.CVE_TARGET_CALLABLE;
const targetParam = process.env.CVE_TARGET_PARAM || null;
const marker = process.env.CVE_MARKER;

const hits = [];

const server = http.createServer((req, res) => {
  hits.push(req.url);
  res.writeHead(200, { "Content-Length": "0" });
  res.end();
});

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

(async () => {
  await new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", resolve);
    server.on("error", reject);
  });
  const port = server.address().port;
  const payloadUrl = "http://127.0.0.1:" + port + "/" + marker;

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

  let callError = null;
  try {
    if (targetParam) {
      obj({ [targetParam]: payloadUrl });
    } else {
      obj(payloadUrl);
    }
  } catch (e) {
    callError = e;
  }

  // target_callable may block until its own request completes, or kick the
  // request off asynchronously (including via its own returned Promise, not
  // awaited here per the limitation above) — poll briefly either way.
  const deadline = Date.now() + 5000;
  let matchedPath = null;
  while (Date.now() < deadline) {
    matchedPath = hits.find((p) => p.includes(marker)) || (hits.length > 0 ? hits[0] : null);
    if (matchedPath !== null) {
      break;
    }
    await sleep(250);
  }

  if (matchedPath !== null) {
    console.log("TRIGGERED");
    console.log("path=" + matchedPath);
  } else if (callError !== null) {
    console.log("CALL_ERROR: " + String(callError).slice(0, 500));
  } else {
    console.log("NOT_TRIGGERED");
  }
  process.exit(0);
})();
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
        # Loopback-only, no external egress — the listener and the request
        # that is supposed to reach it both live inside this one container,
        # so "none" (not "isolated") is correct: see module docstring.
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
        return ValidationOutcome(result="error", summary="Sandbox timed out during ssrf probe.", log=log)
    if "NOT_TRIGGERED" in result.stdout:
        return ValidationOutcome(
            result="not_confirmed",
            summary=f"{target_module}.{target_callable} did not cause any request to reach our throwaway 127.0.0.1 listener — SSRF not reproduced with the supplied target/param.",
            log=log,
        )
    if "TRIGGERED" in result.stdout:
        return ValidationOutcome(
            result="confirmed",
            summary=f"{target_module}.{target_callable}'s own outbound request reached our throwaway 127.0.0.1 listener — SSRF confirmed.",
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
            summary="Target callable raised an exception rather than reaching the listener — see log.",
            log=log,
        )
    return ValidationOutcome(result="inconclusive", summary="Unexpected sandbox output.", log=log)
