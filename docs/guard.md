# straiker-broker guard

`straiker-broker guard` checks the model calls of agents running in [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell)
sandboxes with Straiker Defend, inline. It is an OpenShell **supervisor middleware**. OpenShell's sandbox supervisors
call it for each HTTP request an agent sends to a model provider, before OpenShell injects the provider's credentials,
and for each answer, before the agent receives it. The guard is a separate process from the broker's connectivity
agent (`straiker-broker run`). It shares only the binary, the environments and the service installer. OpenShell is
the gateway it serves today; another gateway would be another adapter in the same guard, with its own settings.

```
 sandbox ──► OpenShell supervisor ──► model provider
               │  ▲     request: allow / deny
               ▼  │     answer:  release / cut off
       straiker-broker guard ──► https://api.<env>.straiker.ai/api/v3/detect
          (gRPC, TLS, gateway-signed token)            (integration key)
```

- **Requests:** the guard sends each Anthropic Messages, OpenAI Chat Completions or OpenAI Responses request to
  Defend as the agent sent it.
  - When Defend says `block`, the request is denied: it never reaches the provider. With `--on-block replace` it
    goes ahead changed instead (see **Blocks** below), so the agent gets an ordinary answer.
  - When Defend says `allow` or `detect`, it proceeds. Defend records a `detect`, and the guard reports one finding
    per control to OpenShell.
  - The guard recognises a model call by its path (`…/messages`, `…/chat/completions`, `…/responses`, Vertex's
    Anthropic `:streamRawPredict`) and by the shape of its body, on any host. Every other request passes
    unchecked.
- **Answers:** a streamed answer is released to the agent piece by piece, as it arrives.
  - As soon as a tool call the agent would run is complete, the guard sends the answer so far to Defend. That is an
    Anthropic `tool_use` block's `content_block_stop`, a Chat Completions `finish_reason: tool_calls`, or a Responses
    `function_call` (or other client-side tool) item's `response.output_item.done`.
  - If Defend blocks, OpenShell cuts the stream before the piece that completes the call. The agent never receives a
    runnable call.
  - What no check has covered, such as text after the last tool call, is checked at the end.
  - A JSON (non-streamed) answer is checked whole before any of it is released. A block then becomes OpenShell's
    `403 middleware_denied`.
- **Kill switch:** an agent killswitched in Straiker gets `block` from Defend, with reason code
  `straiker_killswitch`.
- **Blocks.** `--on-block deny` (the default) denies the call, which reaches the agent as an error. Some agent
  runtimes treat that as fatal: NVIDIA NemoClaw's Fabric runtime exits, and the agent stays down until restarted.
  `--on-block replace` keeps the agent running instead:
  - **Masked:** a request blocked only for a credential (`api_key`) goes ahead with every credential redacted to
    `[REDACTED by Straiker: <type>]`, once Straiker clears the redacted request. Masking reads the JSON's decoded
    strings (so an escape can't hide a key) and removes a PEM private key through its END line. The credential never
    reaches the provider: a body in which any credential is still found after masking gets the stub instead.
  - **Stub:** anything else is replaced by a request asking the model for a notice ("Straiker Defend blocked this
    message, so it was not sent to the model."), carrying nothing of the original but the model.
  - The kill switch always denies.
- **When Straiker gives no verdict** (unreachable, slower than `--straiker-timeout`, an error status, an unreadable
  reply), the guard first runs its **own credential check** on what the request adds to the conversation (or on the
  answer, with a stream's text and tool arguments rebuilt from their deltas, so a key split across pieces is whole):
  15 key formats whose shape proves what they are, taken from Defend's `api_key` control (AWS, GitHub,
  OpenAI, Anthropic, GitLab, Slack, Google, Hugging Face, npm, Stripe, DigitalOcean, SendGrid, PEM private keys). A
  credential is denied (masked with `--on-block replace`), whatever `--on-straiker-error` says. Otherwise the guard
  applies `--on-straiker-error`.
  - `allow` is the default: monitor-safe, so a Straiker outage never stops an agent.
  - `deny` denies the call (a stub with `--on-block replace`). It also denies what the guard can't check: a model
    request whose body it can't read (compressed, or not JSON), an answer it can't read or that is too large to keep,
    a request it has no room to hold for its answer's check, and an answer whose held request was dropped (for room,
    or because it came more than 2 minutes later).
  - Every check of one request, a masked request's re-check included, shares one deadline of 6.5s, inside
    OpenShell's 7s per-call timeout. So OpenShell's `on_error` (default `fail_closed`) applies only when the guard
    itself is down.
- **Timeouts.** Defend answers most checks in under a second. A check where a control fires takes a second or two
  longer, because Defend confirms the finding before it answers. So the guard waits up to 6s by default
  (`--straiker-timeout`), and the registration's `timeout` must be above that: 7s. With OpenShell's default of
  500ms, every call where a control fires would time out and fail closed.

## Set up

1. **Get the integration key.** Connecting the gateway in the Straiker console (the NVIDIA OpenShell integration, the
   same one Discover and Ascend use) shows its key (`sk_agt_…`) once; if it is lost, mint another on that integration.
   Put the key alone in a file only the guard can read (mode 600), e.g. `/etc/straiker/guard.key`.

2. **Make the guard's certificate.** Name every host the gateway and the sandboxes reach the guard at. Both must
   reach it over TCP: OpenShell does not support Unix sockets for middleware.

   ```sh
   straiker-broker guard ca --host guard.corp.internal > straiker-guard-ca.pem
   ```

   This creates a private CA and a server certificate in the guard's directory. It prints the CA on stdout, and on
   stderr the gateway configuration to add. Run it again with more hosts later: it keeps the CA, so the gateway
   needs no change.

3. **Register the guard with the gateway** (gateway TOML), then restart the gateway after the guard is running:

   ```toml
   [[openshell.supervisor.middleware]]
   name = "straiker-guard"
   grpc_endpoint = "https://guard.corp.internal:50051"
   tls_ca_cert_path = "/etc/openshell/straiker-guard-ca.pem"
   max_payload_bytes = 4194304
   timeout = "7s"      # above the guard's --straiker-timeout (6s); OpenShell's 500ms default is too short
   audience = "urn:openshell:extension:middleware:straiker-guard"
   ```

   The gateway must have JWT signing configured: the guard refuses every call without a valid gateway token, from its
   headers, before reading its message, and serves at most 1024 calls at once per gateway connection. Do not set
   `allow_insecure_transport`, which sends no token at all.

4. **Run the guard** with the gateway's id and its signing keys:

   ```sh
   straiker-broker guard run --gateway-id <gateway id> --gateway-jwks /etc/straiker/openshell-jwks.json \
     --api-key-file /etc/straiker/guard.key
   ```

   - **Gateway id:** the `<id>` in the gateway's tokens' `iss: openshell-gateway:<id>`.
   - **Gateway keys:** a JWKS file or a PEM public key, copied from the gateway operator, or the gateway's own
     `https://<gateway>/.well-known/jwks.json`.
   - **Prefer a file.** The gateway starts only after its middleware answers, so on a cold start a URL cannot be
     fetched until the gateway is up. A URL is retried every 30s until it loads, then refreshed every 10 minutes.
   - **Rotation:** an unknown key id reloads either source, at most every 30s.

   To keep it running: `straiker-broker guard service install` with the same flags. That is a Windows service
   (`StraikerBrokerGuard`), a macOS LaunchAgent, or a systemd user service (`straiker-broker-guard`). The service
   reads its key from `--api-key-file`, never from its own definition. On Windows, keep the key file in the guard's
   directory, which the service account is granted.

5. **Attach it in sandbox policy**, for the model providers' hosts:

   ```yaml
   network_middlewares:
     straiker:
       middleware: straiker-guard
       endpoints:
         include: ["api.anthropic.com", "api.openai.com"]
       config:           # optional: both default to true
         request: true   # check model requests
         response: true  # check model answers
   ```

   Keep both of the guard's bindings in the gateway registration (the default): an answer's check needs its request,
   which the guard holds from the request call even with `request: false`.

   The gateway validates `config` with the guard (`ValidateConfig`) before it accepts the policy. Unknown keys,
   non-boolean values and `request: false, response: false` are refused.

`GET http://127.0.0.1:50052/healthz` answers `200 {"status":"ok"}` once the guard holds the gateway's keys, and
`503` before.

## Configuration

Flags override `BROKER_GUARD_*` environment variables, which override the config file (`-c`; by default
`/etc/straiker/guard.yaml`, or `%ProgramData%\Straiker\straiker-broker\guard.yaml` on Windows, when present).

| flag | environment | file | default |
|---|---|---|---|
| `--env` | `BROKER_GUARD_ENV` | `env` | `prod` (`stage` and `dev` are for Straiker's own testing) |
| `--api` | `BROKER_GUARD_API` | `api` | the environment's `https://api.<env>.straiker.ai` |
| `--api-key-file` | `BROKER_GUARD_API_KEY_FILE` | `api_key_file` | none: this, or the key in `BROKER_GUARD_API_KEY` |
| `--gateway-id` | `BROKER_GUARD_GATEWAY_ID` | `gateway_id` | required |
| `--gateway-jwks` | `BROKER_GUARD_GATEWAY_JWKS` | `gateway_jwks` | required: a file or an `https://` URL |
| `--audience` | `BROKER_GUARD_AUDIENCE` | `audience` | `urn:openshell:extension:middleware:straiker-guard` |
| `--listen` | `BROKER_GUARD_LISTEN` | `listen` | `:50051` |
| `--health` | `BROKER_GUARD_HEALTH` | `health` | `127.0.0.1:50052` (`off` for none) |
| `--tls-cert`, `--tls-key` | `BROKER_GUARD_TLS_CERT`, `_TLS_KEY` | `tls_cert`, `tls_key` | `<dir>/server.pem`, `<dir>/server-key.pem` |
| `--ca-file` | `BROKER_GUARD_CA_FILE` | `ca_file` | none: an extra CA for outbound HTTPS (a proxy's, the gateway's) |
| `--dir` | `BROKER_GUARD_DIR` | `dir` | `<the broker's state directory>/guard` |
| `--audit-log` | `BROKER_GUARD_AUDIT_LOG` | `audit_log` | `<dir>/guard.jsonl` |
| `--on-straiker-error` | `BROKER_GUARD_ON_STRAIKER_ERROR` | `on_straiker_error` | `allow` (or `deny`) |
| `--on-block` | `BROKER_GUARD_ON_BLOCK` | `on_block` | `deny` (or `replace`: mask or stub, so the agent keeps running) |
| `--straiker-timeout` | `BROKER_GUARD_STRAIKER_TIMEOUT` | `straiker_timeout` | `6s`: keep it below the registration's `timeout` (7s) |

- **Integration key:** the key is never a flag, and never belongs in the config file.
- **Outbound traffic:** calls to Straiker, and to the gateway's JWKS, go through `HTTPS_PROXY` when it is set.
- **Docker:** pass `--dir /var/lib/straiker-broker/guard` so the CA and the certificate live in the volume.

## What Straiker receives

`POST https://api.<env>.straiker.ai/api/v3/detect`, with these headers:

| header | value |
|---|---|
| `Authorization` | `Bearer <integration key>` |
| `X-S6r-Ingress` | `gw-openshell` |
| `X-S6r-Agent-Id` | the OpenShell sandbox id, which is the agent's identity in Straiker's registry. `X-S6r-Agent` carries it instead if it is not an id Defend accepts. |
| `X-S6r-Session` | the conversation: the client's own id when it sends one (`x-claude-code-session-id`, `x-s6r-session`); otherwise the request's `prompt_cache_key`; otherwise `conv-<hash>`, a fingerprint of how the conversation opens (its system prompt and first user message, as text), which every later call in it repeats. Two conversations that open with the same message share a fingerprint. |

The body depends on the phase:

- **Request:** the provider request body, verbatim. When a credential block is masked, Straiker is asked once more,
  about the redacted body.
- **Repeated history:** a model request repeats the whole conversation, but with `X-S6r-Session` Defend scores only
  the messages it hasn't seen in that session, so a check stays fast as the conversation grows.
- **Answer:** `{"straiker_phase": "response-sync", "sse": "<the answer so far, verbatim>", "model": "<model>",
  "request": <the provider request>}`. `response-sync` tells Defend the answer is still held, so it scores its tool
  calls as not yet run.

The guard reads Defend's neutral reply (`action`, `controls`, `blocked_by`, `block_message`) and the Kong-shaped reply
Defend renders for gateway keys (`hookSpecificOutput.permissionDecision`, `stopReason`, `straiker.{action, …,
killswitch}`). A reply that says neither allow nor block counts as an error, never as an allow.

## What OpenShell receives

| case | decision | reason code | findings |
|---|---|---|---|
| Defend blocks | `DENY` / `block_delivery` | `straiker_blocked` (`straiker_killswitch` if killswitched) | `straiker.block` labelled with the block message, plus one per blocking control |
| Defend detects | `ALLOW` / `pass_through` | none | one `straiker.detect` per control |
| No verdict, `allow` | `ALLOW` / `pass_through` | none | `straiker.unavailable` |
| No verdict, `deny` | `DENY` / `block_delivery` | `straiker_unavailable` | `straiker.unavailable` |
| No verdict, a credential found by the guard | `DENY` | `straiker_local_block` | `straiker.unavailable`, `straiker.local_block` labelled with the credential type |
| `--on-block replace`, masked or stub | `ALLOW` with a replacement body | none | as for the block; metadata `straiker_replaced` is `masked` or `stub` |
| Too many answers at once, no room to hold a request, an answer it can't read or keep, `deny` | `block_delivery`, or `DENY` for the request | `straiker_guard_busy` | none |

Metadata carries `straiker_action`, `straiker_turn_id` and `straiker_error`: names, never content. A request the guard
will inspect the answer to is sent with `Accept-Encoding: identity`, because OpenShell cannot expose a compressed
body.

## Log

One JSON object per line, in `--audit-log` and on stdout. Lines carry ids, names, hosts and paths, never prompt or
answer content, and never the key.

| event | when |
|---|---|
| `start` / `stop` | the guard starts or stops, with its settings |
| `decision` | one per Straiker check: `phase` (request or response), `sandbox_id`, `sandbox`, `workspace`, `request_id`, `host`, `path`, `api`, `model`, `action`, `decision`, `controls`, `blocked_by`, `turn_id`, `session` (an id or a hash), `latency_ms`; `error` with `on_straiker_error` when there was no verdict; `local_check` (the credential type, never the credential) when the guard's own check found one; `replaced` (`masked` or `stub`) |
| `uninspected` | an answer the guard could not inspect: `uninspectable` (compressed, partial), `busy`, or `too_large` |
| `unauthenticated` | a call refused for its token, with why |
| `gateway_keys` | the gateway's keys could not be loaded or refreshed |

## Limits

- **Body size:** a request body, a whole answer, or one streamed piece of up to 4 MiB, OpenShell's maximum.
- **Answer bound:** an answer is kept for its checks up to 4 MiB. Past that, the guard stops inspecting it and logs
  `too_large`.
- **Concurrency and memory:** at most 64 answers are inspected at once. Requests wait for their answers' checks for
  up to 2 minutes, within 64 MiB in all.
- **Not checked yet:** MCP and tool hosts, WebSocket traffic, Bedrock's binary event stream, and answers OpenShell
  cannot expose (compressed, partial, `Cache-Control: no-transform`).
- **Blocking an answer does not undo its request:** the provider has already run it.
