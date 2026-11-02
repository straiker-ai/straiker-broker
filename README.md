# straiker-broker

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/straiker-ai/straiker-broker/badge)](https://scorecard.dev/viewer/?uri=github.com/straiker-ai/straiker-broker)

The Straiker Broker agent. Run it on a machine inside your network that can reach your AI apps, and Straiker's
products (Ascend, Defend, Discover) reach those apps through one outbound HTTPS connection: no inbound ports, no
VPN, no DNS or cloud changes.

```
Straiker products ──► Straiker relay ◄──── outbound HTTPS (WebSocket) ──── straiker-broker ──► your app
                                                                              (your network)
        └──────────────────── TLS end to end, Straiker to your (HTTPS) app ─────────────────┘
```

> **Status: in development.** Only the `dev` environment is built in, so nothing here is for production use yet.
> The service this agent connects to lives in `straiker-ai/platform` (`services/broker`).

- **Outbound only.** The broker dials out to Straiker's relay on 443, through your proxy if you have one.
  Nothing connects in.
- **Reaches only what you list.** Each `--allow host[:port]` is one fixed forward; the broker dials nothing
  else, whatever it is asked.
- **Sees only ciphertext, for HTTPS apps.** TLS runs end to end from Straiker to your app; the broker splices
  bytes. A plain-HTTP app's traffic is carried as it is, inside the encrypted connection.
- **Your key, on your machine.** The broker generates its key on first start and never sends the private half
  anywhere. You authorize it by registering the public half with Straiker.
- **Every connection logged locally** - when, where, how many bytes - in a JSON-lines audit log.

## Install

| | |
|---|---|
| macOS | `brew install straiker-ai/tap/straiker-broker` |
| Windows | the `.zip` from [Releases](../../releases), then [`service install`](#running-it-as-a-service) |
| Linux | the `.deb` / `.rpm` from [Releases](../../releases) (installs a systemd service), or the archive |
| Docker | `docker run ghcr.io/straiker-ai/straiker-broker` |
| Anything else | the archive for your platform from [Releases](../../releases): one static binary |

macOS binaries are signed with Straiker's Developer ID and notarized by Apple. Windows binaries aren't
Authenticode-signed yet. winget and Scoop packages aren't published yet.

### Verify a download

Every release artifact has a signed build provenance attestation:

```sh
gh attestation verify straiker-broker_<version>_<os>_<arch>.tar.gz --repo straiker-ai/straiker-broker
sha256sum -c checksums.txt --ignore-missing
```

Each release publishes why a scanner's finding that does not apply is not exploitable, in
`straiker-broker.openvex.json` (OpenVEX): `trivy rootfs --vex straiker-broker.openvex.json <binary>`. Each archive
has an SPDX SBOM beside it, and the container image carries an SBOM and build provenance.

Builds are reproducible: rebuild a release binary from its tag with the Go toolchain `go.mod` names and compare
checksums (Linux byte for byte; Windows and macOS carry a code signature, so compare after removing it).

```sh
git checkout v<version>
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X main.version=<version> -X main.commit=$(git rev-parse --short HEAD)" ./cmd/straiker-broker
```

## Set up

**Before you start**, have your **Straiker org id**, the **host** of each app to reach (and its port if not 443),
and a **machine** inside your network that can reach them and stays on. A server or VM is best: a laptop that
sleeps, or a virtual desktop that resets at logoff, drops the connection.

1. **Check the connection** (network team). Saves nothing:

   ```sh
   straiker-broker check connection --org 1234
   ```

   Tests this machine's path to Straiker one hop at a time: DNS, TCP, your proxy, TLS, HTTPS, WebSocket and the
   relay's identity. **Done when:** `RESULT PASS: this machine reaches Straiker`. If a step fails, the `->` line
   under it says what to ask for. See [Troubleshooting](#troubleshooting).

2. **Check the apps** (app owner). It never contacts Straiker:

   ```sh
   straiker-broker check app --allow chat.corp.internal
   ```

   **Done when:** `RESULT PASS`. Note each app's URL, e.g. `https://chat.corp.internal.brk.straiker.ai`. A `WARN`
   that an app speaks plain HTTP means its URL starts with `http://`.

3. **Run the broker** (machine owner), as a service, with the same org and allowlist: see
   [Running it as a service](#running-it-as-a-service). On first start it creates its key in its state directory
   and logs it (`{"event":"identity", ... "agent_key":"AAAAC3Nz..."}`). Until step 4 it logs `waiting` once a
   minute: expected. The key survives restarts and upgrades; it changes only if the state directory is lost.

4. **Register the key** with Straiker: in the Straiker console under **Connect > Straiker Broker**, paste the
   `agent_key` for your org. Within seconds the broker logs `connected`, then one `connection` line per request.
   More apps: add each host to `--allow` and restart. For availability, run a second broker and register both keys.

## Configuration

Flags override `BROKER_*` environment variables, which override the config file (`-c broker.yaml`; by default
`/etc/straiker/broker.yaml`, or `%ProgramData%\Straiker\straiker-broker\broker.yaml` on Windows, when present).
See [config.example.yaml](config.example.yaml).

| flag | environment | file | default |
|---|---|---|---|
| `--org` | `BROKER_TENANT` | `tenant` | required |
| `--allow host[:port]` (repeat; port 443 if omitted) | `BROKER_ALLOW` (comma-separated) | `allow` | required |
| `--env` | `BROKER_ENV` | `env` | `dev` (until production is built in) |
| `--relay` | `BROKER_RELAY` | `relay` | the environment's relay |
| `--host-key` | `BROKER_HOST_KEY` | `host_key` | the environment's pinned key |
| `--state-dir` | `BROKER_STATE_DIR` | `state_dir` | per user (below) |
| `--ca-file` | `BROKER_CA_FILE` | `ca_file` | none |
| `--audit-log` | `BROKER_AUDIT_LOG` | `audit_log` | `<state-dir>/connections.jsonl` |
| `--fanout` | `BROKER_FANOUT` | `fanout` | `1` |

The state directory holds the broker's private key; keep it, or the broker gets a new identity. By default:
`%LOCALAPPDATA%\Straiker\straiker-broker` on Windows, `~/Library/Application Support/Straiker/straiker-broker` on
macOS, `/var/lib/straiker-broker` for root on Linux, `~/.local/state/straiker-broker` otherwise.

### What goes in `--allow`

Each entry is one app, as this machine reaches it: `host` (port 443) or `host:port`; a hostname or IPv4 address,
not an IPv6 address, wildcard or range. One entry per host. The broker resolves the host with this machine's own
DNS when it connects and dials it directly, never through the proxy; `check app` dials the same way.

The port stays with the broker: Straiker's URL for an app names only the host
(`https://<host>.brk.straiker.ai`), and the broker dials the `host:port` of the matching entry. Straiker sends
`<host>` as the `Host` header (no port) and, over TLS, as the server name, so allow the name the app answers to.
If this machine cannot resolve it, add it to the hosts file (in Docker, `--add-host`). A second port on one host
needs a second name for the same machine.

### Corporate proxies and TLS inspection

The broker reaches the relay through `HTTPS_PROXY` (`http://`, `https://` or `socks5://`; credentials as
`http://user:password@proxy:port`), honours `NO_PROXY`, and trusts the operating system's certificate store. If the
proxy's CA is not in it, pass `--ca-file`. The relay's SSH host key is pinned inside the connection, so a proxy
cannot impersonate it. Not supported: operating-system proxy settings, PAC files, and NTLM or Kerberos proxy
authentication (`check connection` names what it finds). Targets are always dialled directly.

For more throughput than one link carries (tens of concurrent connections), raise `--fanout` (up to 16) or run
more brokers, each with its own state directory.

## Running it as a service

- **Linux (deb/rpm):** put your org id and allowlist in `/etc/straiker/broker.yaml`, then
  `sudo systemctl enable --now straiker-broker`. It runs as a sandboxed dynamic user with its key in
  `/var/lib/straiker-broker`. Key: `journalctl -u straiker-broker | grep identity`.
- **Docker:** `docker run -d --name straiker-broker --restart unless-stopped -v straiker-broker:/var/lib/straiker-broker
  ghcr.io/straiker-ai/straiker-broker --org 1234 --allow chat.corp.internal`. The volume holds the key. The image is
  distroless and runs as uid 65532; a container uses neither the host's proxy settings nor its certificate store.
- **Windows:** from a terminal opened with **Run as administrator**:
  `straiker-broker service install --org 1234 --allow chat.corp.internal`. It copies itself to
  `%ProgramFiles%\Straiker\straiker-broker` and installs the `StraikerBroker` service, which starts with Windows and
  restarts if it stops, as its own account (`NT SERVICE\StraikerBroker`). It takes the proxy settings of the
  terminal, but refuses a proxy URL with a password.
- **macOS:** `straiker-broker service install --org 1234 --allow chat.corp.internal`, without sudo: a LaunchAgent
  that runs as you, with your key. Keep the machine awake while Straiker uses it.
- **Linux, without the package:** the same command installs a systemd user service; add
  `loginctl enable-linger $USER` so it starts at boot.

`service install` takes the same flags as `run`, checks them first, and prints the key and each app's URL.
`straiker-broker service status` and `service uninstall` (which keeps the key); `straiker-broker key` prints the key.

## Troubleshooting

Run the full check with the broker's own key, on the machine it runs on:
`straiker-broker check --org 1234 --allow chat.corp.internal` (with Docker, `docker run --rm --volumes-from
straiker-broker ghcr.io/straiker-ai/straiker-broker check ...`). Healthy is `RESULT PASS` for both halves, with
the `login` step saying the key is registered; otherwise the first `FAIL` is the answer and its `->` line is the fix.

| step | fails when | usually |
|---|---|---|
| `dns` | the relay's host does not resolve, or resolves to `0.0.0.0` | a DNS filter blocks it |
| `tcp` | nothing answers on 443 | a firewall drops it, or this network needs a proxy |
| `tcp` | some of the relay's addresses answer, some do not | a firewall rule by hostname that resolved a stale set |
| `proxy` | the proxy answers `403`, `407` or `5xx` | its policy, credentials, or its own access to the relay |
| `tls` | the connection is cut after the TLS hello | filtering by name (SNI / URL category) |
| `tls` | the certificate is from an unknown CA | TLS inspection: pass that CA with `--ca-file` |
| `https` | something other than the relay answers | a block page or web filter |
| `websocket` | HTTPS works, the upgrade does not | application control, or a proxy that strips `Upgrade` |
| `link` | the WebSocket opens, then is cut | inspection of WebSocket traffic |
| `login` | `WAIT` | the key is not registered yet, `--org` is wrong, or the key changed (new state dir) |

The running broker logs the same diagnosis once per outage, as a `diagnosis` event. `ping` does not help: the
relay does not answer it.

## The audit log

One JSON object per line, also printed to stdout:

| event | when |
|---|---|
| `identity` | start: org, agent id, the key to register |
| `waiting` | the relay refused the key (not registered yet); at most once a minute |
| `connected` / `forward` | a link is up, and each target's socket on it |
| `connection` | one per connection: target, bytes each way, duration |
| `disconnected` | a link dropped, after `up_s` seconds up; it reconnects with backoff |
| `diagnosis` | once per outage, when the relay cannot be reached: where the path stops, and the fix |

## Development

```sh
go test -race ./...
go test ./pkg/config -run '^$' -fuzz FuzzParseForwards      # CI fuzzes it for 30s
goreleaser release --snapshot --clean --skip=publish         # every archive, package and manifest
```

The code under `pkg/` is product-neutral so other Straiker agents can build on it: `pkg/config` (a `Profile` names
the product: environments, env prefix, paths), `pkg/identity`, `pkg/agent` (the link, the check) and `pkg/service`
(Windows service, LaunchAgent, systemd unit, from a `Def`). `cmd/straiker-broker` is this product's profile.
`testdata/contract.json` pins the names the broker and the relay must derive identically; the relay's tests
(`straiker-ai/platform`, `services/broker/relay`) check the same file.

Maintainers: how releases are cut, approved and signed is in [docs/releasing.md](docs/releasing.md).

## License

[Apache 2.0](LICENSE)
