# Continuous local radio service

`gm-radio serve` keeps one bridge owner running while local operators submit
commands, query outcomes and inspect telemetry counts through an authenticated
HTTP API. The owner thread alone holds the SQLite journal, adapters and GenesisMesh
client. The existing direct `run`, `command` and `status` commands remain available
when the service is stopped; they cannot acquire its live journal lock.

## Run and inspect

Provision the device keys and a separate random 32-byte control token encoded as
64 lowercase hexadecimal characters. Store the control token in
`GM_RADIO_CONTROL_TOKEN`; it is not an edge-agent credential or device radio key.
The [provisioning tool](provisioning.md) generates a fresh bundle. Enroll the edge
agent and initialize the bridge's journal explicitly before starting the service.

```sh
gm-radio check-config --config bridge.toml
gm-radio init-state --config bridge.toml
gm-radio serve --config bridge.toml
```

In another local terminal with the control token loaded:

```sh
gm-radio service-health
gm-radio service-status
gm-radio service-command --device-id 1 --interval 60 --ttl 60 --request-id 11111111-1111-4111-8111-111111111111
gm-radio service-result --request-id 11111111-1111-4111-8111-111111111111
```

Generate a fresh UUID for each *new* command. Save it before sending. The example
UUID is illustrative. Reuse the original UUID when inspecting or retrying the same
operation; a timeout or lost HTTP response must never produce a fresh command ID.
The service's command response is a journal record, not proof of execution. Only
`state=confirmed` proves the matching authenticated application outcome was received;
`report_status=accepted` separately describes the GenesisMesh evidence report.

## API contract

Default origin: `http://127.0.0.1:17901`. Every request, including health, needs
`Authorization: Bearer <control-token>`. Only literal IPv4 loopback bind addresses
are supported. Remote hosts, CORS and reverse-proxy deployment are outside this
interface's scope. Do not expose it through port forwarding.

| Method and path | Result |
| --- | --- |
| `GET /healthz` | Local owner liveness/readiness; does not prove radio delivery or authority availability |
| `GET /v1/status` | Bounded recent command history, event count and transport rejection counters |
| `GET /v1/commands/<canonical-UUID>` | Stored command record, or 404 if it is not in the journal |
| `POST /v1/commands` | Governed dispatch request with `command_id`, `device_id`, `interval_seconds`, `ttl` |

POST accepts an application/json object only, with no duplicate or unknown fields.
`ttl` defaults to 60 seconds. Bodies are limited to 4096 bytes; headers, connections
and mailbox work are bounded. Framing ambiguity, browser Origin headers and an
unexpected Host are rejected. Connections close after each response.

The mailbox is transient; there is no durable scheduled-command queue. A 202
response follows creation of a durable command record. A 504 response is uncertain:
the owner may still finish the request. Query/retry the same UUID. The bridge
continues to permit only one active command or pending outcome report at a time;
another command is rejected rather than queued for later physical execution.
The CLI's `--timeout` controls HTTPX's per-I/O inactivity timeout, not a total
operation deadline. A client timeout does not cancel work already sent to the owner.
Shutdown stops new requests and preserves the journal. On recovery, an interrupted
operation becomes uncertain and is not automatically dispatched again.

## Linux systemd deployment

The supplied [unit](../deploy/systemd/genesismesh-radio.service) is a template for a
dedicated `genesismesh-radio` user. It is not installed or enabled automatically.

1. Create a dedicated system user and group named `genesismesh-radio`, with no
   interactive login. Install the package and required transport extras into
   `/opt/genesismesh-radio/venv`. Pin the reviewed release or commit.
2. Put `bridge.toml` and `bridge.env` in `/etc/genesismesh-radio`. Keep the directory
   private to the administrator/service account and the environment file mode 0600.
   Set `bridge.state_path` to `/var/lib/genesismesh-radio/bridge.db`; keep that
   directory mode 0700 and owned by the service user.
3. Put the actual device secrets and separately issued edge/TTS credentials in the
   protected environment file. A generated bundle does not enroll an edge agent
   or issue a TTS credential. Never copy device secret profiles into a public repo.
4. Grant only the required serial-device and edge Unix-socket permissions. Prefer
   a stable `/dev/serial/by-id/...` path. Configure the enrolled edge agent to admit
   the service account's local access. The unit intentionally does not hide serial
   devices; adapt device permissions for the selected hardware.
5. Run `check-config` and `init-state` as the service identity with the same protected
   environment. Do not recreate an existing journal or reuse counters after a restore.
6. Install the unit as `/etc/systemd/system/genesismesh-radio.service`, owned by
   root with mode 0644. Run `systemctl daemon-reload`, then
   `systemctl enable --now genesismesh-radio`. Check `journalctl -u genesismesh-radio`
   and authenticated `service-health` locally. A running process alone does not prove
   radio or authority connectivity.

SIGTERM requests graceful shutdown. The unit waits up to 30 seconds; a forced kill
retains the conservative uncertain-operation recovery behavior. OS privilege,
device drivers, provisioning and radio reliability still need a field pilot.
