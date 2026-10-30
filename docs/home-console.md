# Home operator console

The optional console adds browser access over a fixed `ControlClient` connection.
The existing bridge API remains on literal loopback, holds its journal lock and
continues to call the real edge agent for dispatch authorization. No browser
receives the bridge token, device key or authority credentials.

Console accounts are **local admission identities**. An observer can inspect
status and command results; an operator can also request the existing bounded
sampling command. Both use the enrolled bridge identity downstream. They are not
GenesisMesh node enrollment, per-person core delegation, multi-party approval or
a visiting-device certificate implementation. Those belong to core/Connect work.

## Private setup on WSL or Linux

Install `python -m pip install -e '.[console]'`. Keep state in a directory on the
Linux filesystem, outside `/mnt/c` and other shared mounts. The directory must be
owned by the current user with mode 0700; SQLite state and TLS keys require 0600.
The console refuses symlink ancestors, public files and unsupported permissions.
Native Windows credential storage is not implemented by this console.

```sh
mkdir -m 700 "$HOME/gm-home-console"
gm-radio-console init --state "$HOME/gm-home-console/operators.db" --username owner --role operator
gm-radio-console set-user --state "$HOME/gm-home-console/operators.db" --username observer --role observer
```

Password prompts accept 16 to 128 characters; do not put passwords in shell
arguments, configuration tracked by Git or screenshots. There are no default
accounts or browser signup. `set-user` resets that account and invalidates its
sessions; `revoke --state ... --username owner` disables an account. The app reads
the current account on each request, including changes made by another CLI process.

Passwords use fixed salted scrypt (N=32768, r=8, p=3, 64 MiB OpenSSL memory cap).
Opaque sessions stay server-side, expire after 30 minutes and disappear on restart.
Cookies are host-only, HttpOnly and SameSite Strict; HTTPS uses a Secure `__Host-`
cookie. Login attempts, hash concurrency, sessions, request sizes and HTTP work
are bounded. Unsafe requests require the exact configured Origin, JSON, a custom
request header and, after login, a session-bound CSRF value. Proxy headers and CORS
are not trusted. Static assets are local and sensor labels use text rendering.

## Loopback software preview

```sh
gm-radio-console demo --state "$HOME/gm-home-console/operators.db" \
  --origin http://127.0.0.1:17902 --development-loopback
```

This opens no radio hardware and uses an explicitly **simulated authority and
radio**, a real loopback bridge and generated disposable device secrets. It is a
local preview, not Android LAN access. Each demo gets a fresh disposable bridge;
old submission IDs in console state are retained and never silently resubmitted.

For a real disposable authority/edge with injected RF, start the
[home lab](home-pilot-lab.md) with `--hold-seconds 300` and use its private
`session.json` path:

```sh
gm-radio-console serve --state "$HOME/gm-home-console/operators.db" \
  --bridge-session /private/lab/session.json \
  --origin http://127.0.0.1:17902 --development-loopback
```

The session file's schema, permissions, absolute expiry and literal-loopback
control URL are checked. Its lab endpoint closes at expiry. It supplies no phone
account or production enrollment. Recreate disposable environments deliberately;
do not turn temporary peers or their state into real-device identities.

## Android access over the home LAN

Use a fixed private IPv4 address for the console and a certificate whose subject
alternative name matches that address. Establish trust through an appropriate
local CA workflow on each client before using it; do not bypass browser warnings.
Provide the certificate and private key directly to the console:

```sh
gm-radio-console serve --state "$HOME/gm-home-console/operators.db" \
  --origin https://192.168.1.50:17902 \
  --ssl-certfile /private/tls/home.crt --ssl-keyfile /private/tls/home.key
```

Set `GM_RADIO_CONTROL_TOKEN` in the console's private service environment; its
default backend is `http://127.0.0.1:17901`. The example LAN address must be
replaced with the actual address. TLS must be available before a LAN bind. No
firewall rule, Windows forwarding rule, router change or remote access is created
automatically. WSL networking must be deliberately configured and verified for
the chosen Windows mode. Until actual Android connectivity, lock/reopen and
certificate trust pass, phone acceptance remains pending.

For WSL NAT, the browser origin is the Windows PC's home LAN address while the
listener binds the WSL guest's private IPv4 address. Add an explicit bind:

```sh
gm-radio-console serve --state "$HOME/gm-home-console/operators.db" \
  --origin https://192.168.1.50:17902 --listen-host 172.20.1.5 \
  --ssl-certfile /private/tls/home.crt --ssl-keyfile /private/tls/home.key
```

Replace both sample addresses. The certificate must match the browser origin,
and exact Host/Origin checks still use that origin, not the guest bind. The
listener accepts only an explicit private/loopback IPv4 address; wildcard and
public binds are refused. This does not trust `X-Forwarded-*` headers. Windows
TCP forwarding and a narrow firewall rule are separate deployment steps; follow
[Microsoft's WSL networking guide](https://learn.microsoft.com/en-us/windows/wsl/networking)
and verify them with the actual phone when ready. The guest address can change
after restart, so startup/reboot acceptance must include the forwarding target.
TCP forwarding can make clients share an apparent source address and therefore
share the console's login-rate limit. No forwarding or firewall rule is applied
by this CLI.

Use one console worker and one loopback bridge owner. Restarting the console
invalidates browser sessions. Local operator administration is through the CLI;
the phone interface does not grant authority administration rights.

## Request lifecycle

The browser saves a canonical UUID and exact request before submission. Console
state durably associates it with its local operator and full parameters before
calling the bridge. Repeating the same request performs lookup only. Conflicting
parameters or another submitter using that UUID are refused. A crash before
bridge admission can therefore leave an unconfirmed intent that is not resent.
The original request ID must be retained for reconciliation; the app does not
automatically generate a replacement after a failure.

The screen separates request admission, bridge dispatch, device outcome and
evidence reporting. A transport ACK is not success. Authority and adapter
connectivity are explicitly not independently probed by the status screen.
Sensor timestamps retain their source metric IDs/units; after 30 seconds the
preview marks readings stale. This display threshold is not device expiry or
an authorization decision. No background notification guarantee is made.

Keep the operator database with its durable submission records. Deleting or
restoring old state is not a safe retry or device counter recovery workflow.
The local database is an operator correlation record, not signed GenesisMesh
evidence. Its 10000-submission cap refuses new work rather than discarding
ownership history; deliberate archival/rotation remains an operator workflow.
