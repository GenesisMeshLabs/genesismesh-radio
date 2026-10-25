# Fresh-device provisioning

`gm-radio provision` prepares a private bundle for devices that have never used
these radio identities and keys. It validates the complete template before
creating files, generates distinct 32-byte device keys and a separate 32-byte
local control token, and preserves existing edge-agent and TTS credential
references. It does not read credential values from the environment.

This workflow does not enroll an edge agent, create TTS credentials, join a
LoRaWAN network, flash hardware, rotate a deployed key, or recover lost state.
Use the existing deployment's enrollment and device-management procedures for
those operations. The device profiles are inputs for a trusted provisioning
workflow, not executable firmware.

## Create a bundle

Use Linux with a filesystem that enforces POSIX ownership and permissions. The
parent directory must already exist, and the output directory must be absent.
The command refuses symlink ancestors, an existing output path, and a template
whose configured bridge-state path already exists.

```sh
gm-radio provision --config examples/meshtastic.toml --output /home/user/new-radio
```

The same command accepts the serial LoRa and TTS templates. Review device IDs,
routes, resource IDs, payload budgets and transport settings in the template
first. The copied configuration uses `bridge.db` inside the new bundle.

Native Windows creation fails with `unsupported_private_permissions`; the
implementation does not configure Windows ACLs. On Windows, use WSL and a Linux
filesystem path such as `/home/user/new-radio`, not `/mnt/c` or another mounted
Windows drive. On Linux, the tool reads the opened parent directory's mount ID
from `/proc/self/fdinfo` and matches it against `/proc/self/mountinfo` before
creating the bundle. Known Windows/shared filesystem types (`drvfs`, `9p`,
`ntfs`, `ntfs3`, `fuseblk`, `cifs`, `smb3`) are refused even if they report private
POSIX metadata. Missing or ambiguous mount identity also prevents creation.
A filesystem that cannot enforce the requested private modes is refused. Do not
copy the secret bundle into a shared or cloud-synchronized folder.

## Bundle contents

| File | Contents | Secret |
| --- | --- | --- |
| `bridge.toml` | Validated device/resource bindings and copied edge/transport settings | No |
| `bridge.env` | Newly generated device keys and `GM_RADIO_CONTROL_TOKEN` | Yes |
| `devices/<device_id>.json` | One device's audience, ID, key, limits, protocol version, route and transport/resource metadata | Yes |
| `manifest.json` | File inventory, device IDs, binding fingerprint, credential-reference names and setup instructions | No |

Directories are created with mode `0700`; every file uses `0600`. The creator
verifies ownership and permissions, writes with exclusive file creation, and
syncs files and directories before returning. An ordinary failure removes only
the files and directories created by that attempt. An unexpected replacement or
unrecognized file leaves the remaining directory intact and reports
`provisioning_failed_cleanup_incomplete` for inspection; it is never overwritten
on a later attempt.

The JSON result printed by the CLI contains the manifest and output path, with
no key or bearer-token values. The binding fingerprint uses the same binding
function as the bridge journal. It is not an enrollment certificate or a signed
device identity. TTS profiles include identifiers such as DevEUI and FPort, but
no LoRaWAN network or application session keys.

## Prepare the service and devices

Load only the trusted, generated environment file, without printing its values:

```sh
set -a
. /home/user/new-radio/bridge.env
set +a
gm-radio init-state --config /home/user/new-radio/bridge.toml
gm-radio serve --config /home/user/new-radio/bridge.toml
```

Supply any existing edge-agent bearer token or TTS API credential separately,
under the environment names in `bridge.toml`. The manifest lists those references;
the edge token is optional when using the edge agent's Unix-socket authentication.
No existing external credential is generated or replaced. A device-key reference
that collides with an external credential or the control-token reference is
rejected.

State initialization is explicit: provisioning does not create a journal. Send
each device only its own secret profile through a trusted local workflow and
implement persistent counters, trusted time and the documented protocol rules
in its firmware. The bridge must retain its initialized journal across restarts.
Never reuse these fresh profiles as a reset or recovery procedure for a device
that has already sent or received traffic.

The reference codec and software tests do not demonstrate physical programming,
RF range, power consumption, regional airtime compliance or secure key storage
on a particular board. Those checks belong to the hardware pilot.
