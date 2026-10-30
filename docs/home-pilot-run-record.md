# Home pilot run record template

Copy this template into a private lab folder. Never add credentials, contact or
shipping information, serial identifiers or private runtime files to Git.

- Run time (UTC):
- Operator's private run label:
- Radio repository commit / working tree clean:
- Core source commit / edge and verifier versions:
- Redacted JSON report and its SHA-256:
- Mode: `software rehearsal` / `physical hardware pilot`
- Authority: `disposable test` / separately approved pilot authority
- Transport: `injected Meshtastic SDK` / physical path explicitly described
- RF tested: **No** until observations support changing this field

| Scenario | Expected behavior | Observed result | Evidence reference |
| --- | --- | --- | --- |
| Authenticated control/status | Ready local owner; token required | Pending | |
| Telemetry | Correct device binding and authenticated source claim | Pending | |
| Online bounded command | Dispatch separated from confirmed outcome | Pending | |
| Duplicate request ID | Same operation, no redispatch | Pending | |
| Conflicting request ID | Refused | Pending | |
| Online policy denial | No radio dispatch | Pending | |
| Authority outage | Only a valid bounded offline grant permits dispatch | Pending | |
| Offline bound exceeded | Refused | Pending | |
| Restart/lost confirmation | Uncertain; never automatically reapplied | Pending | |
| Replay | Refused after recovery | Pending | |
| Evidence reconnect | Queued evidence synchronizes; verifier accepts | Pending | |
| Evidence tamper | Independent verifier rejects | Pending | |
| Physical radio baseline | Actual two-node RF delivery observed | Pending | |
| Physical power interruption | Durable counters; explicit uncertain recovery | Pending | |
| Clock loss/rollback | Device refuses unsafe operation | Pending | |
| LoRaWAN join/downlink | Actual gateway and provisioned device verified | Pending | |

For physical runs also record board/module revisions, bootloader/firmware
versions, ELF hash, region/data rate, antenna, supply, distance and exact fault
injection in the private notebook. Keep device EUIs and keys out of shared
reports. List skipped/unavailable checks separately; a software result must not
fill a physical-result row.

Unresolved observations:

-

Next acceptance step:

-
