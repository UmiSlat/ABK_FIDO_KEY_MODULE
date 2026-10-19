# Userspace authenticator

`cmd/abk-fidod` runs the CTAP engine without a custom kernel driver. The Android
package manages the standard configfs HID interface and approvals still come
from the Companion's biometric/screen-lock prompt. The daemon has no network
listener. The Companion retains its separately controlled encrypted LAN relay.

Production entry point:

```sh
abk-fidod serve --state-dir /data/adb/abk-fido --store /data/adb/abk-fido/store.bin
```

`--no-usb` runs only local CTAP transports, useful for an isolated Linux test
store. `--gadget-root` overrides configfs autodetection; it never creates a new
USB gadget or changes Android's selected USB mode. Neither option disables
mandatory local approval. `serve` requires root and refuses the legacy builtin
driver, even with `--no-usb`.

`control.sock` uses Unix `SO_PEERCRED`, a private directory and mode 0600. Each
connection contains one JSON request, ends its write half, and receives one JSON
response, bounded to 64 KiB. `ctl BASE64_JSON` handles this framing for root
clients; `--socket PATH` selects an isolated test service. The executable and
socket must never be copied to an app-writable directory.

| Operation | Fields | Result |
|---|---|---|
| `status` | none | backend, protocol, epoch, store count/generation, USB state/errors |
| `auth-pending` | none | pending request or null |
| `auth-decision` | `id`, `allow` | accepts only the pending unpredictable request ID |
| `store-get` | none | base64 `blob`, `generation`, `epoch` |
| `store-put` | `data`, `generation`, `epoch` | CRC/key validation, compare-and-swap and durable commit |
| `hid-write` | 32 hex `session`, base64 `data` | one 64-byte CTAP HID packet |
| `hid-read` | `session`, optional `timeout_ms` (1–40000) | base64 `packet` |
| `hid-close` | `session` | cancels requests and discards that transport queue |

When the destination is absent, `--legacy-store` (default
`/metadata/abk_fido_store.bin`) imports a strictly validated old store once.
The source is preserved; an existing destination is never overwritten, and a
malformed old file blocks startup rather than creating a new empty identity.
For isolated tests, select a nonexistent legacy path or pass an empty one.

Store modification must use `store-put` with the exact snapshot's revision.
The daemon is the only writer. A stale generation, old process epoch, malformed
credential or counter rollback fails without adopting the proposed store. A
storage I/O error blocks subsequent writes until restart, including uncertainty
after a failed directory sync. Do not directly edit the persistent file while
the service runs. Missing files create an empty store; malformed existing files
are never silently replaced.

Approval IDs are bound to one in-flight request and invalidated on cancellation
or timeout. Every new credential operation needs local approval; getNextAssertion
only continues its already approved request on the same transport/channel and
store generation. A new USB connection gets a new session and queue. Management
cannot replace the store underneath a pending ceremony without invalidating it.

The compatibility store contains software private keys. Root compromise can
read them, just as it can read the previous kernel's exported store. This is a
software authenticator, not a secure-element-backed hardware security key.

Use `go test -race ./...` and the independent host-library integration test
before packaging. The fake configfs tests cover ownership and rollback but
cannot prove a particular vendor USB HAL's real timing or host enumeration.
