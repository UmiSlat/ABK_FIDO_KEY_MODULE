# ABK FIDO Userspace module

This KernelSU module uses the kernel's existing standard HID gadget support.
It does not install a kernel, a `.ko`, or a custom USB configfs hook.

Before migration, boot a kernel without the old builtin ABK FIDO driver. The
installer and service refuse `/sys/kernel/abk_fido_key` to prevent two competing
authenticators. The kernel must already support `USB_CONFIGFS_F_HID`.

Use Companion **0.4.0 / versionCode 3 or newer** for local approval. Both the
release and debug package are checked. An installed older app prevents startup
because it writes the metadata store directly. Update or uninstall it first.
Without a compatible Companion, no request can be approved automatically.

The service waits for boot completion in the background and starts once. It
does not restart indefinitely after a crash. Logs are at
`/data/adb/abk-fido/service.log`; the daemon owns the private store at
`/data/adb/abk-fido/store.bin`. If this store does not exist, a valid old
`/metadata/abk_fido_store.bin` is strictly validated and imported once. The old
file is retained. A corrupt legacy file is reported rather than silently
replaced. Devices without `/metadata` work normally. Keys and state survive
uninstallation.

The KernelSU action toggles the daemon. Stop uses SIGTERM after checking the
PID, process start time and command identity; it never force-kills a process.
Graceful shutdown removes only the FIDO HID link and restores the native USB
configuration. Enabling/disabling HID briefly reconnects USB, including ADB.

The module preserves VID/PID and native function links. It waits for a stable
HAL configuration and reapplies HID after a mode change. Ambiguous multiple
gadgets/configurations are left alone. A failed HID bind rolls back the added
link and restores the original USB binding; it is not retried in a disconnect
loop while that native configuration remains unchanged.

The existing KernelSU root domain supplies access. `sepolicy.rule` deliberately
contains no guessed ROM-specific labels or permissive rules. If an AVC occurs,
review it and add only the rule for the actual denied operation on that ROM.
