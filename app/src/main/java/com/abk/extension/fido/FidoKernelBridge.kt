package com.abk.extension.fido

import android.util.Log

private const val SYSFS_BASE = "/sys/kernel/abk_fido_key"
private const val AUTH_PENDING_PATH = "$SYSFS_BASE/auth_pending"
private const val AUTH_REQUEST_ID_PATH = "$SYSFS_BASE/auth_request_id"
private const val AUTH_CONTEXT_PATH = "$SYSFS_BASE/auth_context"
private const val AUTH_DECISION_PATH = "$SYSFS_BASE/auth_decision"
private const val LAST_ERROR_PATH = "$SYSFS_BASE/last_error"
private const val LAST_TRACE_PATH = "$SYSFS_BASE/last_trace"
private const val STORE_GENERATION_PATH = "$SYSFS_BASE/store_generation"
private const val CREDENTIAL_COUNT_PATH = "$SYSFS_BASE/credential_count"
private const val RESTORE_METADATA_PATH = "$SYSFS_BASE/restore_metadata"
private const val RELOAD_STORE_PATH = "$SYSFS_BASE/reload_store"
private const val AUTH_GATE_ENABLED_PATH = "$SYSFS_BASE/auth_gate_enabled"
private const val BOUND_PATH = "$SYSFS_BASE/bound"
private const val HID_DEV_PATH = "$SYSFS_BASE/hid_dev"
private const val TAG = "AbkFidoCompanion"

internal data class PendingAuthRequest(
    val requestId: Int,
    val command: String,
    val rpId: String,
    val uv: Boolean,
    val rk: Boolean,
)

internal object FidoKernelBridge {
    fun readPendingAuthRequest(): PendingAuthRequest? {
        if (FidoDaemonBridge.isInstalled()) return FidoDaemonBridge.pending()
        val pending = RootShell.readTextFile(AUTH_PENDING_PATH)
        if (!pending.success) {
            Log.w(TAG, "read auth_pending failed exit=${pending.exitCode} out=${pending.stdout}")
            return null
        }
        if (pending.stdout.trim() != "1") return null

        val requestId = RootShell.readTextFile(AUTH_REQUEST_ID_PATH)
        if (!requestId.success) {
            Log.w(TAG, "read auth_request_id failed exit=${requestId.exitCode} out=${requestId.stdout}")
            return null
        }
        val requestIdValue = requestId.stdout.trim().toIntOrNull()
        if (requestIdValue == null) {
            Log.w(TAG, "parse auth_request_id failed out=${requestId.stdout}")
            return null
        }
        val context = RootShell.readTextFile(AUTH_CONTEXT_PATH)
        if (!context.success) {
            Log.w(TAG, "read auth_context failed exit=${context.exitCode} out=${context.stdout}")
            return null
        }

        val raw = context.stdout.trim()
        val values = raw
            .split(' ')
            .mapNotNull { token ->
                val idx = token.indexOf('=')
                if (idx <= 0) null else token.substring(0, idx) to token.substring(idx + 1)
            }
            .toMap()

        return PendingAuthRequest(
            requestId = requestIdValue,
            command = values["cmd"].orEmpty(),
            rpId = values["rp"].orEmpty(),
            uv = values["uv"] == "1",
            rk = values["rk"] == "1",
        )
    }

    fun allow(requestId: Int): RootShell.CommandResult =
        if (FidoDaemonBridge.isInstalled()) FidoDaemonBridge.decide(requestId, true)
        else RootShell.writeTextFile(AUTH_DECISION_PATH, "allow $requestId\n")

    fun deny(requestId: Int): RootShell.CommandResult =
        if (FidoDaemonBridge.isInstalled()) FidoDaemonBridge.decide(requestId, false)
        else RootShell.writeTextFile(AUTH_DECISION_PATH, "deny $requestId\n")

    fun readLastError(): String =
        if (FidoDaemonBridge.isInstalled()) FidoDaemonBridge.status()?.let {
            it.optString("last_error").ifBlank { it.optString("usb_error") }
        }.orEmpty() else RootShell.readTextFile(LAST_ERROR_PATH).stdout.trim()

    fun readLastTrace(): String =
        if (FidoDaemonBridge.isInstalled()) FidoDaemonBridge.status()?.optString("last_trace").orEmpty()
        else RootShell.readTextFile(LAST_TRACE_PATH).stdout.trim()

    fun readCredentialCount(): Int? =
        if (FidoDaemonBridge.isInstalled()) FidoDaemonBridge.status()?.optInt("credential_count")
        else RootShell.readTextFile(CREDENTIAL_COUNT_PATH).stdout.trim().toIntOrNull()

    fun readStoreGeneration(): Int? =
        if (FidoDaemonBridge.isInstalled()) FidoDaemonBridge.status()?.optLong("store_generation")?.toInt()
        else RootShell.readTextFile(STORE_GENERATION_PATH).stdout.trim().toIntOrNull()

    fun restoreMetadata(): RootShell.CommandResult =
        if (FidoDaemonBridge.isInstalled()) RootShell.CommandResult(1, "Use the daemon store transaction")
        else RootShell.writeTextFile(RESTORE_METADATA_PATH, "1\n")

    fun reloadStore(): RootShell.CommandResult =
        if (FidoDaemonBridge.isInstalled()) RootShell.CommandResult(1, "The daemon owns the live store")
        else RootShell.writeTextFile(RELOAD_STORE_PATH, "1\n")

    /**
     * Whether the driver holds every CTAP operation until this app decides.
     * It is the only policy knob the driver exposes: `enabled` is read-only, so
     * the app's own master switch is enforced by keeping the gate on and denying
     * while the switch is off.
     */
    fun readAuthGateEnabled(): Boolean? =
        if (FidoDaemonBridge.isInstalled()) FidoDaemonBridge.status()?.optBoolean("auth_gate_enabled")
        else when (RootShell.readTextFile(AUTH_GATE_ENABLED_PATH).stdout.trim()) {
            "1" -> true
            "0" -> false
            else -> null
        }

    fun writeAuthGateEnabled(enabled: Boolean): RootShell.CommandResult =
        if (FidoDaemonBridge.isInstalled()) RootShell.CommandResult(if (enabled) 0 else 1,
            if (enabled) "" else "Local approval is mandatory")
        else RootShell.writeTextFile(AUTH_GATE_ENABLED_PATH, if (enabled) "1\n" else "0\n")

    /** True once the gadget is bound to a UDC, i.e. the key can talk over USB. */
    fun readBound(): Boolean? =
        if (FidoDaemonBridge.isInstalled()) FidoDaemonBridge.status()?.optBoolean("bound")
        else when (RootShell.readTextFile(BOUND_PATH).stdout.trim()) {
            "1" -> true
            "0" -> false
            else -> null
        }

    fun readHidDevice(): String =
        if (FidoDaemonBridge.isInstalled()) FidoDaemonBridge.status()?.optString("hid_dev").orEmpty()
        else RootShell.readTextFile(HID_DEV_PATH).stdout.trim()

    fun isPresent(): Boolean =
        if (FidoDaemonBridge.isInstalled()) FidoDaemonBridge.status() != null
        else RootShell.run("[ -d $SYSFS_BASE ]").success

    fun waitForCredentialCountAtLeast(target: Int, attempts: Int = 20, delayMs: Long = 200): Int? {
        repeat(attempts) {
            val count = readCredentialCount()
            if (count != null && count >= target) {
                return count
            }
            Thread.sleep(delayMs)
        }
        return readCredentialCount()
    }
}
