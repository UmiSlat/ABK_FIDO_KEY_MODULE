package com.abk.extension.fido

import android.util.Base64
import org.json.JSONObject

/** Root-only IPC for the standalone module. No app-writable control files. */
internal object FidoDaemonBridge {
    private const val BINARY = "/data/adb/modules/abk_fido_userspace/bin/abk-fidod"

    data class Snapshot(val blob: FidoStoreBlob, val generation: Long, val epoch: String)

    // The migrated store remains authoritative after disable/uninstall too.
    // Falling back to the old metadata backup could roll credentials/counters
    // backwards, so an unavailable daemon must remain an unavailable backend.
    fun isInstalled(): Boolean = RootShell.run(
        "[ -x '$BINARY' ] || [ -f '/data/adb/abk-fido/store.bin' ]"
    ).success

    fun call(op: String, fields: JSONObject = JSONObject(), timeoutSeconds: Long = 10): RootShell.CommandResult {
        fields.put("op", op)
        val encoded = Base64.encodeToString(fields.toString().toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
        return RootShell.run("'$BINARY' ctl '$encoded'", timeoutSeconds)
    }

    fun status(): JSONObject? = json(call("status"))

    fun pending(): PendingAuthRequest? {
        val value = json(call("auth-pending")) ?: return null
        return PendingAuthRequest(
            requestId = value.optInt("request_id", -1).takeIf { it > 0 } ?: return null,
            command = value.optString("command"),
            rpId = value.optString("rp_id"),
            uv = value.optBoolean("uv"),
            rk = value.optBoolean("rk"),
        )
    }

    fun decide(id: Int, allow: Boolean) = call(
        "auth-decision", JSONObject().put("id", id).put("allow", allow)
    )

    fun snapshot(): Snapshot? {
        val value = json(call("store-get")) ?: return null
        return runCatching {
            Snapshot(
                FidoStoreBlob.parse(Base64.decode(value.getString("blob"), Base64.NO_WRAP)) ?: return null,
                value.getLong("generation"), value.getString("epoch")
            )
        }.getOrNull()
    }

    fun replace(blob: FidoStoreBlob, snapshot: Snapshot): RootShell.CommandResult = call(
        "store-put", JSONObject()
            .put("data", Base64.encodeToString(blob.toBytes(), Base64.NO_WRAP))
            .put("generation", snapshot.generation).put("epoch", snapshot.epoch)
    )

    fun writePacket(session: String, packet: ByteArray) = call(
        "hid-write", JSONObject().put("session", session)
            .put("data", Base64.encodeToString(packet, Base64.NO_WRAP))
    )

    fun readPacket(session: String, timeoutSeconds: Long): ByteArray? {
        val timeout = timeoutSeconds.coerceIn(1, 40)
        val value = json(call("hid-read", JSONObject().put("session", session)
            .put("timeout_ms", timeout * 1000), timeout + 3)) ?: return null
        return runCatching { Base64.decode(value.getString("packet"), Base64.NO_WRAP) }.getOrNull()
    }

    fun closeSession(session: String) = call("hid-close", JSONObject().put("session", session))

    private fun json(result: RootShell.CommandResult): JSONObject? =
        if (result.success) runCatching { JSONObject(result.stdout.trim()) }.getOrNull() else null
}
