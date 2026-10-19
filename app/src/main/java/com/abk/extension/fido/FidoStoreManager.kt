package com.abk.extension.fido

import android.util.Base64
import android.util.Log

private const val STORE_PATH = "/metadata/abk_fido_store.bin"
private const val TAG = "AbkFidoStore"

/** Outcome of an operation that has to survive into the kernel to count. */
internal sealed class StoreEditResult {
    object Success : StoreEditResult()
    class Failure(val message: String) : StoreEditResult()
}

/**
 * Everything the UI does to the key store: read it, edit it, and make the
 * driver adopt the result.
 *
 * The driver owns the live store, so an edit is a three-step move — rewrite
 * `/metadata/abk_fido_store.bin`, poke `restore_metadata`, then confirm the
 * store generation advanced. Without the last step a rejected blob (bad CRC,
 * for instance) would look like a success while the key kept its old contents.
 */
internal object FidoStoreManager {

    private data class ReadState(val blob: FidoStoreBlob, val snapshot: FidoDaemonBridge.Snapshot?)

    private fun readState(): ReadState? {
        if (FidoDaemonBridge.isInstalled()) {
            val snapshot = FidoDaemonBridge.snapshot() ?: return null
            return ReadState(snapshot.blob, snapshot)
        }
        return readLegacy()?.let { ReadState(it, null) }
    }

    /** Read the persisted store. Returns null when root or the file is missing. */
    fun read(): FidoStoreBlob? = readState()?.blob

    private fun readLegacy(): FidoStoreBlob? {
        val result = RootShell.readFileBase64(STORE_PATH)
        if (!result.success) {
            Log.w(TAG, "read $STORE_PATH failed exit=${result.exitCode} out=${result.stdout}")
            return null
        }
        val encoded = result.stdout.trim()
        if (encoded.isEmpty()) return FidoStoreBlob.empty()
        val bytes = runCatching { Base64.decode(encoded, Base64.DEFAULT) }.getOrNull() ?: return null
        if (bytes.isEmpty()) return FidoStoreBlob.empty()
        return FidoStoreBlob.parse(bytes)
    }

    fun delete(slot: Int): StoreEditResult {
        val state = readState() ?: return StoreEditResult.Failure("cannot read the FIDO store")
        val store = state.blob
        val record = store.credentialAt(slot)
            ?: return StoreEditResult.Failure("that key is no longer in the store")
        return commit(store.withoutSlot(slot), state.snapshot).also {
            if (it is StoreEditResult.Success) {
                Log.i(TAG, "deleted slot=$slot rp=${record.rpId}")
            }
        }
    }

    fun rename(slot: Int, userName: String, userDisplay: String): StoreEditResult {
        val state = readState() ?: return StoreEditResult.Failure("cannot read the FIDO store")
        val store = state.blob
        store.credentialAt(slot)
            ?: return StoreEditResult.Failure("that key is no longer in the store")
        return commit(store.withRenamedSlot(slot, userName, userDisplay), state.snapshot)
    }

    /**
     * Add credentials from an archive. Anything whose credential id is already
     * present is skipped rather than duplicated, because the driver matches
     * assertions by credential id and two identical ids would be ambiguous.
     */
    fun import(records: List<FidoCredentialRecord>): ImportOutcome {
        val state = readState() ?: return ImportOutcome(
            result = StoreEditResult.Failure("cannot read the FIDO store"),
            imported = 0,
            skipped = 0,
        )
        val store = state.blob
        val existing = store.credentials().map { it.credIdHex }.toMutableSet()
        var next = store
        var imported = 0
        var skipped = 0
        for (record in records) {
            if (!existing.add(record.credIdHex)) {
                skipped++
                continue
            }
            val updated = next.withCredential(record)
            if (updated == null) {
                return ImportOutcome(
                    result = StoreEditResult.Failure(
                        "the store is full at ${FidoStoreBlob.MAX_CREDS} keys; no keys were imported"
                    ),
                    imported = 0,
                    skipped = skipped,
                )
            }
            next = updated
            imported++
        }
        if (imported == 0) {
            return ImportOutcome(StoreEditResult.Success, imported = 0, skipped = skipped)
        }
        val result = commit(next, state.snapshot)
        return ImportOutcome(result, imported = if (result is StoreEditResult.Success) imported else 0, skipped = skipped)
    }

    class ImportOutcome(val result: StoreEditResult, val imported: Int, val skipped: Int)

    /**
     * Write the blob and wait for the driver to pick it up. `restore_metadata`
     * bumps `store_generation` on success, which is the only unambiguous signal
     * that the new contents are live.
     */
    private fun commit(store: FidoStoreBlob, snapshot: FidoDaemonBridge.Snapshot?): StoreEditResult {
        if (snapshot != null) {
            val result = FidoDaemonBridge.replace(store, snapshot)
            return if (result.success) StoreEditResult.Success
            else StoreEditResult.Failure("FIDO service rejected the edit: ${result.stdout.trim()}")
        }
        // Do not fall back to a raw file write if a module was installed after
        // the legacy snapshot was read. The caller must start a fresh edit.
        if (FidoDaemonBridge.isInstalled()) return StoreEditResult.Failure("FIDO backend changed; retry the edit")
        val bytes = store.toBytes()
        val generationBefore = FidoKernelBridge.readStoreGeneration()
            ?: return StoreEditResult.Failure("the abk_fido_key driver is not loaded")

        val write = RootShell.writeFileBase64(STORE_PATH, Base64.encodeToString(bytes, Base64.NO_WRAP))
        if (!write.success) {
            return StoreEditResult.Failure("writing $STORE_PATH failed: ${write.stdout.trim()}")
        }

        val trigger = FidoKernelBridge.restoreMetadata()
        if (!trigger.success) {
            return StoreEditResult.Failure("restore_metadata rejected the store: ${trigger.stdout.trim()}")
        }

        val expected = store.credentials().size
        repeat(RESTORE_ATTEMPTS) {
            val generation = FidoKernelBridge.readStoreGeneration()
            val count = FidoKernelBridge.readCredentialCount()
            if (generation != null && generation > generationBefore && count != null && count == expected) {
                return StoreEditResult.Success
            }
            Thread.sleep(RESTORE_DELAY_MS)
        }
        val error = FidoKernelBridge.readLastError().ifBlank { FidoKernelBridge.readLastTrace() }
        return StoreEditResult.Failure(
            "the driver did not adopt the edited store" + if (error.isBlank()) "" else ": $error"
        )
    }

    private const val RESTORE_ATTEMPTS = 20
    private const val RESTORE_DELAY_MS = 200L
}
