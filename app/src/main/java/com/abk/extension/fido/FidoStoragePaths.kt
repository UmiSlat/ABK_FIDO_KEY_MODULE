package com.abk.extension.fido

import java.security.SecureRandom

internal object FidoStoragePaths {
    private const val LEGACY_PAIRING = "/metadata/abk_fido_pairing_code"
    val pairingCode: String
        get() = if (FidoDaemonBridge.isInstalled()) "/data/adb/abk-fido/pairing_code" else LEGACY_PAIRING

    fun readPairingCode(create: Boolean = false): String {
        val path = pairingCode
        val existing = RootShell.readTextFile(path).stdout.trim()
        if (existing.matches(Regex("[0-9]{6,12}"))) return existing
        if (!create) return ""
        val legacy = if (path != LEGACY_PAIRING) RootShell.readTextFile(LEGACY_PAIRING).stdout.trim() else ""
        val code = legacy.takeIf { it.matches(Regex("[0-9]{6,12}")) }
            ?: (100000 + SecureRandom().nextInt(900000)).toString()
        // Paths and code are fixed/validated here, not supplied by a peer.
        val result = RootShell.run("umask 077; mkdir -p '${path.substringBeforeLast('/')}'; " +
            "printf '%s\\n' '$code' > '$path' && chmod 0600 '$path'")
        return if (result.success) code else ""
    }
}
