package com.abk.extension.fido

import java.io.Closeable
import java.io.IOException
import android.util.Base64

/** Raw 64-byte CTAP HID transport exposed by the kernel for local providers. */
internal class CtapHidEndpoint : Closeable {
    private val session = java.util.UUID.randomUUID().toString().replace("-", "")
    // Pin the backend for the lifetime of a ceremony; never redirect packets
    // from a stopped daemon into the legacy driver's global queue.
    private val userspace = FidoDaemonBridge.isInstalled()
    fun transceive(cid: Int, command: Int, payload: ByteArray, timeoutMs: Long = 30_000): ByteArray {
        return withTransportLock {
            writeMessage(cid, command, payload)
            val deadline = System.nanoTime() + timeoutMs * 1_000_000
            val response = ArrayList<Byte>()
            var expected = -1
            while (System.nanoTime() < deadline) {
                val remainingNanos = deadline - System.nanoTime()
                val readSeconds = ((remainingNanos + 999_999_999L) / 1_000_000_000L)
                    .coerceIn(1L, MAX_READ_SECONDS)
                val packet = readPacket(readSeconds)
                val packetCid = u32(packet, 0)
                if (packetCid != cid) continue
                val head = packet[4].toInt() and 0xff
                if ((head and 0x80) != 0) {
                    // KEEPALIVE is an out-of-band status packet, not the
                    // response to the request being assembled.
                    if ((head and 0x7f) == HID_KEEPALIVE) continue
                    val responseCommand = head and 0x7f
                    if (responseCommand != command && responseCommand != HID_ERROR) continue
                    if (cid == BROADCAST_CID && command == HID_INIT) {
                        val nonceMatches = payload.size >= 8 &&
                            packet.copyOfRange(7, 15).contentEquals(payload.copyOfRange(0, 8))
                        if (!nonceMatches && responseCommand != HID_ERROR) {
                            // INIT responses echo the nonce. Ignore a response
                            // left by an older transaction on the shared queue.
                            continue
                        }
                    }
                    expected = ((packet[5].toInt() and 0xff) shl 8) or (packet[6].toInt() and 0xff)
                    response.clear()
                    append(response, packet, 7, minOf(expected, 57))
                    if (response.size >= expected) return@withTransportLock response.take(expected).toByteArray()
                } else if (expected >= 0) {
                    append(response, packet, 5, minOf(expected - response.size, 59))
                    if (response.size >= expected) return@withTransportLock response.take(expected).toByteArray()
                }
            }
            throw IOException("CTAP HID response timeout")
        }
    }

    fun writePacket(packet: ByteArray) {
        require(packet.size == 64) { "CTAP HID packet must be 64 bytes" }
        if (userspace) {
            val result = FidoDaemonBridge.writePacket(session, packet)
            if (!result.success) throw IOException("FIDO service write failed: ${result.stdout}")
            return
        }
        val encoded = Base64.encodeToString(packet, Base64.NO_WRAP)
        // A rejected write means nothing reached the endpoint queue, so one
        // retry cannot duplicate a packet. It covers a transiently full kernel
        // TX queue, which would otherwise drop the whole CTAP transaction.
        var failure = ""
        repeat(WRITE_ATTEMPTS) { attempt ->
            val result = RootShell.writeDeviceBase64(DEVICE, encoded)
            if (result.success) return
            failure = result.stdout
            if (attempt < WRITE_ATTEMPTS - 1) Thread.sleep(WRITE_RETRY_DELAY_MS)
        }
        throw IOException("write CTAP endpoint failed: $failure")
    }

    fun readPacket(timeoutSeconds: Long = MAX_READ_SECONDS): ByteArray {
        if (userspace) {
            val packet = FidoDaemonBridge.readPacket(session, timeoutSeconds)
                ?: throw IOException("FIDO service read failed or timed out")
            if (packet.size != 64) throw IOException("short CTAP HID packet: ${packet.size}")
            return packet
        }
        val result = RootShell.readDeviceBase64(DEVICE, 64, timeoutSeconds)
        if (!result.success) throw IOException("read CTAP endpoint failed: ${result.stdout}")
        val packet = Base64.decode(result.stdout.trim(), Base64.DEFAULT)
        if (packet.size != 64) throw IOException("short CTAP HID packet: ${packet.size}")
        return packet
    }

    private fun writeMessage(cid: Int, command: Int, payload: ByteArray) {
        var offset = 0
        val first = ByteArray(64)
        putU32(first, 0, cid)
        first[4] = (command or 0x80).toByte()
        first[5] = (payload.size ushr 8).toByte()
        first[6] = payload.size.toByte()
        val firstLen = minOf(payload.size, 57)
        payload.copyInto(first, 7, 0, firstLen)
        writePacket(first)
        offset += firstLen
        var seq = 0
        while (offset < payload.size) {
            val packet = ByteArray(64)
            putU32(packet, 0, cid)
            packet[4] = seq++.toByte()
            val n = minOf(payload.size - offset, 59)
            payload.copyInto(packet, 5, offset, offset + n)
            writePacket(packet)
            offset += n
        }
    }

    private fun append(dst: MutableList<Byte>, src: ByteArray, off: Int, len: Int) {
        for (i in 0 until len) dst.add(src[off + i])
    }

    override fun close() {
        if (userspace) FidoDaemonBridge.closeSession(session)
    }

    companion object {
        const val DEVICE = "/dev/abk_fido_ctap"
        private const val MAX_READ_SECONDS = 40L
        private const val WRITE_ATTEMPTS = 2
        private const val WRITE_RETRY_DELAY_MS = 20L
        private const val BROADCAST_CID = -1
        private const val HID_INIT = 0x06
        private const val HID_KEEPALIVE = 0x3b
        private const val HID_ERROR = 0x3f
        private val transportLock = Any()

        /**
         * The kernel endpoint has one global TX queue, so reads cannot be
         * isolated by CtapHidEndpoint instances. Keep one complete HID
         * transaction (write plus response reads) exclusive across local and
         * LAN consumers to prevent an old session from stealing packets.
         */
        internal fun <T> withTransportLock(block: () -> T): T =
            synchronized(transportLock) { block() }

        private fun u32(b: ByteArray, o: Int) = ((b[o].toInt() and 0xff) shl 24) or
            ((b[o + 1].toInt() and 0xff) shl 16) or ((b[o + 2].toInt() and 0xff) shl 8) or
            (b[o + 3].toInt() and 0xff)
        private fun putU32(b: ByteArray, o: Int, v: Int) {
            b[o] = (v ushr 24).toByte(); b[o + 1] = (v ushr 16).toByte()
            b[o + 2] = (v ushr 8).toByte(); b[o + 3] = v.toByte()
        }
    }
}
