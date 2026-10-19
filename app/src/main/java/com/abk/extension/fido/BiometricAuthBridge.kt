package com.abk.extension.fido

import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit

internal object BiometricAuthBridge {
    private class RequestState(val id: Int) {
        val result = ArrayBlockingQueue<Boolean>(1)
        var answered = false
    }

    private val stateLock = Any()
    @Volatile private var current: RequestState? = null

    val isAuthenticating: Boolean
        get() = synchronized(stateLock) { current?.answered == false }

    val expectedRequestId: Int
        get() = current?.id ?: -1

    fun begin(requestId: Int) {
        require(requestId > 0)
        synchronized(stateLock) {
            val previous = current
            current = RequestState(requestId)
            if (previous != null && !previous.answered) {
                previous.answered = true
                previous.result.offer(false)
            }
        }
    }

    fun isCurrent(requestId: Int): Boolean = synchronized(stateLock) {
        current?.let { it.id == requestId && !it.answered } ?: false
    }

    /** A callback must carry its original request id, never the latest id. */
    fun finish(requestId: Int, success: Boolean): Boolean = synchronized(stateLock) {
        val state = current
        if (state == null || state.id != requestId || state.answered) return@synchronized false
        state.answered = true
        state.result.offer(success)
    }

    fun await(
        requestId: Int,
        timeoutMs: Long,
        stillPending: () -> Boolean = { true },
    ): Boolean? {
        val state = synchronized(stateLock) { current?.takeIf { it.id == requestId } } ?: return null
        val started = System.nanoTime()
        val timeoutNanos = TimeUnit.MILLISECONDS.toNanos(timeoutMs.coerceAtLeast(0))
        return try {
            var result: Boolean? = null
            while (true) {
                // The broker may have cancelled this request while the system
                // biometric prompt was still visible. Fail closed on IPC errors.
                if (!runCatching(stillPending).getOrDefault(false)) break
                val remaining = timeoutNanos - (System.nanoTime() - started)
                if (remaining <= 0) break
                result = state.result.poll(minOf(remaining, POLL_NANOS), TimeUnit.NANOSECONDS)
                if (result != null) break
                if (synchronized(stateLock) { current !== state }) break
            }
            result
        } finally {
            synchronized(stateLock) {
                if (current === state) current = null
            }
        }
    }

    private val POLL_NANOS = TimeUnit.MILLISECONDS.toNanos(300)
}
