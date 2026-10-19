package com.abk.extension.fido

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import org.junit.Assert.*
import org.junit.Test

class BiometricAuthBridgeTest {
    @Test fun oldPromptCannotApproveNewRequest() {
        BiometricAuthBridge.begin(1001)
        BiometricAuthBridge.begin(1002)
        assertFalse(BiometricAuthBridge.finish(1001, true))
        assertTrue(BiometricAuthBridge.isCurrent(1002))
        assertTrue(BiometricAuthBridge.finish(1002, false))
        assertEquals(false, BiometricAuthBridge.await(1002, 100))
        assertEquals(-1, BiometricAuthBridge.expectedRequestId)
    }

    @Test fun oldWaiterCannotClearOrConsumeNewState() {
        BiometricAuthBridge.begin(2001)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val result = AtomicReference<Boolean?>()
        val waiter = thread {
            result.set(BiometricAuthBridge.await(2001, 100) {
                entered.countDown()
                check(release.await(2, TimeUnit.SECONDS))
                true
            })
        }
        assertTrue(entered.await(2, TimeUnit.SECONDS))
        BiometricAuthBridge.begin(2002)
        Thread.sleep(150) // A's own deadline expires after B is published.
        release.countDown()
        waiter.join(2000)
        assertFalse(waiter.isAlive)
        assertNull(result.get())
        assertTrue(BiometricAuthBridge.isCurrent(2002))
        assertFalse(BiometricAuthBridge.finish(2001, true))
        assertTrue(BiometricAuthBridge.finish(2002, true))
        assertEquals(true, BiometricAuthBridge.await(2002, 100))
    }

    @Test fun cancelledBrokerRequestEndsPromptStateQuickly() {
        BiometricAuthBridge.begin(3001)
        val start = System.nanoTime()
        assertNull(BiometricAuthBridge.await(3001, 25_000) { false })
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 1000)
        assertFalse(BiometricAuthBridge.isCurrent(3001))
        assertFalse(BiometricAuthBridge.finish(3001, true))
    }

    @Test fun brokerFailureAndDuplicateResultsFailClosed() {
        BiometricAuthBridge.begin(4001)
        assertNull(BiometricAuthBridge.await(4001, 100) { error("service disconnected") })
        assertFalse(BiometricAuthBridge.finish(4001, true))
        BiometricAuthBridge.begin(4002)
        assertTrue(BiometricAuthBridge.finish(4002, false))
        assertFalse(BiometricAuthBridge.finish(4002, true))
        assertEquals(false, BiometricAuthBridge.await(4002, 100))
    }

    @Test fun requestTimeoutClearsOnlyItsOwnIdentity() {
        BiometricAuthBridge.begin(5001)
        assertNull(BiometricAuthBridge.await(5001, 1))
        assertEquals(-1, BiometricAuthBridge.expectedRequestId)
        assertFalse(BiometricAuthBridge.finish(5001, true))
        BiometricAuthBridge.begin(5002)
        assertNull(BiometricAuthBridge.await(5001, 1))
        assertTrue(BiometricAuthBridge.isCurrent(5002))
        assertTrue(BiometricAuthBridge.finish(5002, true))
        assertEquals(true, BiometricAuthBridge.await(5002, 100))
    }
}
