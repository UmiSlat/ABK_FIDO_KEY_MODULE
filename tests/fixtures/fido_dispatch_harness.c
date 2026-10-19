/* A reentrant peer request models a second RX worker during approval. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint32_t u32;
#define READ_ONCE(value) (value)
#ifndef ENOIOCTLCMD
#define ENOIOCTLCMD 515
#endif
#ifndef EBADRQC
#define EBADRQC 56
#endif
#ifndef EBADSLT
#define EBADSLT 57
#endif
#ifndef ENOKEY
#define ENOKEY 126
#endif

/* ABK_FIDO_DEFINES */

struct mutex { bool held; };
struct abk_fido_usb { int id; u32 active_generation; };
struct abk_fido_channel { bool cancelled; };
static struct mutex abk_fido_ctap_lock;
static struct {
	struct mutex lock;
	struct abk_fido_usb *auth_usb;
	u32 auth_cid;
	struct abk_fido_usb *ctap_usb;
	u32 ctap_cid, ctap_generation;
	bool auth_cache_valid, auth_deny_valid, assert_valid;
	unsigned int assert_count;
	int auth_keepalive_work;
	char last_error[160];
} abk_fido_dev;
static struct abk_fido_usb primary = { .id = 1 }, peer = { .id = 2 };
static struct abk_fido_channel channel;
static int dispatch_calls, busy_calls, cancel_calls, response_calls;
static int dispatch_result, nesting;
static int assert_clear_calls;
static bool inject_peer = true, expected_cached, expected_assertion;
static unsigned int expected_assert_count;
static struct abk_fido_usb *expected_usb = &primary;
static u32 expected_cid = 11;
static void abk_fido_dispatch_msg(struct abk_fido_usb *, u32, u8, const u8 *, size_t);

static void mutex_lock(struct mutex *lock)
{
	assert(!lock->held);
	lock->held = true;
}
static void mutex_unlock(struct mutex *lock)
{
	assert(lock->held);
	lock->held = false;
}
static bool mutex_trylock(struct mutex *lock)
{
	if (lock->held)
		return false;
	lock->held = true;
	return true;
}
static void abk_fido_clear_assert_state_locked(void)
{
	assert(abk_fido_dev.lock.held);
	abk_fido_dev.assert_valid = false;
	abk_fido_dev.assert_count = 0;
	assert_clear_calls++;
}
static u32 abk_fido_next_cid_locked(void) { return 17; }
static struct abk_fido_channel *abk_fido_alloc_channel_locked(struct abk_fido_usb *usb, u32 cid)
{
	(void)usb; (void)cid;
	return &channel;
}
static struct abk_fido_channel *abk_fido_find_channel_locked(struct abk_fido_usb *usb, u32 cid)
{
	return abk_fido_alloc_channel_locked(usb, cid);
}
static void put_unaligned_be32(u32 value, u8 *out)
{
	out[0] = value >> 24; out[1] = value >> 16;
	out[2] = value >> 8; out[3] = value;
}
static void abk_fido_send_hid_error(struct abk_fido_usb *usb, u32 cid, u8 error)
{
	assert(usb == &peer && cid == 22);
	assert(error == ABK_FIDO_HID_ERR_CHANNEL_BUSY);
	busy_calls++;
}
static void abk_fido_send_hid_message(struct abk_fido_usb *usb, u32 cid, u8 cmd,
				      const u8 *payload, size_t len)
{
	(void)usb; (void)cid; (void)cmd; (void)payload; (void)len;
	assert(false); /* These tests send CBOR only. */
}
static int abk_fido_cbor_dispatch(const u8 *msg, size_t len, u8 *payload, size_t *payload_len)
{
	(void)msg; (void)len; (void)payload;
	dispatch_calls++;
	assert(abk_fido_dev.auth_usb == expected_usb);
	assert(abk_fido_dev.auth_cid == expected_cid);
	assert(abk_fido_dev.ctap_usb == expected_usb);
	assert(abk_fido_dev.ctap_cid == expected_cid);
	assert(abk_fido_dev.ctap_generation == expected_usb->active_generation);
	assert(abk_fido_dev.auth_cache_valid == expected_cached);
	assert(abk_fido_dev.assert_valid == expected_assertion);
	assert(abk_fido_dev.assert_count == expected_assert_count);
	if (!nesting && inject_peer) {
		const u8 other[] = { ABK_FIDO_CTAP_RESET };
		nesting++;
		abk_fido_dispatch_msg(&peer, 22, ABK_FIDO_HID_CBOR, other, sizeof(other));
		nesting--;
		assert(abk_fido_dev.auth_usb == expected_usb);
		assert(abk_fido_dev.auth_cid == expected_cid);
		assert(abk_fido_dev.ctap_usb == expected_usb);
		assert(abk_fido_dev.auth_cache_valid == expected_cached);
		assert(abk_fido_dev.assert_valid == expected_assertion);
	}
	*payload_len = 0;
	return dispatch_result;
}
static void cancel_delayed_work_sync(int *work)
{
	assert(work == &abk_fido_dev.auth_keepalive_work);
	assert(abk_fido_ctap_lock.held);
	assert(abk_fido_dev.auth_usb == NULL);
	cancel_calls++;
}
static void abk_fido_send_cbor_result(struct abk_fido_usb *usb, u32 cid, u8 status,
				      const u8 *payload, size_t len)
{
	(void)status; (void)payload; (void)len;
	assert(usb == expected_usb && cid == expected_cid);
	assert(abk_fido_ctap_lock.held);
	response_calls++;
}
static void pr_warn(const char *format, ...) { (void)format; }

/* ABK_FIDO_DISPATCH */

int main(void)
{
	const u8 message[] = { ABK_FIDO_CTAP_GET_INFO };
	const int outcomes[] = { 0, -EPERM, -EINVAL, -ENOMEM, -EOPNOTSUPP };
	size_t i;

	for (i = 0; i < sizeof(outcomes) / sizeof(outcomes[0]); i++) {
		dispatch_result = outcomes[i];
		abk_fido_dispatch_msg(&primary, 11, ABK_FIDO_HID_CBOR, message, sizeof(message));
		assert(!abk_fido_ctap_lock.held && !abk_fido_dev.lock.held);
		assert(abk_fido_dev.auth_usb == NULL);
	}
	assert(dispatch_calls == 5 && busy_calls == 5);
	assert(cancel_calls == 5 && response_calls == 5);
	assert(assert_clear_calls == 1); /* Repeated requests retain one identity. */

	/* Same session keeps the selection grant and multi-account continuation. */
	dispatch_result = 0;
	abk_fido_dev.auth_cache_valid = expected_cached = true;
	abk_fido_dev.assert_valid = expected_assertion = true;
	abk_fido_dev.assert_count = expected_assert_count = 7;
	abk_fido_dev.auth_deny_valid = true;
	abk_fido_dispatch_msg(&primary, 11, ABK_FIDO_HID_CBOR, message, sizeof(message));
	assert(assert_clear_calls == 1 && abk_fido_dev.auth_deny_valid);

	/* A different HID channel must not inherit either authorization state. */
	inject_peer = false;
	expected_cid = 12;
	expected_cached = expected_assertion = false;
	expected_assert_count = 0;
	abk_fido_dispatch_msg(&primary, 12, ABK_FIDO_HID_CBOR, message, sizeof(message));
	assert(assert_clear_calls == 2 && abk_fido_dev.auth_deny_valid);

	/* Identical CID on a separate transport is still a separate session. */
	abk_fido_dev.auth_cache_valid = abk_fido_dev.assert_valid = true;
	abk_fido_dev.assert_count = 7;
	expected_usb = &peer;
	abk_fido_dispatch_msg(&peer, 12, ABK_FIDO_HID_CBOR, message, sizeof(message));
	assert(assert_clear_calls == 3 && abk_fido_dev.auth_deny_valid);

	/* Fast reconnect can reuse the pointer and CID, but never the epoch. */
	abk_fido_dev.auth_cache_valid = abk_fido_dev.assert_valid = true;
	abk_fido_dev.assert_count = 7;
	peer.active_generation++;
	abk_fido_dispatch_msg(&peer, 12, ABK_FIDO_HID_CBOR, message, sizeof(message));
	assert(assert_clear_calls == 4 && abk_fido_dev.auth_deny_valid);
	assert(abk_fido_dev.auth_usb == NULL);
	assert(!abk_fido_ctap_lock.held && !abk_fido_dev.lock.held);
	return 0;
}
