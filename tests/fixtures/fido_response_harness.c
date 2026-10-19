/* Run the production response encoders with deterministic, public test data.
 * Crypto is mocked: signed_input records the bytes hashed before signing, so
 * the independent Python decoder can check that the returned flags are signed.
 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
#define noinline_for_stack
#define SHA256_DIGEST_SIZE 32
#define ECC_MAX_DIGITS 6
#define ECC_CURVE_NIST_P256 2
#define ECC_CURVE_NIST_P256_DIGITS 4
#define ARRAY_SIZE(value) (sizeof(value) / sizeof((value)[0]))
#define pr_info(...) ((void)0)
#ifndef ENOKEY
#define ENOKEY 126
#endif
#ifndef EBADRQC
#define EBADRQC 56
#endif

/* ABK_FIDO_DEFINES */
/* ABK_FIDO_CREDENTIAL_STRUCTS */
/* ABK_FIDO_WRITER_STRUCT */
/* ABK_FIDO_MAKE_CRED_STRUCT */

struct mutex { bool held; };
static struct {
	struct mutex lock;
	struct abk_fido_store store;
	bool store_dirty;
} abk_fido_dev;
static u8 signed_input[1024];
static size_t signed_input_len;
static int persist_calls, sign_calls;

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
static void put_unaligned_be16(unsigned int value, u8 *out)
{
	out[0] = value >> 8; out[1] = value;
}
static void put_unaligned_be32(u32 value, u8 *out)
{
	out[0] = value >> 24; out[1] = value >> 16;
	out[2] = value >> 8; out[3] = value;
}
static void put_unaligned_be64(u64 value, u8 *out)
{
	unsigned int i;
	for (i = 0; i < 8; i++)
		out[i] = value >> (56 - 8 * i);
}
static int abk_fido_sha256(const u8 *input, size_t len, u8 *output)
{
	if (len > 32) {
		assert(len <= sizeof(signed_input));
		memcpy(signed_input, input, len);
		signed_input_len = len;
	}
	memset(output, 0x44, 32);
	return 0;
}
static int abk_fido_ecdsa_sign_p256(const u8 *priv, const u8 *hash,
				   u8 *sig, size_t *len)
{
	static const u8 test_sig[] = { 0x30, 6, 2, 1, 1, 2, 1, 2 };
	unsigned int i;
	assert(priv[31] == 1 && signed_input_len > 32);
	for (i = 0; i < 32; i++)
		assert(hash[i] == 0x44);
	memcpy(sig, test_sig, sizeof(test_sig));
	*len = sizeof(test_sig);
	sign_calls++;
	return 0;
}
static int abk_fido_load_store_locked(void)
{
	assert(abk_fido_dev.lock.held);
	return 0;
}
static int abk_fido_maybe_persist_locked(void)
{
	assert(abk_fido_dev.lock.held && abk_fido_dev.store_dirty);
	persist_calls++;
	return 0;
}
static void abk_fido_set_last_trace_locked(const char *format, ...)
{
	(void)format;
	assert(abk_fido_dev.lock.held);
}
static int abk_fido_auth_begin_locked(u8 cmd, const char *rp, bool uv, bool rk)
{
	(void)uv; (void)rk;
	assert(abk_fido_dev.lock.held);
	assert(cmd == ABK_FIDO_CTAP_MAKE_CREDENTIAL);
	assert(!strcmp(rp, "example.test"));
	return 0;
}
static bool abk_fido_is_selection_make_credential(struct abk_fido_make_cred_req *req)
{
	(void)req;
	return false;
}
static int abk_fido_make_selection_credential_resp(struct abk_fido_make_cred_req *req,
						  u8 *payload, size_t *len)
{
	(void)req; (void)payload; (void)len;
	assert(false);
	return -EINVAL;
}
static int abk_fido_find_credential_by_id_locked(const u8 *id, size_t len)
{
	(void)id; (void)len;
	assert(abk_fido_dev.lock.held);
	return -ENOENT;
}
static int abk_fido_alloc_credential_locked(void)
{
	assert(abk_fido_dev.lock.held);
	return 0;
}
static void get_random_bytes(void *out, size_t len)
{
	memset(out, 0x6b, len);
}
static void strscpy(char *out, const char *input, size_t capacity)
{
	assert(strlen(input) < capacity);
	memcpy(out, input, strlen(input) + 1);
}
static int ecc_gen_privkey(unsigned int curve, unsigned int digits, u64 *key)
{
	assert(curve == ECC_CURVE_NIST_P256 && digits == 4);
	memset(key, 0, 32);
	((u8 *)key)[31] = 1;
	return 0;
}
static int ecc_make_pub_key(unsigned int curve, unsigned int digits,
			    const u64 *priv, u64 *pub)
{
	/* Public P-256 generator point; no device credential is used. */
	static const u8 generator[64] = {
		0x6b,0x17,0xd1,0xf2,0xe1,0x2c,0x42,0x47,
		0xf8,0xbc,0xe6,0xe5,0x63,0xa4,0x40,0xf2,
		0x77,0x03,0x7d,0x81,0x2d,0xeb,0x33,0xa0,
		0xf4,0xa1,0x39,0x45,0xd8,0x98,0xc2,0x96,
		0x4f,0xe3,0x42,0xe2,0xfe,0x1a,0x7f,0x9b,
		0x8e,0xe7,0xeb,0x4a,0x7c,0x0f,0x9e,0x16,
		0x2b,0xce,0x33,0x57,0x6b,0x31,0x5e,0xce,
		0xcb,0xb6,0x40,0x68,0x37,0xbf,0x51,0xf5
	};
	assert(curve == ECC_CURVE_NIST_P256 && digits == 4);
	assert(((const u8 *)priv)[31] == 1);
	memcpy(pub, generator, sizeof(generator));
	return 0;
}

/* ABK_FIDO_KEY_BYTE_HELPERS */
/* ABK_FIDO_CBOR_WRITER */
/* ABK_FIDO_AUTHDATA_HELPERS */
/* ABK_FIDO_MAKE_CREDENTIAL_RESPONSE */
/* ABK_FIDO_ASSERTION_RESPONSE */

static void print_hex(const u8 *bytes, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++)
		printf("%02x", bytes[i]);
}
static void print_case(const char *name, const u8 *payload, size_t len)
{
	printf("%s ", name);
	print_hex(payload, len);
	printf(" ");
	print_hex(signed_input, signed_input_len);
	printf("\n");
}
int main(void)
{
	struct abk_fido_make_cred_req req = { 0 };
	struct {
		u8 before[16];
		u8 payload[ABK_FIDO_MAX_CBOR];
		u8 after[16];
	} guarded;
	u8 hmac_output[64];
	size_t len, i;
	int use_hmac;

	memset(hmac_output, 0x91, sizeof(hmac_output));
	memset(req.client_data_hash, 0x5a, 32);
	strcpy(req.rp_id, "example.test");
	strcpy(req.user_name, "fixture");
	strcpy(req.user_display, "Fixture User");
	memset(req.user_id, 0x37, 16);
	req.user_id_len = 16;
	req.rk = req.uv = true;
	for (use_hmac = 0; use_hmac <= 1; use_hmac++) {
		memset(&abk_fido_dev, 0, sizeof(abk_fido_dev));
		memset(abk_fido_dev.store.aaguid, 0xa3, 16);
		memset(&guarded, 0xa7, sizeof(guarded));
		req.hmac_secret_requested = use_hmac;
		assert(abk_fido_make_credential_resp(&req, guarded.payload, &len) == 0);
		assert(!abk_fido_dev.lock.held);
		print_case(use_hmac ? "make_hmac" : "make_plain", guarded.payload, len);

		mutex_lock(&abk_fido_dev.lock);
		assert(abk_fido_encode_assertion_locked(0, req.rp_id,
			req.client_data_hash, true, 2,
			use_hmac ? hmac_output : NULL, guarded.payload, &len) == 0);
		mutex_unlock(&abk_fido_dev.lock);
		print_case(use_hmac ? "assert_hmac" : "assert_plain", guarded.payload, len);
		for (i = 0; i < sizeof(guarded.before); i++) {
			assert(guarded.before[i] == 0xa7 && guarded.after[i] == 0xa7);
		}
	}
	assert(persist_calls == 4 && sign_calls == 4);
	return 0;
}
