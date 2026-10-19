/* Execute both production HMAC call sites with full 32-byte digest writes. */
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma GCC diagnostic ignored "-Wunused-parameter"
typedef uint8_t u8;
typedef intptr_t fido_test_ssize_t;
#define ssize_t fido_test_ssize_t
#define SHA256_DIGEST_SIZE 32
#define ABK_FIDO_HMAC_SALT_LEN 32
#define ABK_FIDO_HMAC_SALT_AUTH_LEN 16
#define ABK_FIDO_ERR_INVALID_OPTION (-200)
#define GFP_KERNEL 0
#define noinline_for_stack __attribute__((noinline))
#define pr_info(...) ((void)0)
#define pr_warn(...) ((void)0)
#define kvzalloc(size, flags) calloc(1, (size))
#define kvfree(pointer) free(pointer)

struct kobject { int unused; };
struct kobj_attribute { int unused; };
struct abk_fido_get_assert_req {
	u8 hmac_key_agreement[64];
	u8 hmac_salt_enc[64];
	u8 hmac_salt_auth[16];
};
struct abk_fido_credential {
	u8 hmac_secret[32];
	u8 priv_key[32];
	char rp_id[16];
};
static struct {
	struct {
		struct abk_fido_credential creds[1];
	} store;
} abk_fido_dev;
static const u8 abk_fido_hmac_zero_iv[16];
static int hmac_calls, aes_calls, hmac_failure;

static void memzero_explicit(void *pointer, size_t length)
{
	volatile u8 *bytes = pointer;
	while (length--)
		*bytes++ = 0;
}
static void *memchr_inv(const void *pointer, int value, size_t length)
{
	const u8 *bytes = pointer;
	while (length--) {
		if (*bytes != (u8)value)
			return (void *)bytes;
		bytes++;
	}
	return NULL;
}
static int sysfs_emit_at(char *buffer, int offset, const char *format, ...)
{
	va_list arguments;
	int length;
	va_start(arguments, format);
	length = vsnprintf(buffer + offset, 4096 - (size_t)offset, format, arguments);
	va_end(arguments);
	return length;
}
static int abk_fido_ecdh_p256(const u8 priv[32], const u8 peer_xy[64], u8 shared[32]);
static int abk_fido_hmac_sha256(const u8 *key, size_t key_len,
			       const u8 *data, size_t data_len, u8 out[32]);
static int abk_fido_aes256_cbc(const u8 key[32], const u8 iv[16],
			      u8 *inout, size_t length, bool encrypt);

/* ABK_FIDO_HMAC_GET_SECRET */

/* ABK_FIDO_HMAC_SELFTEST */

static int abk_fido_ecdh_p256(const u8 priv[32], const u8 peer_xy[64], u8 shared[32])
{
	memcpy(shared, abk_fido_selftest_want_z, SHA256_DIGEST_SIZE);
	return 0;
}

static int abk_fido_hmac_sha256(const u8 *key, size_t key_len,
			       const u8 *data, size_t data_len, u8 out[32])
{
	assert(key && key_len == 32 && data && (data_len == 32 || data_len == 64));
	hmac_calls++;
	if (hmac_calls == hmac_failure)
		return -EIO;
	/* SHA-256 always writes 32 bytes, even for the 16-byte saltAuth check.
	 * AddressSanitizer detects the old stack-buffer-overflow in each caller.
	 */
	memcpy(out, abk_fido_selftest_salt_auth, ABK_FIDO_HMAC_SALT_AUTH_LEN);
	memset(out + ABK_FIDO_HMAC_SALT_AUTH_LEN, 0x5c,
	       SHA256_DIGEST_SIZE - ABK_FIDO_HMAC_SALT_AUTH_LEN);
	return 0;
}

static int abk_fido_aes256_cbc(const u8 key[32], const u8 iv[16],
			      u8 *inout, size_t length, bool encrypt)
{
	assert(!memcmp(key, abk_fido_selftest_want_z, SHA256_DIGEST_SIZE));
	assert(iv == abk_fido_hmac_zero_iv && length == 64);
	aes_calls++;
	if (encrypt)
		memcpy(inout, abk_fido_selftest_want_output_enc, length);
	else
		memset(inout, 0x11, length);
	return 0;
}

int main(int argc, char **argv)
{
	struct abk_fido_get_assert_req req = {0};
	u8 output[64];
	char buffer[4096];
	ssize_t length;
	int failure;
	/* Separate modes let the regression check prove both old call sites fail. */
	if (argc == 2 && !strcmp(argv[1], "selftest")) {
		length = hmac_selftest_show(NULL, NULL, buffer);
		assert(length > 0 && strstr(buffer, "hmac-secret:ok\n"));
		assert(hmac_calls == 3 && aes_calls == 2);
		return 0;
	}
	memset(abk_fido_dev.store.creds[0].hmac_secret, 0x42, 32);
	memcpy(req.hmac_salt_auth, abk_fido_selftest_salt_auth, 16);
	memcpy(req.hmac_salt_enc, abk_fido_selftest_salt_enc, 64);
	assert(abk_fido_hmac_get_secret_locked(0, &req, output) == 0);
	assert(!memcmp(output, abk_fido_selftest_want_output_enc, 64));
	assert(!memcmp(req.hmac_salt_enc, abk_fido_selftest_salt_enc, 64));
	assert(hmac_calls == 3 && aes_calls == 2);
	for (failure = 1; failure <= 3; failure++) {
		hmac_calls = aes_calls = 0;
		hmac_failure = failure;
		memset(output, 0x33, sizeof(output));
		assert(abk_fido_hmac_get_secret_locked(0, &req, output) == -EIO);
		assert(output[0] == 0x33 && output[63] == 0x33);
		assert(!memcmp(req.hmac_salt_enc, abk_fido_selftest_salt_enc, 64));
	}
	hmac_calls = aes_calls = hmac_failure = 0;
	req.hmac_salt_auth[0] ^= 1;
	assert(abk_fido_hmac_get_secret_locked(0, &req, output) == -EINVAL);
	assert(hmac_calls == 1 && aes_calls == 0);
	memset(abk_fido_dev.store.creds[0].hmac_secret, 0, 32);
	assert(abk_fido_hmac_get_secret_locked(0, &req, output) == ABK_FIDO_ERR_INVALID_OPTION);
	return 0;
}
