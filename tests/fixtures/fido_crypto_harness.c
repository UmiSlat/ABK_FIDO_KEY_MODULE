/* Test production helpers against the scatterlist and async lifetime contract. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
#define AES_BLOCK_SIZE 16
#define GFP_KERNEL 0
#define CRYPTO_TFM_REQ_MAY_BACKLOG 1
#define ERR_PTR(error) ((void *)(intptr_t)(error))
#define IS_ERR(pointer) ((uintptr_t)(pointer) >= (uintptr_t)-4095)
#define PTR_ERR(pointer) ((int)(intptr_t)(pointer))
#define pr_warn_ratelimited(...) ((void)0)
#define crypto_req_done NULL

struct allocation { void *pointer; size_t length; };
static struct allocation allocations[8];
static int allocation_calls, fail_allocation, live_allocations;
static int transform_error, key_error, operation_error, async_status, short_output;
static int waits, encryptions, decryptions, shared_calls, public_calls;
static int pending_kind;
static void *pending_request;
static const u8 readonly_iv[AES_BLOCK_SIZE];

static void *kmalloc(size_t length, int flags)
{
	unsigned int i;
	void *pointer;
	assert(flags == GFP_KERNEL);
	allocation_calls++;
	if (allocation_calls == fail_allocation)
		return NULL;
	pointer = malloc(length);
	assert(pointer);
	memset(pointer, 0xcc, length);
	for (i = 0; i < 8; i++) {
		if (!allocations[i].pointer) {
			allocations[i].pointer = pointer;
			allocations[i].length = length;
			live_allocations++;
			return pointer;
		}
	}
	abort();
}

static void *kzalloc(size_t length, int flags)
{
	void *pointer = kmalloc(length, flags);
	if (pointer)
		memset(pointer, 0, length);
	return pointer;
}

static void *kmemdup(const void *source, size_t length, int flags)
{
	void *pointer = kmalloc(length, flags);
	if (pointer)
		memcpy(pointer, source, length);
	return pointer;
}

static int is_linear_allocation(const void *pointer, size_t length)
{
	uintptr_t start = (uintptr_t)pointer;
	unsigned int i;
	for (i = 0; i < 8; i++) {
		uintptr_t base = (uintptr_t)allocations[i].pointer;
		if (base && start >= base && start - base <= allocations[i].length &&
		    length <= allocations[i].length - (start - base))
			return 1;
	}
	return 0;
}

static void release_allocation(void *pointer, bool sensitive)
{
	unsigned int i;
	if (!pointer)
		return;
	assert(!pending_request); /* An async provider may still use every buffer. */
	for (i = 0; i < 8; i++) {
		if (allocations[i].pointer == pointer) {
			if (sensitive)
				memset(pointer, 0, allocations[i].length);
			free(pointer);
			allocations[i].pointer = NULL;
			allocations[i].length = 0;
			live_allocations--;
			return;
		}
	}
	abort();
}

static void kfree_sensitive(void *pointer) { release_allocation(pointer, true); }
struct scatterlist { void *buffer; unsigned int length; };
static void sg_init_one(struct scatterlist *sg, const void *buffer, unsigned int length)
{
	/* Stack/vmalloc caller buffers deliberately do not pass this check. */
	assert(length && is_linear_allocation(buffer, length));
	sg->buffer = (void *)buffer;
	sg->length = length;
}

struct crypto_wait { int initialized; };
static void crypto_init_wait(struct crypto_wait *wait) { wait->initialized = 1; }
struct crypto_skcipher { int unused; };
struct crypto_kpp { int unused; };
static struct crypto_skcipher cipher;
static struct crypto_kpp kpp;
struct skcipher_request {
	struct crypto_skcipher *tfm;
	struct scatterlist *src, *dst;
	unsigned int length;
	u8 *iv;
	struct crypto_wait *wait;
};
struct kpp_request {
	struct scatterlist *src, *dst;
	unsigned int src_len, dst_len;
	struct crypto_wait *wait;
};

static struct crypto_skcipher *crypto_alloc_skcipher(const char *name, int type, int mask)
{
	assert(!strcmp(name, "cbc(aes)") && type == 0 && mask == 0);
	return transform_error ? ERR_PTR(transform_error) : &cipher;
}
static void crypto_free_skcipher(struct crypto_skcipher *tfm) { assert(tfm == &cipher); }
static struct skcipher_request *skcipher_request_alloc(struct crypto_skcipher *tfm, int flags)
{
	assert(tfm == &cipher);
	return kzalloc(sizeof(struct skcipher_request), flags);
}
static void skcipher_request_zero(struct skcipher_request *req) { memset(req, 0, sizeof(*req)); }
static void skcipher_request_free(struct skcipher_request *req) { release_allocation(req, false); }
static int crypto_skcipher_setkey(struct crypto_skcipher *tfm, const u8 *key, unsigned int length)
{
	assert(tfm == &cipher && key && length == 32);
	return key_error;
}
static void skcipher_request_set_tfm(struct skcipher_request *req, struct crypto_skcipher *tfm)
{
	req->tfm = tfm;
}
static void skcipher_request_set_callback(struct skcipher_request *req, int flags,
					 void *callback, struct crypto_wait *wait)
{
	assert(flags == CRYPTO_TFM_REQ_MAY_BACKLOG && callback == NULL);
	req->wait = wait;
}
static void skcipher_request_set_crypt(struct skcipher_request *req,
		struct scatterlist *src, struct scatterlist *dst, unsigned int length, void *iv)
{
	assert(src == dst && src->length == length);
	assert(iv != readonly_iv && is_linear_allocation(iv, AES_BLOCK_SIZE));
	assert(!memcmp(iv, readonly_iv, AES_BLOCK_SIZE));
	req->src = src;
	req->dst = dst;
	req->length = length;
	req->iv = iv;
}
static void finish_cipher(struct skcipher_request *req)
{
	unsigned int i;
	assert(req->tfm == &cipher && req->wait->initialized);
	for (i = 0; i < req->length; i++)
		((u8 *)req->dst->buffer)[i] ^= 0x5a;
	/* Real CBC writes its IV, including when the caller supplied const data. */
	memset(req->iv, 0x7b, AES_BLOCK_SIZE);
}
static int start_cipher(struct skcipher_request *req)
{
	if (async_status) {
		pending_kind = 1;
		pending_request = req;
		return async_status;
	}
	finish_cipher(req);
	return operation_error;
}
static int crypto_skcipher_encrypt(struct skcipher_request *req) { encryptions++; return start_cipher(req); }
static int crypto_skcipher_decrypt(struct skcipher_request *req) { decryptions++; return start_cipher(req); }
static struct kpp_request *kpp_request_alloc(struct crypto_kpp *tfm, int flags)
{
	assert(tfm == &kpp);
	return kzalloc(sizeof(struct kpp_request), flags);
}
static void kpp_request_free(struct kpp_request *req) { release_allocation(req, false); }
static void kpp_request_set_callback(struct kpp_request *req, int flags,
				    void *callback, struct crypto_wait *wait)
{
	assert(flags == CRYPTO_TFM_REQ_MAY_BACKLOG && callback == NULL);
	req->wait = wait;
}
static void kpp_request_set_input(struct kpp_request *req, struct scatterlist *src, unsigned int length)
{
	assert((src && length == src->length) || (!src && !length));
	req->src = src;
	req->src_len = length;
}
static void kpp_request_set_output(struct kpp_request *req, struct scatterlist *dst, unsigned int length)
{
	assert(dst && length == dst->length);
	req->dst = dst;
	req->dst_len = length;
}
static void finish_kpp(struct kpp_request *req)
{
	assert(req->wait->initialized);
	if (req->src) {
		assert(req->src_len == 64 && ((u8 *)req->src->buffer)[0] == 0x42);
		memset(req->dst->buffer, 0xa5, req->dst_len);
	} else {
		memset(req->dst->buffer, 0x5a, req->dst_len);
	}
	if (short_output)
		req->dst_len--;
}
static int start_kpp(struct kpp_request *req)
{
	if (async_status) {
		pending_kind = 2;
		pending_request = req;
		return async_status;
	}
	finish_kpp(req);
	return operation_error;
}
static int crypto_kpp_compute_shared_secret(struct kpp_request *req) { shared_calls++; return start_kpp(req); }
static int crypto_kpp_generate_public_key(struct kpp_request *req) { public_calls++; return start_kpp(req); }
static int crypto_wait_req(int result, struct crypto_wait *wait)
{
	assert(wait->initialized);
	waits++;
	if (result == -EINPROGRESS || result == -EBUSY) {
		assert(pending_request);
		if (pending_kind == 1)
			finish_cipher(pending_request);
		else
			finish_kpp(pending_request);
		pending_request = NULL;
		return operation_error;
	}
	assert(!pending_request);
	return result;
}

/* ABK_FIDO_CRYPTO_HELPERS */

static void reset_case(void)
{
	assert(!live_allocations && !pending_request);
	allocation_calls = fail_allocation = 0;
	transform_error = key_error = operation_error = async_status = short_output = 0;
	waits = encryptions = decryptions = shared_calls = public_calls = 0;
}

int main(void)
{
	u8 key[32] = {0}, data[64], input[64], output[64];
	int mode, status, error, failure, ret;
	const int statuses[] = {0, -EINPROGRESS, -EBUSY};
	memset(input, 0x42, sizeof(input));
	for (mode = 0; mode <= 1; mode++) {
		for (status = 0; status < 3; status++) {
			for (error = 0; error <= 1; error++) {
				reset_case();
				async_status = statuses[status];
				operation_error = error ? -EIO : 0;
				memset(data, 0x42, sizeof(data));
				ret = abk_fido_aes256_cbc(key, readonly_iv, data, sizeof(data), mode);
				assert(ret == operation_error && waits == 1);
				assert(encryptions == mode && decryptions == !mode);
				assert(data[0] == (error ? 0x42 : (0x42 ^ 0x5a)));
				assert(data[63] == data[0] && readonly_iv[0] == 0);
			}
		}
	}
	for (failure = 1; failure <= 2; failure++) {
		reset_case();
		fail_allocation = failure;
		assert(abk_fido_aes256_cbc(key, readonly_iv, data, sizeof(data), true) == -ENOMEM);
		assert(!encryptions && !waits && !live_allocations);
	}
	reset_case();
	key_error = -EINVAL;
	assert(abk_fido_aes256_cbc(key, readonly_iv, data, sizeof(data), true) == -EINVAL);
	assert(!encryptions && !waits && !live_allocations);
	reset_case();
	transform_error = -ENOENT;
	assert(abk_fido_aes256_cbc(key, readonly_iv, data, sizeof(data), true) == -ENOENT);
	assert(!allocation_calls);
	reset_case();
	assert(abk_fido_aes256_cbc(key, readonly_iv, data, 0, true) == -EINVAL);
	assert(abk_fido_aes256_cbc(key, readonly_iv, data, 63, true) == -EINVAL);
	assert(abk_fido_aes256_cbc(key, readonly_iv, NULL, 64, true) == -EINVAL);
	assert(abk_fido_aes256_cbc(key, readonly_iv, data, UINT_MAX, true) == -EINVAL);
	assert(!allocation_calls);
	for (mode = 0; mode <= 1; mode++) {
		for (status = 0; status < 3; status++) {
			for (error = 0; error <= 1; error++) {
				reset_case();
				async_status = statuses[status];
				operation_error = error ? -EIO : 0;
				memset(output, 0x11, sizeof(output));
				ret = abk_fido_kpp_run_sync(&kpp, mode, mode ? input : NULL,
							 mode ? 64 : 0, output, sizeof(output));
				assert(ret == operation_error && waits == 1);
				assert(shared_calls == mode && public_calls == !mode);
				assert(output[0] == (error ? 0x11 : mode ? 0xa5 : 0x5a));
				assert(output[63] == output[0] && input[0] == 0x42);
			}
		}
	}
	for (failure = 1; failure <= 3; failure++) {
		reset_case();
		fail_allocation = failure;
		assert(abk_fido_kpp_run_sync(&kpp, true, input, 64, output, 32) == -ENOMEM);
		assert(!shared_calls && !waits && !live_allocations);
	}
	reset_case();
	short_output = 1;
	memset(output, 0x11, sizeof(output));
	assert(abk_fido_kpp_run_sync(&kpp, true, input, 64, output, 32) == -EIO);
	assert(output[0] == 0x11 && !live_allocations);
	reset_case();
	assert(abk_fido_kpp_run_sync(&kpp, true, NULL, 64, output, 32) == -EINVAL);
	assert(abk_fido_kpp_run_sync(&kpp, true, input, 64, NULL, 32) == -EINVAL);
	assert(abk_fido_kpp_run_sync(&kpp, true, input, 64, output, 0) == -EINVAL);
	assert(!allocation_calls);
	return 0;
}
