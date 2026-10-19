/* Exercise production readers against malformed, host-controlled CBOR. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
#define S64_MAX INT64_MAX
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define ABK_FIDO_MAX_CHANNELS 4

struct abk_cbor_reader { const u8 *buf; size_t len; size_t pos; };
struct abk_fido_slice { const u8 *ptr; size_t len; };
struct abk_fido_channel { bool in_use; u32 cid; u8 msg[64]; };
struct abk_fido_usb { struct abk_fido_channel channels[ABK_FIDO_MAX_CHANNELS]; };

static u64 get_be(const u8 *buf, size_t len)
{
	u64 value = 0;
	while (len--)
		value = (value << 8) | *buf++;
	return value;
}
#define get_unaligned_be16(p) ((u16)get_be(p, 2))
#define get_unaligned_be32(p) ((u32)get_be(p, 4))
#define get_unaligned_be64(p) get_be(p, 8)

/* ABK_FIDO_CBOR_READER */
/* ABK_FIDO_CHANNELS */

static struct abk_cbor_reader reader(const u8 *buf, size_t len)
{
	struct abk_cbor_reader r = { buf, len, 0 };
	return r;
}

static void test_overflow_lengths(void)
{
	u8 data[] = { 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	struct abk_fido_slice slice;
	struct abk_cbor_reader r = reader(data, sizeof(data));
	u64 count;
	s64 integer;

	assert(abk_cbor_read_bytes(&r, &slice) == -EINVAL);
	r = reader(data, sizeof(data));
	assert(abk_cbor_skip(&r) == -EINVAL);
	data[0] = 0x7b;
	r = reader(data, sizeof(data));
	assert(abk_cbor_read_text(&r, &slice) == -EINVAL);
	r = reader(data, sizeof(data));
	assert(abk_cbor_skip(&r) == -EINVAL);
	data[0] = 0x9b;
	r = reader(data, sizeof(data));
	assert(abk_cbor_read_array(&r, &count) == -EINVAL);
	data[0] = 0xbb;
	r = reader(data, sizeof(data));
	assert(abk_cbor_read_map(&r, &count) == -EINVAL);
	r = reader(data, sizeof(data));
	assert(abk_cbor_skip(&r) == -EINVAL);
	data[0] = 0x1b;
	r = reader(data, sizeof(data));
	assert(abk_cbor_read_int(&r, &integer) == -EINVAL);
	data[0] = 0x3b;
	r = reader(data, sizeof(data));
	assert(abk_cbor_read_int(&r, &integer) == -EINVAL);
	data[1] = 0x7f;
	r = reader(data, sizeof(data));
	assert(!abk_cbor_read_int(&r, &integer));
	assert(integer == INT64_MIN);
	data[0] = 0x1b;
	r = reader(data, sizeof(data));
	assert(!abk_cbor_read_int(&r, &integer));
	assert(integer == INT64_MAX);
}

static void test_bounded_skip(void)
{
	u8 deep[2048];
	u8 flat[2048] = { 0x99, 0x07, 0xfd }; /* 2045 single-byte children */
	const u8 valid[] = { 0xa1, 0x61, 'x', 0x82, 0x00, 0x41, 0xaa };
	const u8 truncated[] = { 0x82, 0x00 };
	struct abk_cbor_reader r = reader(valid, sizeof(valid));

	assert(!abk_cbor_skip(&r));
	assert(r.pos == sizeof(valid));
	memset(deep, 0x81, sizeof(deep));
	deep[sizeof(deep) - 1] = 0;
	r = reader(deep, sizeof(deep));
	assert(abk_cbor_skip(&r) == -EINVAL);
	assert(r.pos < 32); /* Reject deeply nested input without recursion. */
	r = reader(flat, sizeof(flat));
	assert(!abk_cbor_skip(&r));
	assert(r.pos == sizeof(flat));
	r = reader(truncated, sizeof(truncated));
	assert(abk_cbor_skip(&r) == -EINVAL);
}

static void test_malformed_inputs_stay_in_bounds(void)
{
	u8 input[256];
	u32 seed = 7;
	size_t len, i;
	unsigned int iteration;

	for (iteration = 0; iteration < 4096; iteration++) {
		len = iteration % sizeof(input);
		for (i = 0; i < len; i++) {
			seed = seed * 1664525U + 1013904223U;
			input[i] = seed >> 24;
		}
		struct abk_cbor_reader r = reader(input, len);
		abk_cbor_skip(&r);
		assert(r.pos <= r.len);
	}
}

static void test_transport_channels_are_independent(void)
{
	struct abk_fido_usb first = { 0 }, second = { 0 };
	struct abk_fido_channel *a, *b;

	a = abk_fido_alloc_channel_locked(&first, 42);
	assert(abk_fido_find_channel_locked(&second, 42) == NULL);
	b = abk_fido_alloc_channel_locked(&second, 42);
	a->msg[0] = 0xaa;
	b->msg[0] = 0xbb;
	assert(abk_fido_find_channel_locked(&first, 42) == a);
	assert(abk_fido_find_channel_locked(&second, 42) == b);
	assert(a->msg[0] == 0xaa && b->msg[0] == 0xbb);
}

int main(void)
{
	test_overflow_lengths();
	test_bounded_skip();
	test_malformed_inputs_stay_in_bounds();
	test_transport_channels_are_independent();
	return 0;
}
