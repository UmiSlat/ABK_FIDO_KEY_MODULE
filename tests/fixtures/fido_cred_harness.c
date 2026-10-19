/* Exercise the production metadata wrappers with the kernel credential contract. */
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

/* Host libc may already define these names (notably MinGW's ssize_t). */
typedef intptr_t fido_test_ssize_t;
typedef long long fido_test_loff_t;
typedef unsigned short fido_test_umode_t;
#define ssize_t fido_test_ssize_t
#define loff_t fido_test_loff_t
#define umode_t fido_test_umode_t

#define ERR_PTR(error) ((void *)(intptr_t)(error))

struct task_struct { int unused; };
struct file { int unused; };
struct cred { unsigned int usage; };

static struct task_struct init_task;
static struct cred original_cred;
static struct cred allocated_cred;
static const struct cred *current_cred;
static struct file store;
static const char store_path[] = "/metadata/abk_fido_store.bin";
static char buffer[8];
static loff_t position;
static int fail_allocation;
static int allocation_calls;
static int override_calls;
static int revert_calls;
static int put_calls;
static int io_calls;
static int io_fails;

static struct cred *prepare_kernel_cred(struct task_struct *task)
{
	/* Linux 6.6 refuses NULL; use init's kernel security context. */
	assert(task == &init_task);
	assert(current_cred == &original_cred);
	assert(allocated_cred.usage == 0);
	allocation_calls++;
	if (fail_allocation)
		return NULL;
	allocated_cred.usage = 1;
	return &allocated_cred;
}

static void put_cred(const struct cred *cred)
{
	assert(cred == &allocated_cred);
	assert(allocated_cred.usage > 0);
	allocated_cred.usage--;
	put_calls++;
}

static const struct cred *override_creds(const struct cred *cred)
{
	assert(current_cred == &original_cred);
	assert(cred == &allocated_cred);
	assert(allocated_cred.usage == 1);
	allocated_cred.usage++; /* The task takes a second reference. */
	current_cred = cred;
	override_calls++;
	return &original_cred;
}

static void revert_creds(const struct cred *cred)
{
	assert(current_cred == &allocated_cred);
	assert(cred == &original_cred);
	assert(allocated_cred.usage == 2);
	current_cred = cred;
	put_cred(&allocated_cred); /* Drop the task's reference, not the caller's. */
	revert_calls++;
}

static void check_io(void)
{
	assert(current_cred == &allocated_cred);
	assert(allocated_cred.usage == 2);
	assert(override_calls == 1 && revert_calls == 0);
	io_calls++;
}

static struct file *filp_open(const char *path, int flags, umode_t mode)
{
	check_io();
	assert(path == store_path && flags == 123 && mode == 0600);
	return io_fails ? ERR_PTR(-EACCES) : &store;
}

static ssize_t kernel_read(struct file *file, void *buf, size_t len, loff_t *pos)
{
	check_io();
	assert(file == &store && buf == buffer && len == sizeof(buffer));
	assert(pos == &position);
	*pos = 7;
	return io_fails ? -EIO : 7;
}

static ssize_t kernel_write(struct file *file, const void *buf, size_t len,
			    loff_t *pos)
{
	return kernel_read(file, (void *)buf, len, pos);
}

/* ABK_FIDO_CREDENTIAL_WRAPPERS */

static void reset_case(int allocation_fails, int operation_fails)
{
	assert(allocated_cred.usage == 0);
	current_cred = &original_cred;
	fail_allocation = allocation_fails;
	io_fails = operation_fails;
	position = 0;
	allocation_calls = override_calls = revert_calls = put_calls = io_calls = 0;
}

static void check_lifetime(void)
{
	assert(allocation_calls == 1);
	assert(current_cred == &original_cred);
	assert(allocated_cred.usage == 0);
	assert(io_calls == !fail_allocation);
	assert(override_calls == !fail_allocation);
	assert(revert_calls == !fail_allocation);
	assert(put_calls == (fail_allocation ? 0 : 2));
}

int main(void)
{
	int allocation_fails, operation_fails;

	for (allocation_fails = 0; allocation_fails <= 1; allocation_fails++) {
		for (operation_fails = 0; operation_fails <= 1; operation_fails++) {
			struct file *file;
			ssize_t ret;

			reset_case(allocation_fails, operation_fails);
			file = abk_fido_filp_open_kernel(store_path, 123, 0600);
			assert(file == (allocation_fails ? ERR_PTR(-ENOMEM) :
					operation_fails ? ERR_PTR(-EACCES) : &store));
			check_lifetime();

			reset_case(allocation_fails, operation_fails);
			ret = abk_fido_kernel_read(&store, buffer, sizeof(buffer), &position);
			assert(ret == (allocation_fails ? -ENOMEM : operation_fails ? -EIO : 7));
			assert(position == (allocation_fails ? 0 : 7));
			check_lifetime();

			reset_case(allocation_fails, operation_fails);
			ret = abk_fido_kernel_write(&store, buffer, sizeof(buffer), &position);
			assert(ret == (allocation_fails ? -ENOMEM : operation_fails ? -EIO : 7));
			assert(position == (allocation_fails ? 0 : 7));
			check_lifetime();
		}
	}
	return 0;
}
