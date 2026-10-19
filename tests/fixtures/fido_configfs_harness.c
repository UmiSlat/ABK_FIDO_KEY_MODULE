/* Model usb_add_function's real failure contract: it unlinks the function and
 * clears f->config, but leaves interface/string IDs and speed flags allocated.
 * Exercise the production optional-function wrapper against that contract.
 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define MAX_CONFIG_INTERFACES 8
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define EXPORT_SYMBOL_GPL(symbol)
#define pr_warn(...) ((void)0)

struct usb_configuration;
struct usb_function_instance { unsigned int refs; };
struct usb_function {
	int (*bind)(struct usb_configuration *, struct usb_function *);
	const struct usb_function_instance *fi;
	struct usb_configuration *config;
	unsigned int refs;
};
struct usb_composite_dev { unsigned char next_string_id; };
struct usb_configuration {
	struct usb_composite_dev *cdev;
	unsigned char next_interface_id;
	unsigned int fullspeed:1;
	unsigned int highspeed:1;
	unsigned int superspeed:1;
	unsigned int superspeed_plus:1;
	struct usb_function *interface[MAX_CONFIG_INTERFACES];
};
struct abk_fido_opts {
	struct usb_function_instance func_inst;
	int minor;
	bool auto_attached;
};
static struct { int lock; } abk_fido_dev;
static int bind_result, fail_stage, add_calls, function_puts, instance_puts;
static int last_attach_error;

static void mutex_lock(int *lock) { (void)lock; }
static void mutex_unlock(int *lock) { (void)lock; }
static void abk_fido_set_attach_state_locked(const char *format, ...)
{
	va_list args;
	assert(!strcmp(format, "bind_failed:%d"));
	va_start(args, format);
	last_attach_error = va_arg(args, int);
	va_end(args);
}
static int abk_fido_bind(struct usb_configuration *cfg, struct usb_function *f)
{
	(void)cfg;
	(void)f;
	return 0;
}
static int native_bind(struct usb_configuration *cfg, struct usb_function *f)
{
	return abk_fido_bind(cfg, f);
}
static int usb_add_function(struct usb_configuration *cfg, struct usb_function *f)
{
	add_calls++;
	f->config = cfg;
	if (fail_stage >= 1)
		cfg->cdev->next_string_id++;
	if (fail_stage >= 2) {
		cfg->interface[cfg->next_interface_id++] = f;
		/* A failed bind may have assigned descriptors before unwinding them;
		 * composite.c still updates its flags after invoking bind().
		 */
		cfg->fullspeed = cfg->highspeed = true;
		cfg->superspeed = cfg->superspeed_plus = true;
	}
	if (bind_result)
		f->config = NULL;
	return bind_result;
}
static void usb_put_function(struct usb_function *f)
{
	assert(f->refs == 1);
	assert(f->fi->refs == 1);
	assert(f->config == NULL);
	f->refs--;
	function_puts++;
}
static void usb_put_function_instance(struct usb_function_instance *fi)
{
	assert(fi->refs == 1);
	fi->refs--;
	instance_puts++;
}

/* ABK_FIDO_CONFIGFS_WRAPPERS */

int main(void)
{
	struct usb_function existing[2] = {0};
	unsigned int flags;
	int stage;

	for (flags = 0; flags < 16; flags++) {
		for (stage = 0; stage <= 2; stage++) {
			struct abk_fido_opts opts = { .func_inst.refs = 1, .auto_attached = true };
			struct usb_function f = { .bind = abk_fido_bind, .fi = &opts.func_inst, .refs = 1 };
			struct usb_composite_dev cdev = { .next_string_id = 11 };
			struct usb_configuration cfg = {
				.cdev = &cdev, .next_interface_id = 2,
				.fullspeed = !!(flags & 1), .highspeed = !!(flags & 2),
				.superspeed = !!(flags & 4), .superspeed_plus = !!(flags & 8),
				.interface = { &existing[0], &existing[1] },
			};
			bind_result = -ENODEV;
			fail_stage = stage;
			add_calls = function_puts = instance_puts = 0;
			assert(abk_fido_key_add_config_function(&cfg, &f) == 0);
			assert(add_calls == 1 && function_puts == 1 && instance_puts == 1);
			assert(f.refs == 0 && opts.func_inst.refs == 0);
			assert(cfg.next_interface_id == 2 && cdev.next_string_id == 11);
			assert(cfg.interface[0] == &existing[0] && cfg.interface[1] == &existing[1]);
			assert(cfg.interface[2] == NULL);
			assert(cfg.fullspeed == !!(flags & 1) && cfg.highspeed == !!(flags & 2));
			assert(cfg.superspeed == !!(flags & 4) && cfg.superspeed_plus == !!(flags & 8));
			assert(last_attach_error == -ENODEV);
		}
	}
	{
		struct abk_fido_opts opts = { .func_inst.refs = 1, .auto_attached = true };
		struct usb_function f = { .bind = abk_fido_bind, .fi = &opts.func_inst, .refs = 1 };
		struct usb_composite_dev cdev = { .next_string_id = 11 };
		struct usb_configuration cfg = { .cdev = &cdev };
		bind_result = 0;
		fail_stage = 2;
		function_puts = instance_puts = 0;
		assert(abk_fido_key_add_config_function(&cfg, &f) == 0);
		assert(f.config == &cfg && cfg.interface[0] == &f);
		assert(cfg.next_interface_id == 1 && cdev.next_string_id == 12);
		assert(function_puts == 0 && instance_puts == 0);
		/* Manually linked FIDO and native functions retain their errors and
		 * references; configfs must run its existing purge/error path.
		 */
		bind_result = -ENOMEM;
		opts.auto_attached = false;
		assert(abk_fido_key_add_config_function(&cfg, &f) == -ENOMEM);
		f.bind = native_bind;
		opts.auto_attached = true;
		assert(abk_fido_key_add_config_function(&cfg, &f) == -ENOMEM);
		assert(function_puts == 0 && instance_puts == 0);
		assert(f.refs == 1 && opts.func_inst.refs == 1);
	}
	return 0;
}
