/* Exercise production callbacks against DWC3-style synchronous queue failures. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint32_t u32;
typedef intptr_t test_ssize_t;
#define ssize_t test_ssize_t
#ifndef ESHUTDOWN
#define ESHUTDOWN 108
#endif
#define ABK_FIDO_REPORT_LEN 64
#define ABK_FIDO_QUEUE_DEPTH 32
#define ABK_FIDO_MAX_CHANNELS 4
#define GFP_ATOMIC 1
#define GFP_KERNEL 2
#define HID_REPORT_PROTOCOL 1
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define BIT(index) (1UL << (index))
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))
#define READ_ONCE(value) (value)
#define WRITE_ONCE(target, value) ((target) = (value))
#define pr_warn(...) do { } while (0)

typedef int spinlock_t;
typedef int wait_queue_head_t;
static int lock_count, atomic_context, request_frees, usb_frees, queue_calls;
static spinlock_t *io_lock_ptr, *tx_lock_ptr;
static void (*unlock_hook)(void);
static void lock(spinlock_t *value)
{
    assert(!*value);
    if (value == io_lock_ptr)
        assert(!*tx_lock_ptr); /* No tx -> io nesting, including callbacks. */
    *value = 1;
    lock_count++;
}
static void unlock(spinlock_t *value)
{
    assert(*value);
    *value = 0;
    lock_count--;
    if (!lock_count && unlock_hook) {
        void (*hook)(void) = unlock_hook;
        unlock_hook = NULL;
        hook();
    }
}
#define spin_lock_init(value) (*(value) = 0)
#define spin_lock_irqsave(value, flags) do { (flags) = 0; lock(value); } while (0)
#define spin_unlock_irqrestore(value, flags) do { (void)(flags); unlock(value); } while (0)
static void init_waitqueue_head(wait_queue_head_t *wait) { *wait = 0; }
static void wake_up_interruptible(wait_queue_head_t *wait) { (*wait)++; }

struct work_struct { bool queued; unsigned int joins; };
static void schedule_work(struct work_struct *work) { work->queued = true; }
static void cancel_work_sync(struct work_struct *work)
{
    assert(!lock_count && !atomic_context);
    work->queued = false;
    work->joins++;
}
struct mutex { bool held; };
static void mutex_lock(struct mutex *mutex)
{
    assert(!lock_count && !atomic_context && !mutex->held);
    mutex->held = true;
}
static void mutex_unlock(struct mutex *mutex)
{
    assert(mutex->held);
    mutex->held = false;
}
struct kref { int count; };
static void kref_get(struct kref *ref) { assert(ref->count > 0); ref->count++; }
static void kref_put(struct kref *ref, void (*release)(struct kref *))
{
    assert(ref->count > 0);
    if (!--ref->count)
        release(ref);
}
struct usb_request;
struct usb_ep {
    bool enabled;
    void *driver_data;
    struct usb_request *pending[8];
    unsigned int count;
};
struct usb_request {
    void *buf;
    void *context;
    unsigned int actual, length;
    int status;
    void (*complete)(struct usb_ep *, struct usb_request *);
};
struct usb_gadget { int unused; };
struct usb_composite_dev { struct usb_gadget *gadget; };
struct usb_configuration { struct usb_composite_dev *cdev; };
struct usb_function { struct usb_configuration *config; };
struct miscdevice { int unused; };
struct inode { int unused; };
struct file { void *private_data; };
struct abk_fido_channel { int unused; };
struct abk_fido_device;

/* QUEUE_TYPES */
/* USB_TYPE */
static struct {
    struct mutex lock;
    wait_queue_head_t auth_wait;
    struct abk_fido_usb *ctap_usb;
    u32 ctap_cid, ctap_generation;
    bool auth_cache_valid, auth_deny_valid, assert_valid;
} abk_fido_dev;
static struct abk_fido_usb abk_fido_user_usb;
static struct abk_fido_usb *tracked_usb;
enum queue_behavior { QUEUE_NORMAL, QUEUE_INLINE_CURRENT_ERROR, QUEUE_INLINE_OLD_ERROR };
static enum queue_behavior queue_behavior;
static unsigned int inline_failures;
static void abk_fido_clear_assert_state_locked(void)
{
    assert(abk_fido_dev.lock.held && tracked_usb->out_work.joins);
    abk_fido_dev.assert_valid = false;
}
static void misc_deregister(struct miscdevice *misc)
{
    assert(!lock_count && !atomic_context && misc == &tracked_usb->miscdev);
}
static void put_unaligned_be32(u32 value, u8 *buf)
{
    buf[0] = value >> 24; buf[1] = value >> 16; buf[2] = value >> 8; buf[3] = value;
}
static void put_unaligned_be16(unsigned int value, u8 *buf)
{ buf[0] = value >> 8; buf[1] = value; }
static void *kmalloc(size_t size, int flags)
{
    assert(!atomic_context && !lock_count && flags == GFP_KERNEL);
    return malloc(size);
}
static void kfree(void *ptr)
{
    if (ptr == tracked_usb)
        usb_frees++;
    free(ptr);
}
static void giveback(struct usb_ep *ep, struct usb_request *req, int status);
static void check_udc_lock_order(void)
{
    assert(io_lock_ptr && *io_lock_ptr && !*tx_lock_ptr);
}
static int usb_ep_queue(struct usb_ep *ep, struct usb_request *req, int flags)
{
    unsigned int i;
    check_udc_lock_order();
    assert(flags == GFP_ATOMIC);
    if (!ep->enabled)
        return -ESHUTDOWN;
    for (i = 0; i < ep->count; i++)
        assert(ep->pending[i] != req);
    assert(ep->count < ARRAY_SIZE(ep->pending));
    ep->pending[ep->count++] = req;
    req->status = -EINPROGRESS;
    queue_calls++;
    /* DWC3 can complete the current OR a previously cancelled request here,
     * then swallow the failed STARTTRANSFER status and still return zero.
     */
    if (queue_behavior != QUEUE_NORMAL && inline_failures) {
        struct usb_request *cancelled = req;
        inline_failures--;
        if (queue_behavior == QUEUE_INLINE_OLD_ERROR) {
            assert(ep->count > 1 && ep->pending[0] != req);
            cancelled = ep->pending[0];
        }
        giveback(ep, cancelled, -ECONNRESET);
    }
    return 0;
}
static void giveback(struct usb_ep *ep, struct usb_request *req, int status)
{
    unsigned int i;
    for (i = 0; i < ep->count && ep->pending[i] != req; i++)
        ;
    assert(i < ep->count);
    memmove(ep->pending + i, ep->pending + i + 1,
            (--ep->count - i) * sizeof(ep->pending[0]));
    req->status = status;
    req->complete(ep, req);
}
static int usb_ep_disable(struct usb_ep *ep)
{
    check_udc_lock_order();
    ep->enabled = false;
    while (ep->count)
        giveback(ep, ep->pending[0], -ESHUTDOWN);
    return 0;
}
static int usb_ep_dequeue(struct usb_ep *ep, struct usb_request *req)
{
    check_udc_lock_order();
    giveback(ep, req, -ECONNRESET);
    return 0;
}
static int usb_ep_enable(struct usb_ep *ep)
{
    check_udc_lock_order();
    assert(!ep->enabled);
    ep->enabled = true;
    return 0;
}
static int config_ep_by_speed(struct usb_gadget *g, struct usb_function *f, struct usb_ep *ep)
{ return 0; }
static void free_ep_req(struct usb_ep *ep, struct usb_request *req)
{
    assert(!atomic_context && !lock_count && !ep->enabled && !ep->count);
    request_frees++;
    free(req->buf);
    free(req);
}
static void usb_ep_autoconfig_release(struct usb_ep *ep) { assert(!ep->enabled); ep->driver_data = NULL; }

/* QUEUE_FUNCTIONS */
static void abk_fido_tx_kick(struct abk_fido_usb *usb);
/* USB_SEND */
/* USB_TX */
/* USB_FILE */
/* USB_FREE */
/* USB_CALLBACKS */
/* USB_QUIESCE */

static struct usb_request *new_request(struct abk_fido_usb *usb,
        void (*complete)(struct usb_ep *, struct usb_request *))
{
    struct usb_request *req = calloc(1, sizeof(*req));
    req->buf = calloc(1, ABK_FIDO_REPORT_LEN);
    req->context = usb;
    req->complete = complete;
    return req;
}
static void push_tx(struct abk_fido_usb *usb, u32 generation, u8 value)
{
    u8 report[ABK_FIDO_REPORT_LEN];
    memset(report, value, sizeof(report));
    assert(abk_fido_queue_push_tagged(&usb->tx_packets, report, sizeof(report), generation));
}

static void interrupt_with_disconnect(void)
{
    atomic_context = 1;
    abk_fido_disable(&tracked_usb->func);
    atomic_context = 0;
}

static void interrupt_with_reconnect(void)
{
    atomic_context = 1;
    abk_fido_disable(&tracked_usb->func);
    assert(!abk_fido_set_alt(&tracked_usb->func, 0, 0));
    atomic_context = 0;
}

static void run_worker(struct work_struct *work, void (*worker)(struct work_struct *))
{
    work->queued = false;
    worker(work);
    assert(!lock_count);
}

static void drain_io_workers(struct abk_fido_usb *usb)
{
    unsigned int iterations = 0;
    while (usb->tx_work.queued || usb->out_work.queued) {
        assert(++iterations < 100); /* Inline errors must not retry forever. */
        if (usb->tx_work.queued)
            run_worker(&usb->tx_work, abk_fido_tx_worker);
        if (usb->out_work.queued)
            run_worker(&usb->out_work, abk_fido_out_worker);
    }
}

static void set_alt_ok(struct abk_fido_usb *usb)
{
    queue_behavior = QUEUE_NORMAL;
    inline_failures = 0;
    atomic_context = 1;
    assert(!abk_fido_set_alt(&usb->func, 0, 0));
    atomic_context = 0;
    drain_io_workers(usb);
    assert(usb->online && usb->out_ep->count == 4 && !lock_count);
}

int main(void)
{
    struct usb_ep in = {0}, out = {0};
    struct usb_gadget gadget;
    struct usb_composite_dev cdev = { &gadget };
    struct usb_configuration config = { &cdev };
    struct abk_fido_usb *usb = calloc(1, sizeof(*usb));
    struct usb_request *saved_request;
    struct abk_fido_report report;
    struct file fd;
    struct abk_fido_file *ctx;
    unsigned int i;
    int before_queues;
    u32 old_generation;
    u8 reply = 42;

    tracked_usb = usb;
    io_lock_ptr = &usb->io_lock;
    tx_lock_ptr = &usb->tx_lock;
    usb->ref.count = 1;
    usb->func.config = &config;
    usb->in_ep = &in;
    usb->out_ep = &out;
    usb->in_req = new_request(usb, abk_fido_tx_complete);
    for (i = 0; i < ARRAY_SIZE(usb->out_req); i++)
        usb->out_req[i] = new_request(usb, abk_fido_out_complete);
    abk_fido_queue_init(&usb->rx_packets);
    abk_fido_queue_init(&usb->debug_rx);
    abk_fido_queue_init(&usb->tx_packets);

    /* The first OUT STARTTRANSFER can synchronously fail while queue returns 0. */
    queue_behavior = QUEUE_INLINE_CURRENT_ERROR;
    inline_failures = 1;
    atomic_context = 1;
    assert(abk_fido_set_alt(&usb->func, 0, 0) == -ECONNRESET);
    atomic_context = 0;
    drain_io_workers(usb);
    assert(!usb->online && !in.count && !out.count && !usb->out_ready);
    assert(!usb->tx_pending && !lock_count && !inline_failures);

    set_alt_ok(usb);
    assert(usb->online && out.count == 4 && request_frees == 0);
    fd.private_data = &usb->miscdev;
    assert(!abk_fido_misc_open(NULL, &fd));
    ctx = fd.private_data;
    assert(usb->ref.count == 2 && !abk_fido_file_gone(ctx));

    push_tx(usb, usb->generation, 17);
    run_worker(&usb->tx_work, abk_fido_tx_worker);
    assert(in.count == 1 && usb->tx_pending);
    saved_request = usb->in_req;
    push_tx(usb, usb->generation, 18);
    usb->cancel_tx = true;
    schedule_work(&usb->tx_work);
    drain_io_workers(usb);
    /* A merged kick cannot leave the new reply stranded after old IN cancel. */
    assert(in.count == 1 && usb->tx_pending && ((u8 *)usb->in_req->buf)[0] == 18);
    giveback(&in, usb->in_req, 0);
    drain_io_workers(usb);

    /* First IN STARTTRANSFER can also complete inline with error and return 0. */
    queue_behavior = QUEUE_INLINE_CURRENT_ERROR;
    inline_failures = 1;
    before_queues = queue_calls;
    push_tx(usb, usb->generation, 19);
    schedule_work(&usb->tx_work);
    drain_io_workers(usb);
    assert(queue_calls == before_queues + 1 && !in.count && !usb->tx_pending);
    assert(usb->tx_status == -ECONNRESET && !inline_failures);
    queue_behavior = QUEUE_NORMAL;

    usb->out_req[0]->actual = ABK_FIDO_REPORT_LEN;
    giveback(&out, usb->out_req[0], 0);
    assert(out.count == 3 && usb->rx_work.queued && usb->out_work.queued);
    assert(abk_fido_queue_pop(&usb->rx_packets, &report));
    assert(report.generation == usb->generation);
    assert(!abk_fido_queue_empty(&usb->debug_rx));
    before_queues = queue_calls;
    drain_io_workers(usb);
    assert(out.count == 4 && queue_calls == before_queues + 1);

    /* OUT re-submission is deferred and an inline failure is attempted once. */
    usb->out_req[0]->actual = ABK_FIDO_REPORT_LEN;
    giveback(&out, usb->out_req[0], 0);
    queue_behavior = QUEUE_INLINE_CURRENT_ERROR;
    inline_failures = 1;
    before_queues = queue_calls;
    drain_io_workers(usb);
    assert(out.count == 3 && queue_calls == before_queues + 1 && !inline_failures);
    assert(!usb->out_ready && !usb->out_work.queued && usb->out_status[0] == -ECONNRESET);

    /* A queue operation may instead give back a different cancelled request. */
    set_alt_ok(usb);
    usb->out_req[0]->actual = ABK_FIDO_REPORT_LEN;
    giveback(&out, usb->out_req[0], 0);
    queue_behavior = QUEUE_INLINE_OLD_ERROR;
    inline_failures = 1;
    before_queues = queue_calls;
    drain_io_workers(usb);
    assert(out.count == 3 && queue_calls == before_queues + 1 && !inline_failures);
    assert(!usb->out_ready && !usb->out_work.queued && usb->out_status[1] == -ECONNRESET);
    set_alt_ok(usb);

    push_tx(usb, usb->generation, 20);
    run_worker(&usb->tx_work, abk_fido_tx_worker);
    old_generation = usb->generation;
    atomic_context = 1;
    abk_fido_disable(&usb->func);
    atomic_context = 0;
    assert(!usb->online && !usb->tx_pending && !in.count && !out.count);
    assert(usb->in_req == saved_request && request_frees == 0);
    assert(usb->generation != old_generation && abk_fido_file_gone(ctx));
    assert(abk_fido_queue_empty(&usb->debug_rx));

    set_alt_ok(usb);
    push_tx(usb, old_generation, 19);
    push_tx(usb, usb->generation, 20);
    run_worker(&usb->tx_work, abk_fido_tx_worker);
    assert(in.count == 1 && ((u8 *)usb->in_req->buf)[0] == 20);

    giveback(&in, usb->in_req, 0);
    usb->active_generation = old_generation;
    abk_fido_send_hid_message(usb, 1, 2, &reply, 1);
    assert(abk_fido_queue_empty(&usb->tx_packets));
    usb->active_generation = usb->generation;
    abk_fido_send_hid_message(usb, 1, 2, &reply, 1);
    assert(usb->tx_packets.count == 1);
    unlock_hook = interrupt_with_disconnect;
    run_worker(&usb->tx_work, abk_fido_tx_worker);
    assert(!usb->online && !usb->tx_pending && !in.count && !out.count);
    assert(usb->in_req == saved_request && request_frees == 0);

    /* Disconnect/reconnect cannot slip between reservation and UDC submit. */
    set_alt_ok(usb);
    old_generation = usb->generation;
    push_tx(usb, old_generation, 21);
    unlock_hook = interrupt_with_reconnect;
    run_worker(&usb->tx_work, abk_fido_tx_worker);
    drain_io_workers(usb);
    assert(usb->generation != old_generation && usb->online);
    assert(!usb->tx_pending && !in.count && out.count == 4);
    push_tx(usb, old_generation, 22);
    push_tx(usb, usb->generation, 23);
    run_worker(&usb->tx_work, abk_fido_tx_worker);
    assert(in.count == 1 && ((u8 *)usb->in_req->buf)[0] == 23);

    /* Retained fd survives owner teardown, but never resumes after rebind. */
    abk_fido_dev.ctap_usb = usb;
    abk_fido_dev.ctap_cid = 1;
    abk_fido_dev.ctap_generation = usb->generation;
    abk_fido_dev.auth_cache_valid = abk_fido_dev.assert_valid = true;
    abk_fido_dev.auth_deny_valid = true;
    usb->misc_registered = true;
    abk_fido_quiesce(usb);
    assert(usb->dead && !usb->online && usb->out_work.joins == 1);
    assert(!abk_fido_dev.ctap_usb && !abk_fido_dev.ctap_cid && !abk_fido_dev.ctap_generation);
    assert(!abk_fido_dev.auth_cache_valid && !abk_fido_dev.assert_valid);
    assert(abk_fido_dev.auth_deny_valid && !usb->misc_registered);
    assert(abk_fido_file_gone(ctx));
    usb->dead = false;
    usb->online = true;
    usb->binding_id++;
    assert(abk_fido_file_gone(ctx));
    usb->dead = true;
    usb->online = false;
    abk_fido_free_requests(usb);
    abk_fido_release_endpoints(usb);
    assert(request_frees == 5);
    kref_put(&usb->ref, abk_fido_usb_release);
    assert(usb_frees == 0 && abk_fido_file_gone(ctx));
    assert(!abk_fido_misc_release(NULL, &fd));
    assert(usb_frees == 1 && !lock_count && queue_calls > 5);
    return 0;
}
