#include <assert.h>

#include "dbus-io.h"
#include "common.h"

#define MAX_WSD_TIMERS 10
#define MAX_WSD_FDS 4

struct wsd_utimer {
	struct uloop_timeout utimer;
	DBusTimeout *dtimer;
} timers[MAX_WSD_TIMERS];

struct wsd_ufd {
	struct uloop_fd ufd;
	DBusWatch *dfd;
} fds[MAX_WSD_FDS];

struct wsd_udispatch {
	struct uloop_timeout udefer;
	DBusConnection *dbus;
} dispatch;

static void wsd_trigger_timer(struct uloop_timeout *utimer)
{
	struct wsd_utimer *wsd = container_of(utimer, struct wsd_utimer, utimer);
	// save timeout since timeout_handle will clear wsd->dtimer
	DBusTimeout *timeout = wsd->dtimer;
	dbus_timeout_handle(timeout);
	if (wsd->dtimer) {
		// only set timer if we werent deleted inside timeout_handle -> del_timeout
		uloop_timeout_set(&wsd->utimer, dbus_timeout_get_interval(timeout));
	}
}

static dbus_bool_t wsd_add_timeout(DBusTimeout *timeout, void *data)
{
	//struct prog_context *global = data;
	struct wsd_utimer *wsd = NULL;
	for (size_t i = 0; i < ARRAY_SIZE(timers); ++i)
		if (!timers[i].dtimer) {
			wsd = timers + i;
			break;
		}

	if (!wsd) {
		return FALSE;
	}

	dbus_timeout_set_data(timeout, wsd, NULL);

	wsd->utimer.cb = wsd_trigger_timer;
	wsd->dtimer = timeout;
	if (dbus_timeout_get_enabled(timeout)) {
		uloop_timeout_set(&wsd->utimer, dbus_timeout_get_interval(timeout));
	}
	return TRUE;
}

static void wsd_mod_timeout(DBusTimeout *timeout, void *data)
{
	struct wsd_utimer *wsd = dbus_timeout_get_data(timeout);
	assert(wsd);

	if (dbus_timeout_get_enabled(timeout)) {
		if (wsd->utimer.pending)
			uloop_timeout_cancel(&wsd->utimer);
		uloop_timeout_set(&wsd->utimer, dbus_timeout_get_interval(timeout));
	} else {
		uloop_timeout_cancel(&wsd->utimer);
	}
}

static void wsd_del_timeout(DBusTimeout *timeout, void *data)
{
	struct wsd_utimer *wsd = dbus_timeout_get_data(timeout);
	assert(wsd);

	if (wsd->utimer.pending)
		uloop_timeout_cancel(&wsd->utimer);
	wsd->dtimer = NULL;
}

static inline uint8_t
eventmask_dbus_to_ufd(unsigned d)
{
	return
		(d & DBUS_WATCH_READABLE ? ULOOP_READ  : 0) |
		(d & DBUS_WATCH_WRITABLE ? ULOOP_WRITE : 0);
}

static inline unsigned
eventmask_ufd_to_dbus(unsigned u, bool hup, bool err)
{
	return
		(u & ULOOP_READ ? DBUS_WATCH_READABLE : 0) |
		(u & ULOOP_WRITE ? DBUS_WATCH_WRITABLE : 0) |
		(hup ? DBUS_WATCH_HANGUP : 0) |
		(err ? DBUS_WATCH_ERROR : 0);
}

static void wsd_trigger_io(struct uloop_fd *ufd, unsigned flags)
{
	struct wsd_ufd *wsd = container_of(ufd, struct wsd_ufd, ufd);

	dbus_watch_handle(wsd->dfd, eventmask_ufd_to_dbus(flags, ufd->eof, ufd->error));
}

static dbus_bool_t wsd_add_fd(DBusWatch *dfd, void *data)
{
	struct wsd_ufd *wsd = NULL;
	for (size_t i = 0; i < ARRAY_SIZE(fds); ++i)
		if (!fds[i].dfd) {
			wsd = fds + i;
			break;
		}

	if (!wsd) {
		return FALSE;
	}

	wsd->dfd = dfd;
	wsd->ufd.cb = wsd_trigger_io;
	wsd->ufd.fd = dbus_watch_get_socket(wsd->dfd);
	dbus_watch_set_data(dfd, wsd, NULL);

	if (dbus_watch_get_enabled(dfd)) {
		return uloop_fd_add(&wsd->ufd, eventmask_dbus_to_ufd(dbus_watch_get_flags(dfd))) == 0;
	}

	return TRUE;
}

static void wsd_mod_fd(DBusWatch *timeout, void *data)
{
	struct wsd_ufd *wsd = dbus_watch_get_data(timeout);
	assert(wsd);

	if (dbus_watch_get_enabled(wsd->dfd)) {
		wsd->ufd.fd = dbus_watch_get_socket(wsd->dfd);
		wsd->ufd.cb = wsd_trigger_io;
		uloop_fd_add(&wsd->ufd, eventmask_dbus_to_ufd(dbus_watch_get_flags(wsd->dfd)));
	} else {
		uloop_fd_delete(&wsd->ufd);
	}
}

static void wsd_del_fd(DBusWatch *timeout, void *data)
{
	struct wsd_ufd *wsd = dbus_watch_get_data(timeout);
	assert(wsd);

	uloop_fd_delete(&wsd->ufd);
}
static void wsd_trigger_dispatch(struct uloop_timeout *udefer)
{
	do {
		//
	} while (dbus_connection_dispatch(dispatch.dbus) == DBUS_DISPATCH_DATA_REMAINS);
}

static void wsd_dispatch_cb(DBusConnection *dbus_ctx, DBusDispatchStatus status, void *data)
{
	assert(!dispatch.dbus || dispatch.dbus == dbus_ctx);
	dispatch.dbus = dbus_ctx;
	if (status == DBUS_DISPATCH_DATA_REMAINS) {
		dispatch.udefer.cb = wsd_trigger_dispatch;
		uloop_timeout_set(&dispatch.udefer, 0);
	} else {
	}
}

void wsd_dbus_add_to_uloop(DBusConnection *dbus_ctx)
{
	dbus_connection_set_timeout_functions(dbus_ctx,
			wsd_add_timeout, wsd_del_timeout, wsd_mod_timeout,
			NULL, NULL);
	dbus_connection_set_watch_functions(dbus_ctx,
			wsd_add_fd, wsd_del_fd, wsd_mod_fd,
			NULL, NULL);
	dbus_connection_set_dispatch_status_function(dbus_ctx, wsd_dispatch_cb,
			NULL, NULL);

	// manually poke dbus in case we have dispatch to do from before we were attached to loop
	wsd_dispatch_cb(dbus_ctx, dbus_connection_get_dispatch_status(dbus_ctx), NULL);
}
