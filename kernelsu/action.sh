#!/system/bin/sh
MODDIR=${0%/*}
. "$MODDIR/service-lib.sh"
if daemon_running; then
  stop_daemon
else
  check_companion || exit 1
  sh "$MODDIR/service.sh"
  echo "Startup requested. See $ABK_STATE_DIR/service.log for details."
fi
