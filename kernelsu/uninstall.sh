#!/system/bin/sh
MODDIR=${0%/*}
. "$MODDIR/service-lib.sh"
# Prevent a late-start child that is still waiting for boot from starting.
touch "$MODDIR/disable"
stop_daemon
# Key material and the daemon's state are deliberately preserved.
