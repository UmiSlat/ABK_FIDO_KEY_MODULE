#!/system/bin/sh
MODDIR=${0%/*}
. "$MODDIR/service-lib.sh"
umask 077
mkdir -p "$ABK_STATE_DIR" || exit 1
chmod 0700 "$ABK_STATE_DIR" || exit 1

# KernelSU late_start must return promptly. The child waits for Android and
# runs the daemon exactly once; a crash never creates an automatic restart loop.
(
  # /dev is cleared on reboot. An atomic directory lock prevents two manual
  # startup requests from overwriting the PID record of the live daemon.
  ABK_LAUNCH_LOCK=/dev/.abk_fido_userspace_service
  if ! mkdir -m 0700 "$ABK_LAUNCH_LOCK" 2>/dev/null; then
    echo "A service worker is already active; no duplicate startup."
    exit 0
  fi
  trap 'rmdir "$ABK_LAUNCH_LOCK" 2>/dev/null' 0
  abk_wait=0
  while [ "$(getprop sys.boot_completed)" != 1 ]; do
    [ -d "$MODDIR" ] && [ ! -f "$MODDIR/disable" ] && [ ! -f "$MODDIR/remove" ] || exit 0
    [ "$abk_wait" -lt 180 ] || { echo "Boot did not complete; service not started."; exit 1; }
    sleep 2
    abk_wait=$((abk_wait + 1))
  done
  [ ! -f "$MODDIR/disable" ] && [ ! -f "$MODDIR/remove" ] || exit 0
  [ ! -d /sys/kernel/abk_fido_key ] || { echo "Old builtin FIDO is present; service not started."; exit 1; }
  check_companion || exit 1
  if daemon_running; then
    echo "A matching ABK FIDO daemon is already running."
    exit 0
  fi
  echo "Persistent store: $ABK_STATE_DIR/store.bin."
  echo "A valid legacy /metadata/abk_fido_store.bin is imported only if the new store is missing; the legacy file is retained."
  "$MODDIR/bin/abk-fidod" serve --state-dir "$ABK_STATE_DIR" --store "$ABK_STATE_DIR/store.bin" &
  abk_child=$!
  abk_child_start=$(process_start_time "$abk_child")
  if [ -z "$abk_child_start" ]; then
    wait "$abk_child"
    echo "Daemon exited before its PID record was created."
    exit 1
  fi
  printf '%s %s\n' "$abk_child" "$abk_child_start" > "$ABK_PID_FILE.tmp.$abk_child"
  mv -f "$ABK_PID_FILE.tmp.$abk_child" "$ABK_PID_FILE"
  wait "$abk_child"
  abk_exit=$?
  if daemon_running && [ "$abk_pid" = "$abk_child" ] && [ "$abk_start" = "$abk_child_start" ]; then
    : # A still-running process is never assumed to have exited.
  elif [ "$(cat "$ABK_PID_FILE" 2>/dev/null)" = "$abk_child $abk_child_start" ]; then
    rm -f "$ABK_PID_FILE"
  fi
  echo "ABK FIDO daemon exited with status $abk_exit; no automatic restart."
) >> "$ABK_STATE_DIR/service.log" 2>&1 &
exit 0
