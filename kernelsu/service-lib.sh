#!/system/bin/sh
# Sourced with MODDIR set to this KernelSU module's absolute directory.
ABK_STATE_DIR=/data/adb/abk-fido
ABK_PID_FILE="$ABK_STATE_DIR/service.pid"
ABK_MIN_COMPANION=3

check_companion() {
  for abk_package in com.abk.extension.fido com.abk.extension.fido.debug; do
    if pm path "$abk_package" 2>/dev/null | grep -q '^package:'; then
      abk_version=$(dumpsys package "$abk_package" 2>/dev/null |
        sed -n 's/.*versionCode=\([0-9][0-9]*\).*/\1/p' | head -n 1)
      case "$abk_version" in
        ''|*[!0-9]*)
          echo "Cannot verify $abk_package version; refusing to start."
          return 1 ;;
      esac
      if [ "$abk_version" -lt "$ABK_MIN_COMPANION" ]; then
        echo "$abk_package is versionCode $abk_version; update to Companion 0.4.0 (versionCode 3) or newer, or uninstall the old app first."
        echo "The old app writes the key store directly and cannot run with this daemon."
        return 1
      fi
    fi
  done
  return 0
}

process_start_time() {
  # Remove pid and the parenthesized comm before selecting stat field 22.
  sed 's/^.*) //' "/proc/$1/stat" 2>/dev/null | awk '{print $20}'
}

daemon_running() {
  [ -r "$ABK_PID_FILE" ] || return 1
  read -r abk_pid abk_start < "$ABK_PID_FILE" || return 1
  case "$abk_pid:$abk_start" in
    *[!0-9:]*|:*) return 1 ;;
  esac
  [ -n "$abk_pid" ] && [ -n "$abk_start" ] && [ "$abk_pid" -gt 1 ] || return 1
  kill -0 "$abk_pid" 2>/dev/null || return 1
  [ "$(process_start_time "$abk_pid")" = "$abk_start" ] || return 1
  abk_executable=$(tr '\000' '\n' < "/proc/$abk_pid/cmdline" 2>/dev/null | sed -n '1p')
  abk_command=$(tr '\000' '\n' < "/proc/$abk_pid/cmdline" 2>/dev/null | sed -n '2p')
  [ "$abk_executable" = "$MODDIR/bin/abk-fidod" ] && [ "$abk_command" = serve ]
}

stop_daemon() {
  if ! daemon_running; then
    echo "No matching ABK FIDO daemon is running."
    return 0
  fi
  abk_stop_pid=$abk_pid
  abk_stop_start=$abk_start
  # Identity was checked by pid, kernel start time, executable and subcommand.
  kill -TERM "$abk_stop_pid" 2>/dev/null || return 1
  abk_wait=0
  while [ "$abk_wait" -lt 15 ]; do
    if ! daemon_running || [ "$abk_pid" != "$abk_stop_pid" ] || [ "$abk_start" != "$abk_stop_start" ]; then
      echo "ABK FIDO daemon stopped."
      return 0
    fi
    sleep 1
    abk_wait=$((abk_wait + 1))
  done
  echo "ABK FIDO is still shutting down; it was not force-killed. Reboot to finish safely."
  return 1
}
