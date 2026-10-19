#!/system/bin/sh
SKIPMOUNT=true
PROPFILE=false
POSTFSDATA=false
LATESTARTSERVICE=true

[ "$ARCH" = arm64 ] || abort "ABK FIDO Userspace requires Android arm64."
[ -n "$KSU" ] || abort "Install this package through KernelSU."
[ ! -d /sys/kernel/abk_fido_key ] || abort "Old builtin ABK FIDO is active. First boot a kernel without the builtin FIDO driver."

. "$MODPATH/service-lib.sh"
check_companion || abort "Update or uninstall the old Companion app before installing this module."

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/bin/abk-fidod" 0 0 0700
for abk_script in customize.sh service.sh action.sh uninstall.sh; do
  set_perm "$MODPATH/$abk_script" 0 0 0755
done
set_perm "$MODPATH/service-lib.sh" 0 0 0600
ui_print "Companion 0.4.0 (versionCode 3) or newer is required for approval."
ui_print "Existing keys are preserved. Without a compatible Companion, requests cannot be approved."
ui_print "Store: /data/adb/abk-fido/store.bin; valid legacy metadata keys import once."
ui_print "Reboot to start the userspace FIDO service."
