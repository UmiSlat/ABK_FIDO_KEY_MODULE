#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


INCLUDE_ANCHOR = '#include "u_os_desc.h"\n'
INCLUDE_BLOCK = '#include "u_os_desc.h"\n#include <linux/abk_fido_key.h>\n'

PREPARE_NEEDLE = """\t\tlist_for_each_entry_safe(f, tmp, &cfg->func_list, list) {\n"""
PREPARE_BLOCK = """#ifdef CONFIG_ABK_FIDO_KEY
\t\tret = abk_fido_key_prepare_config(cdev, c, &cfg->func_list);
\t\tif (ret) {
\t\t\tpr_err("abk_fido_key: prepare_config failed: %d\\n", ret);
\t\t\tret = 0;
\t\t}
#endif
\n\t\tlist_for_each_entry_safe(f, tmp, &cfg->func_list, list) {\n"""

RELEASE_NEEDLE = """static void gadget_config_attr_release(struct config_item *item)\n{\n\tstruct config_usb_cfg *cfg = to_config_usb_cfg(item);\n\n"""
RELEASE_BLOCK = """static void gadget_config_attr_release(struct config_item *item)\n{\n\tstruct config_usb_cfg *cfg = to_config_usb_cfg(item);\n\n#ifdef CONFIG_ABK_FIDO_KEY
\tabk_fido_key_release_config(&cfg->func_list);
#endif
\n"""

ADD_FUNCTION_NEEDLE = "\t\t\tret = usb_add_function(c, f);\n"
ADD_FUNCTION_BLOCK = """#ifdef CONFIG_ABK_FIDO_KEY
\t\t\tret = abk_fido_key_add_config_function(c, f);
#else
\t\t\tret = usb_add_function(c, f);
#endif
"""


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: patch_configfs_for_abk_fido.py <configfs.c>", file=sys.stderr)
        return 1

    path = Path(sys.argv[1])
    text = path.read_text()
    updated = text

    if '#include <linux/abk_fido_key.h>\n' not in updated:
        if INCLUDE_ANCHOR not in updated:
            raise SystemExit(f"include anchor not found in {path}")
        updated = updated.replace(INCLUDE_ANCHOR, INCLUDE_BLOCK, 1)

    if "abk_fido_key_prepare_config" not in updated:
        if PREPARE_NEEDLE not in updated:
            raise SystemExit(f"prepare injection point not found in {path}")
        updated = updated.replace(PREPARE_NEEDLE, PREPARE_BLOCK, 1)

    if "abk_fido_key_release_config" not in updated:
        if RELEASE_NEEDLE not in updated:
            raise SystemExit(f"release injection point not found in {path}")
        updated = updated.replace(RELEASE_NEEDLE, RELEASE_BLOCK, 1)

    if "abk_fido_key_add_config_function" not in updated:
        if updated.count(ADD_FUNCTION_NEEDLE) != 1:
            raise SystemExit(f"function bind injection point is missing or ambiguous in {path}")
        updated = updated.replace(ADD_FUNCTION_NEEDLE, ADD_FUNCTION_BLOCK, 1)

    if updated != text:
        path.write_text(updated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
