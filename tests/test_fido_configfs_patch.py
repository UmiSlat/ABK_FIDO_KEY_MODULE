from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/patch_configfs_for_abk_fido.py'
CORE = ROOT / 'files/drivers/abk_fido_key/core.c'
HARNESS = ROOT / 'tests/fixtures/fido_configfs_harness.c'

# Preserve the relevant AOSP configfs bind/release structure, including the
# existing rollback for explicitly linked functions. No network is needed.
CONFIGFS = '''#include "u_os_desc.h"
static void gadget_config_attr_release(struct config_item *item)
{
\tstruct config_usb_cfg *cfg = to_config_usb_cfg(item);

\tWARN_ON(!list_empty(&cfg->c.functions));
\tlist_del(&cfg->c.list);
\tkfree(cfg);
}
static int configfs_composite_bind(struct usb_gadget *gadget,
\t\tstruct usb_gadget_driver *gdriver)
{
\tlist_for_each_entry(c, &gi->cdev.configs, list) {
\t\tlist_for_each_entry_safe(f, tmp, &cfg->func_list, list) {
\t\t\tlist_del(&f->list);
\t\t\tret = usb_add_function(c, f);
\t\t\tif (ret) {
\t\t\t\tlist_add(&f->list, &cfg->func_list);
\t\t\t\tgoto err_purge_funcs;
\t\t\t}
\t\t}
\t}
}
'''


class ConfigfsPatchTests(unittest.TestCase):
    def run_patch(self, path):
        return subprocess.run([sys.executable, str(SCRIPT), str(path)],
                              capture_output=True, text=True)

    def test_injection_is_idempotent_and_preserves_native_failure_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'configfs.c'
            path.write_text(CONFIGFS, encoding='utf-8')
            result = self.run_patch(path)
            self.assertEqual(result.returncode, 0, result.stderr)
            once = path.read_text(encoding='utf-8')
            self.assertEqual(once.count('abk_fido_key_prepare_config('), 1)
            self.assertEqual(once.count('abk_fido_key_release_config('), 1)
            self.assertEqual(once.count('abk_fido_key_add_config_function('), 1)
            self.assertIn('#else\n\t\t\tret = usb_add_function(c, f);\n#endif', once)
            self.assertIn('\t\t\tif (ret) {\n'
                          '\t\t\t\tlist_add(&f->list, &cfg->func_list);\n'
                          '\t\t\t\tgoto err_purge_funcs;', once)
            self.assertLess(once.index('abk_fido_key_prepare_config('),
                            once.index('abk_fido_key_add_config_function('))
            self.assertEqual(self.run_patch(path).returncode, 0)
            self.assertEqual(path.read_text(encoding='utf-8'), once)

    def test_existing_legacy_patch_gets_failure_isolation(self):
        legacy = CONFIGFS.replace('#include "u_os_desc.h"\n',
                                  '#include "u_os_desc.h"\n'
                                  '#include <linux/abk_fido_key.h>\n')
        legacy = legacy.replace('\tWARN_ON(',
                                '\tabk_fido_key_release_config(&cfg->func_list);\n'
                                '\tWARN_ON(')
        legacy = legacy.replace('\t\tlist_for_each_entry_safe(',
                                '\t\tret = abk_fido_key_prepare_config(cdev, c, &cfg->func_list);\n'
                                '\t\tlist_for_each_entry_safe(')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'configfs.c'
            path.write_text(legacy, encoding='utf-8')
            result = self.run_patch(path)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(path.read_text(encoding='utf-8').count(
                'abk_fido_key_add_config_function('), 1)

    def test_missing_or_ambiguous_bind_anchor_fails_without_writing(self):
        anchor = '\t\t\tret = usb_add_function(c, f);\n'
        for source in (CONFIGFS.replace(anchor, ''),
                       CONFIGFS.replace(anchor, anchor * 2)):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'configfs.c'
                path.write_text(source, encoding='utf-8')
                result = self.run_patch(path)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('bind injection point', result.stderr)
                self.assertEqual(path.read_text(encoding='utf-8'), source)

    def test_optional_failure_restores_composite_state_and_references(self):
        compiler = shlex.split(os.environ.get('CC', ''))
        if not compiler:
            compiler = [path for name in ('cc', 'clang', 'gcc')
                        if (path := shutil.which(name))][:1]
        if not compiler:
            self.skipTest('a C compiler is required for the configfs harness')

        source = CORE.read_text(encoding='utf-8')
        start = source.index('static bool abk_fido_is_auto_function(')
        end = source.index('void abk_fido_key_release_config(', start)
        harness = HARNESS.read_text(encoding='utf-8').replace(
            '/* ABK_FIDO_CONFIGFS_WRAPPERS */', source[start:end])
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / 'configfs.c').write_text(harness, encoding='utf-8')
            executable = target / ('configfs.exe' if os.name == 'nt' else 'configfs')
            compiled = subprocess.run(
                [*compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                 str(target / 'configfs.c'), '-o', str(executable)],
                capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
