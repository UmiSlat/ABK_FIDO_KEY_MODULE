from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/patch_kernelsu_sepolicy_for_abk_fido.py'
spec = importlib.util.spec_from_file_location('fido_policy_patch', SCRIPT)
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)
FIXTURE = ROOT / 'tests/fixtures/sukisu_cf87e3f4_rules.c'
# Captured from the exact SukiSU revision selected by failed ABK run 37648124000:
# https://github.com/SukiSU-Ultra/SukiSU-Ultra/blob/
# cf87e3f4ddd3f6e5464d85acf56aaa6950e70841/kernel/selinux/rules.c
MINIMAL = '''void apply_kernelsu_rules(void)
{
    struct policydb *db;
    db = &pol->policydb;
    ksu_allow(db, "init", KERNEL_SU_DOMAIN, ALL, ALL);
}
'''


class PolicyPatchTests(unittest.TestCase):
    def assert_rules_once(self, text):
        self.assertEqual(text.count(patcher.MARKER), 1)
        for rule in patcher.RULES:
            self.assertEqual(text.count(rule), 1)

    def test_exact_failed_sukisu_revision(self):
        original = FIXTURE.read_text(encoding='utf-8')
        self.assertNotIn('restored from https://github.com/tiann/KernelSU/pull/3031', original)
        patched = patcher.patch_rules(original)
        self.assert_rules_once(patched)
        start, end, _ = patcher.rules_function(patched)
        self.assertIn(patcher.MARKER, patched[start:end])
        # handle_sepolicy() also initializes db; it must remain untouched.
        self.assertEqual(original.split('int handle_sepolicy(', 1)[1],
                         patched.split('int handle_sepolicy(', 1)[1])
        block_start = patched.index('    /* ' + patcher.MARKER)
        block_end = patched.index('\n', patched.index(patcher.RULES[-1], block_start))
        self.assertEqual(patched[:block_start-2] + patched[block_end:], original)

    def test_both_module_stages_are_idempotent(self):
        once = patcher.patch_rules(MINIMAL)
        self.assertEqual(patcher.patch_rules(once), once)
        self.assert_rules_once(once)

    def test_inline_policydb_declaration(self):
        source = MINIMAL.replace('    struct policydb *db;\n    db = &pol->policydb;',
                                 '    struct policydb *db = &selinux_state.policy->policydb;')
        patched = patcher.patch_rules(source)
        self.assert_rules_once(patched)
        self.assertLess(patched.index('*db ='), patched.index(patcher.MARKER))

    def test_comments_and_string_braces_do_not_end_function(self):
        source = MINIMAL.replace('    db =', '    /* } db = &fake->policydb; */\n'
                                 '    pr_info("} { db = &fake->policydb;");\n'
                                 '    // }\n    db =')
        patched = patcher.patch_rules(source)
        self.assert_rules_once(patched)

    def test_existing_legacy_placement_is_preserved(self):
        legacy = MINIMAL.replace('    ksu_allow(db, "init",',
                                 '    /* ' + patcher.MARKER + ' */\n' +
                                 '\n'.join('    ' + line for line in patcher.RULES) +
                                 '\n    ksu_allow(db, "init",')
        self.assertEqual(patcher.patch_rules(legacy), legacy)

    def test_policydb_assignment_in_other_function_is_not_used(self):
        unrelated = '\nvoid unrelated(void) { db = &pol->policydb; }\n'
        with self.assertRaisesRegex(ValueError, 'policydb initialization'):
            patcher.patch_rules(MINIMAL.replace('    db = &pol->policydb;\n', '') + unrelated)

    def test_field_assignment_is_not_local_policydb_initialization(self):
        with self.assertRaisesRegex(ValueError, 'policydb initialization'):
            patcher.patch_rules(MINIMAL.replace('    db =', '    other->db ='))

    def test_ambiguous_policydb_assignments_fail(self):
        source = MINIMAL.replace('    db = &pol->policydb;',
                                 '    db = &pol->policydb;\n    db = &other->policydb;')
        with self.assertRaisesRegex(ValueError, 'policydb initialization'):
            patcher.patch_rules(source)

    def test_missing_or_ambiguous_function_fails(self):
        for source in ('void unrelated(void) {}', MINIMAL + MINIMAL):
            with self.subTest(source=source):
                with self.assertRaisesRegex(ValueError, 'definition'):
                    patcher.patch_rules(source)

    def test_partial_or_outside_marker_fails(self):
        for source in ('/* ' + patcher.MARKER + ' */\n' + MINIMAL,
                       MINIMAL.replace('    db =', '    /* ' + patcher.MARKER + ' */\n    db =')):
            with self.subTest(source=source):
                with self.assertRaisesRegex(ValueError, 'complete in-function'):
                    patcher.patch_rules(source)

    def test_unterminated_function_fails(self):
        with self.assertRaisesRegex(ValueError, 'unterminated'):
            patcher.patch_rules(MINIMAL.rsplit('}', 1)[0])

    def test_cli_preserves_line_endings_and_does_not_rewrite_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'rules.c'
            target.write_bytes(MINIMAL.replace('\n', '\r\n').encode())
            for stage in ('after_patch', 'before_build'):
                with self.subTest(stage=stage):
                    result = subprocess.run([sys.executable, str(SCRIPT), str(target)],
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
            data = target.read_bytes()
            self.assertNotIn(b'\n', data.replace(b'\r\n', b''))
            self.assert_rules_once(data.decode())
            invalid = b'/* unsupported layout */\r\n'
            target.write_bytes(invalid)
            result = subprocess.run([sys.executable, str(SCRIPT), str(target)],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(target.read_bytes(), invalid)


if __name__ == '__main__':
    unittest.main()
