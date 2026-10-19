from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / 'files/drivers/abk_fido_key/core.c'
HARNESS = ROOT / 'tests/fixtures/fido_dispatch_harness.c'


class DispatchIsolationTests(unittest.TestCase):
    def test_competing_transports_cannot_replace_an_active_approval(self):
        compiler = shlex.split(os.environ.get('CC', ''))
        if not compiler:
            compiler = [path for name in ('cc', 'clang', 'gcc')
                        if (path := shutil.which(name))][:1]
        if not compiler:
            self.skipTest('a C compiler is required for the dispatch harness')

        source = CORE.read_text(encoding='utf-8')
        start = source.index('static void abk_fido_dispatch_msg(')
        end = source.index('static void abk_fido_process_packet(', start)
        defines = source.index('#define ABK_FIDO_REPORT_LEN')
        defines_end = source.index('struct abk_fido_report {', defines)
        harness = HARNESS.read_text(encoding='utf-8').replace(
            '/* ABK_FIDO_DEFINES */', source[defines:defines_end]
        ).replace('/* ABK_FIDO_DISPATCH */', source[start:end])
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / 'dispatch.c').write_text(harness, encoding='utf-8')
            executable = target / ('dispatch.exe' if os.name == 'nt' else 'dispatch')
            compiled = subprocess.run(
                [*compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                 str(target / 'dispatch.c'), '-o', str(executable)],
                capture_output=True, text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
