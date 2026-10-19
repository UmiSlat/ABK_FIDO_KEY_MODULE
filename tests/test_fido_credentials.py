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
HARNESS = ROOT / 'tests/fixtures/fido_cred_harness.c'


class CredentialLifetimeTests(unittest.TestCase):
    def test_metadata_io_restores_credentials_and_releases_references(self):
        compiler = shlex.split(os.environ.get('CC', ''))
        if not compiler:
            compiler = [path for name in ('cc', 'clang', 'gcc')
                        if (path := shutil.which(name))][:1]
        if not compiler:
            self.skipTest('a C compiler is required for the credential harness')

        source = CORE.read_text(encoding='utf-8')
        start = source.index('static struct file *abk_fido_filp_open_kernel(')
        end = source.index('static void abk_fido_digits_from_bytes(', start)
        harness = HARNESS.read_text(encoding='utf-8').replace(
            '/* ABK_FIDO_CREDENTIAL_WRAPPERS */', source[start:end]
        )
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / 'credentials.c').write_text(harness, encoding='utf-8')
            executable = target / ('credentials.exe' if os.name == 'nt' else 'credentials')
            compiled = subprocess.run(
                [*compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                 str(target / 'credentials.c'), '-o', str(executable)],
                capture_output=True, text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
