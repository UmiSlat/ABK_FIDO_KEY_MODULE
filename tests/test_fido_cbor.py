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
HARNESS = ROOT / 'tests/fixtures/fido_cbor_harness.c'


class CborBoundsTests(unittest.TestCase):
    def test_untrusted_lengths_nesting_and_transport_isolation(self):
        compiler = shlex.split(os.environ.get('CC', ''))
        if not compiler:
            compiler = [path for name in ('cc', 'clang', 'gcc')
                        if (path := shutil.which(name))][:1]
        if not compiler:
            self.skipTest('a C compiler is required for the CBOR harness')

        source = CORE.read_text(encoding='utf-8')
        start = source.index('static int abk_cbor_read_u64(')
        end = source.index('static void abk_cbor_writer_init(', start)
        channels = source.index('static struct abk_fido_channel *abk_fido_find_channel_locked(')
        channels_end = source.index('static u32 abk_fido_next_cid_locked(', channels)
        harness = HARNESS.read_text(encoding='utf-8').replace(
            '/* ABK_FIDO_CBOR_READER */', source[start:end]
        ).replace('/* ABK_FIDO_CHANNELS */', source[channels:channels_end])
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / 'cbor.c').write_text(harness, encoding='utf-8')
            executable = target / ('cbor.exe' if os.name == 'nt' else 'cbor')
            compiled = subprocess.run(
                [*compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                 '-Wno-unused-function', str(target / 'cbor.c'), '-o', str(executable)],
                capture_output=True, text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
