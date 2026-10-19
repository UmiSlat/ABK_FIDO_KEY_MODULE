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
CORE = ROOT / 'files/drivers/abk_fido_key/core.c'


class CryptoLifetimeTests(unittest.TestCase):
    def run_harness(self, fixture: str, substitutions: dict[str, str], *,
                    sanitize=False, argument_sets=((),)):
        compiler = shlex.split(os.environ.get('CC', ''))
        if not compiler:
            compiler = [path for name in ('cc', 'clang', 'gcc')
                        if (path := shutil.which(name))][:1]
        if not compiler:
            self.skipTest('a C compiler is required for the crypto harness')
        harness = (ROOT / 'tests/fixtures' / fixture).read_text(encoding='utf-8')
        for marker, implementation in substitutions.items():
            harness = harness.replace(marker, implementation)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            source = target / 'crypto.c'
            source.write_text(harness, encoding='utf-8')
            executable = target / ('crypto.exe' if os.name == 'nt' else 'crypto')
            flags = ['-std=c11', '-Wall', '-Wextra', '-Werror']
            if sanitize:
                flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
                if sys.platform.startswith('linux'):
                    # Older ASan runtimes can collide with randomized PIE
                    # mappings on hosts with a large mmap entropy setting.
                    flags += ['-fno-pie', '-no-pie']
            compiled = subprocess.run(
                [*compiler, *flags, str(source), '-o', str(executable)],
                capture_output=True, text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            for arguments in argument_sets:
                result = subprocess.run(
                    [str(executable), *arguments], capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_crypto_requests_use_owned_linear_buffers_until_completion(self):
        source = CORE.read_text(encoding='utf-8')
        start = source.index('static int abk_fido_aes256_cbc(')
        end = source.index('/* ECDH over P-256', start)
        self.run_harness('fido_crypto_harness.c', {
            '/* ABK_FIDO_CRYPTO_HELPERS */': source[start:end],
        })

    @unittest.skipIf(os.name == 'nt', 'the HMAC stack regression uses AddressSanitizer')
    def test_hmac_secret_and_selftest_accept_full_sha256_tags_without_stack_overflow(self):
        source = CORE.read_text(encoding='utf-8')
        start = source.index('static noinline_for_stack int abk_fido_hmac_get_secret_locked(')
        end = source.index('static noinline_for_stack int abk_fido_get_assertion_resp(', start)
        vectors_start = source.index('static const u8 abk_fido_selftest_cred_priv[')
        vectors_end = source.index('static ssize_t credential_count_show(', vectors_start)
        self.run_harness('fido_hmac_callers_harness.c', {
            '/* ABK_FIDO_HMAC_GET_SECRET */': source[start:end],
            '/* ABK_FIDO_HMAC_SELFTEST */': source[vectors_start:vectors_end],
        }, sanitize=True, argument_sets=((), ('selftest',)))


if __name__ == '__main__':
    unittest.main()
