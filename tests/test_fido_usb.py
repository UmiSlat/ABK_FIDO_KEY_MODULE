from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / 'files/drivers/abk_fido_key/core.c'


class UsbLifetimeTests(unittest.TestCase):
    def test_atomic_callbacks_reset_epochs_and_open_file_lifetime(self):
        compiler = shlex.split(os.environ.get('CC', ''))
        if not compiler:
            compiler = [path for name in ('cc', 'clang', 'gcc')
                        if (path := shutil.which(name))][:1]
        if not compiler:
            self.skipTest('a C compiler is required for the USB harness')
        source = CORE.read_text(encoding='utf-8')

        def between(start, end):
            offset = source.index(start)
            return source[offset:source.index(end, offset)]

        send = re.search(r'^static void abk_fido_send_hid_message\([^;{]+\)\n\{',
                         source, re.M)
        self.assertIsNotNone(send)

        parts = {
            '/* QUEUE_TYPES */': between('struct abk_fido_report {', 'struct abk_fido_channel {'),
            '/* USB_TYPE */': between('struct abk_fido_usb {', 'static struct abk_fido_device abk_fido_dev'),
            '/* QUEUE_FUNCTIONS */': between('static void abk_fido_queue_init(', 'static int abk_fido_shash_digest('),
            '/* USB_SEND */': source[send.start():source.index('static void abk_fido_send_hid_error(', send.start())],
            '/* USB_TX */': between('static void abk_fido_tx_complete(', 'struct abk_fido_file {'),
            '/* USB_FILE */': between('struct abk_fido_file {', 'static ssize_t abk_fido_misc_read('),
            '/* USB_FREE */': between('static void abk_fido_free_requests(', 'static void abk_fido_disable('),
            '/* USB_CALLBACKS */': between('static void abk_fido_disable(', 'static void abk_fido_quiesce('),
        }
        harness = (ROOT / 'tests/fixtures/fido_usb_harness.c').read_text(encoding='utf-8')
        for marker, implementation in parts.items():
            harness = harness.replace(marker, implementation)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / 'usb.c').write_text(harness, encoding='utf-8')
            executable = target / ('usb.exe' if os.name == 'nt' else 'usb')
            result = subprocess.run(
                [*compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                 '-Wno-unused-parameter', str(target / 'usb.c'), '-o', str(executable)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
