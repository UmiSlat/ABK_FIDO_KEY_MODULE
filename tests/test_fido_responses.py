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
HARNESS = ROOT / 'tests/fixtures/fido_response_harness.c'


def decode_cbor(data: bytes, pos: int = 0):
    """Independent, bounded decoder for the response types used in this test."""
    if pos >= len(data):
        raise ValueError('truncated CBOR')
    initial = data[pos]
    pos += 1
    major, value = initial >> 5, initial & 31
    if value >= 24:
        width = {24: 1, 25: 2, 26: 4, 27: 8}.get(value)
        if width is None or pos + width > len(data):
            raise ValueError('invalid CBOR length')
        value = int.from_bytes(data[pos:pos + width], 'big')
        pos += width
    if major in (0, 1):
        return (value if major == 0 else -1 - value), pos
    if major in (2, 3):
        end = pos + value
        if end > len(data):
            raise ValueError('truncated CBOR string')
        result = data[pos:end]
        return (result.decode('utf-8') if major == 3 else result), end
    if major == 5:
        result = {}
        for _ in range(value):
            key, pos = decode_cbor(data, pos)
            if key in result:
                raise ValueError('duplicate CBOR key')
            result[key], pos = decode_cbor(data, pos)
        return result, pos
    if major == 7 and value in (20, 21):
        return value == 21, pos
    raise ValueError('unsupported CBOR value')


def decode_auth_data(data: bytes):
    """Consume AT/ED sections exactly as a strict WebAuthn client does."""
    if len(data) < 37:
        raise ValueError('short authenticator data')
    flags, pos = data[32], 37
    credential = None
    if flags & 0x40:
        if len(data) < pos + 18:
            raise ValueError('short attested credential data')
        aaguid = data[pos:pos + 16]
        length = int.from_bytes(data[pos + 16:pos + 18], 'big')
        pos += 18
        if pos + length > len(data):
            raise ValueError('short credential ID')
        credential_id = data[pos:pos + length]
        cose, pos = decode_cbor(data, pos + length)
        credential = (aaguid, credential_id, cose)
    extensions = None
    if flags & 0x80:
        extensions, pos = decode_cbor(data, pos)
        if not isinstance(extensions, dict):
            raise ValueError('extensions must be a CBOR map')
    if pos != len(data):
        raise ValueError('unconsumed authenticator data')
    return flags, credential, extensions


class ResponseEncodingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shlex.split(os.environ.get('CC', ''))
        if not compiler:
            compiler = [path for name in ('cc', 'clang', 'gcc')
                        if (path := shutil.which(name))][:1]
        if not compiler:
            raise unittest.SkipTest('a C compiler is required for the response harness')
        source = CORE.read_text(encoding='utf-8')

        def between(start, end):
            offset = source.index(start)
            return source[offset:source.index(end, offset)]

        substitutions = {
            '/* ABK_FIDO_DEFINES */': between(
                '#define ABK_FIDO_REPORT_LEN', 'struct abk_fido_report {'),
            '/* ABK_FIDO_CREDENTIAL_STRUCTS */': between(
                'struct abk_fido_credential {', 'struct abk_fido_store_disk_cred {'),
            '/* ABK_FIDO_WRITER_STRUCT */': between(
                'struct abk_cbor_writer {', 'struct abk_fido_make_cred_req {'),
            '/* ABK_FIDO_MAKE_CRED_STRUCT */': between(
                'struct abk_fido_make_cred_req {', 'struct abk_fido_get_assert_req {'),
            '/* ABK_FIDO_KEY_BYTE_HELPERS */': between(
                'static void abk_fido_p256_scalar_to_bytes(', 'static u64 abk_fido_vli_add('),
            '/* ABK_FIDO_CBOR_WRITER */': between(
                'static void abk_cbor_writer_init(', 'static int abk_cbor_read_cose_p256_xy('),
            '/* ABK_FIDO_AUTHDATA_HELPERS */': between(
                'static void abk_fido_authdata_common(', '/* Windows\' device selection'),
            '/* ABK_FIDO_MAKE_CREDENTIAL_RESPONSE */': between(
                'static noinline_for_stack int abk_fido_make_credential_resp(',
                'static void abk_fido_clear_assert_state_locked(void)\n{'),
            '/* ABK_FIDO_ASSERTION_RESPONSE */': between(
                'static noinline_for_stack int abk_fido_encode_assertion_locked(',
                '/* hmac-secret getAssertion output'),
        }
        harness = HARNESS.read_text(encoding='utf-8')
        for marker, implementation in substitutions.items():
            harness = harness.replace(marker, implementation)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / 'responses.c').write_text(harness, encoding='utf-8')
            executable = target / ('responses.exe' if os.name == 'nt' else 'responses')
            compiled = subprocess.run(
                [*compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                 '-Wno-unused-function', str(target / 'responses.c'), '-o', str(executable)],
                capture_output=True, text=True,
            )
            if compiled.returncode:
                raise AssertionError(compiled.stdout + compiled.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True)
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)
        cls.responses = {}
        for line in result.stdout.splitlines():
            name, encoded, signed = line.split()
            raw = bytes.fromhex(encoded)
            response, end = decode_cbor(raw)
            if end != len(raw):
                raise AssertionError('trailing response CBOR')
            cls.responses[name] = (response, bytes.fromhex(signed))
        if set(cls.responses) != {'make_plain', 'make_hmac', 'assert_plain', 'assert_hmac'}:
            raise AssertionError('missing production response case')

    def test_registration_auth_data_flags_extensions_and_signed_input(self):
        for name in ('make_plain', 'make_hmac'):
            with self.subTest(name=name):
                response, signed = self.responses[name]
                self.assertEqual(set(response), {1, 2, 3})
                self.assertEqual(response[1], 'packed')
                self.assertEqual(response[3], {'alg': -7, 'sig': bytes.fromhex('3006020101020102')})
                auth_data = response[2]
                flags, credential, extensions = decode_auth_data(auth_data)
                self.assertEqual(flags, 0xc5 if name.endswith('hmac') else 0x45)
                self.assertEqual(signed, auth_data + b'\x5a' * 32)
                self.assertEqual(auth_data[:32], b'\x44' * 32)
                self.assertEqual(int.from_bytes(auth_data[33:37], 'big'), 0)
                aaguid, credential_id, cose = credential
                self.assertEqual(aaguid, b'\xa3' * 16)
                self.assertEqual(credential_id, b'\x6b' * 32)
                self.assertEqual(set(cose), {1, 3, -1, -2, -3})
                self.assertEqual((cose[1], cose[3], cose[-1]), (2, -7, 1))
                self.assertEqual((len(cose[-2]), len(cose[-3])), (32, 32))
                self.assertEqual(extensions, {'hmac-secret': True} if name.endswith('hmac') else None)

    def test_assertion_auth_data_flags_extensions_and_signed_input(self):
        for name in ('assert_plain', 'assert_hmac'):
            with self.subTest(name=name):
                response, signed = self.responses[name]
                self.assertEqual(set(response), {1, 2, 3, 4, 5})
                auth_data = response[2]
                flags, credential, extensions = decode_auth_data(auth_data)
                self.assertEqual(flags, 0x85 if name.endswith('hmac') else 0x05)
                self.assertIsNone(credential)
                self.assertEqual(signed, auth_data + b'\x5a' * 32)
                self.assertEqual(int.from_bytes(auth_data[33:37], 'big'), 1)
                self.assertEqual(response[1], {'id': b'\x6b' * 32, 'type': 'public-key'})
                self.assertEqual(response[4]['id'], b'\x37' * 16)
                self.assertEqual(response[5], 2)
                self.assertEqual(extensions, {'hmac-secret': b'\x91' * 64}
                                 if name.endswith('hmac') else None)

    def test_missing_extension_flag_reproduces_strict_client_rejection(self):
        for name in ('make_hmac', 'assert_hmac'):
            with self.subTest(name=name):
                response, _ = self.responses[name]
                malformed = bytearray(response[2])
                malformed[32] &= ~0x80
                with self.assertRaisesRegex(ValueError, 'unconsumed authenticator data'):
                    decode_auth_data(bytes(malformed))


if __name__ == '__main__':
    unittest.main()
