"""Native codesign command binding and safe failure diagnostics regression guards."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('bereal_codesign_guards', Path(__file__).parents[1] / 'scripts/bereal-resign.py')
signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signer)


class CodesignGuardTest(unittest.TestCase):
    def test_optional_certificate_prefix_is_bound_and_leaf_der_returned(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / 'leaf-'
            bundle = Path(directory) / 'Scoped.app'
            def native(arguments, **kwargs):
                self.assertEqual(arguments, ['/usr/bin/codesign', '-d',
                    '--extract-certificates=' + str(prefix), str(bundle)])
                # Model getopt's optional-argument binding, including the sole
                # code path. An unbound prefix would be a second target path.
                self.assertEqual([arg for arg in arguments[2:] if not arg.startswith('--')], [str(bundle)])
                Path(str(prefix) + '0').write_bytes(b'synthetic-leaf-der')
                return subprocess.CompletedProcess(arguments, 0, b'', b'')
            with patch.object(signer.subprocess, 'run', side_effect=native):
                self.assertEqual(signer.extract_signing_certificate(bundle, prefix), b'synthetic-leaf-der')

    def test_failed_extraction_emits_only_static_phase_and_reason(self):
        result = subprocess.CompletedProcess([], 1, b'', b'/private/secret-prefix: No such file or directory\nprivate-cert-subject')
        with patch.object(signer.subprocess, 'run', return_value=result), self.assertRaises(RuntimeError) as raised:
            signer.extract_signing_certificate('/private/secret-bundle', '/private/secret-prefix')
        self.assertIn('stage=extract_certificates reason=missing_code_path', str(raised.exception))
        self.assertNotIn('/private', str(raised.exception))
        self.assertNotIn('subject', str(raised.exception))

    def test_known_and_unknown_native_failures_never_emit_raw_stderr(self):
        for stderr, expected in ((b'private data errSecInternalComponent', 'keychain_internal'),
                                 (b'private data bundle format unrecognized, invalid, or unsuitable', 'invalid_bundle'),
                                 (b'private data unclassified error', 'unclassified')):
            with self.subTest(expected=expected):
                result = subprocess.CompletedProcess([], 1, b'', stderr)
                with patch.object(signer.subprocess, 'run', return_value=result), self.assertRaises(RuntimeError) as raised:
                    signer.run(['/usr/bin/codesign', '--sign', 'private-identity', '/private/path'], error_stage='sign_macho')
                self.assertIn('stage=sign_macho reason=' + expected, str(raised.exception))
                self.assertNotIn('private', str(raised.exception))

    def test_unapproved_stage_text_cannot_leak_through_diagnostics(self):
        result = subprocess.CompletedProcess([], 1, b'', b'sensitive stderr')
        with patch.object(signer.subprocess, 'run', return_value=result), self.assertRaises(RuntimeError) as raised:
            signer.run(['/usr/bin/codesign', '-d', '/private/path'], error_stage='secret-stage')
        self.assertIn('stage=unclassified reason=unclassified', str(raised.exception))
        self.assertNotIn('secret', str(raised.exception))
        self.assertNotIn('sensitive', str(raised.exception))


if __name__ == '__main__':
    unittest.main()
