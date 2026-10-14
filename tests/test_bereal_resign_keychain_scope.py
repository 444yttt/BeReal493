"""Temporary signing-keychain discovery and unconditional cleanup guards."""
from contextlib import redirect_stdout, redirect_stderr
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location('bereal_keychain_scope', Path(__file__).parents[1] / 'scripts/bereal-resign.py')
signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signer)
FINGERPRINT = 'A' * 40
KEYCHAIN = '/private/temporary signing.keychain-db'
ORIGINAL = ['/private/login keychain-db', '/private/system.keychain', '/private/login keychain-db']
LIST_OUTPUT = b'    "/private/login keychain-db"\n    "/private/system.keychain"\n    "/private/login keychain-db"\n'


class KeychainScopeTest(unittest.TestCase):
    def native(self, commands, fail=None):
        def call(arguments, **kwargs):
            commands.append(arguments)
            if fail and fail(arguments):
                return subprocess.CompletedProcess(arguments, 1, b'', b'private-password-and-certificate-path')
            output = LIST_OUTPUT if arguments[1:] == ['list-keychains', '-d', 'user'] else b''
            if arguments[1] == 'find-identity':
                output = ('1) ' + FINGERPRINT + '\n1 valid identities found').encode()
            return subprocess.CompletedProcess(arguments, 0, output, b'')
        return call

    def scope(self):
        return signer.signing_keychain_scope(KEYCHAIN, 'private-keychain-password',
            '/private/identity.p12', 'private-p12-password', FINGERPRINT)

    def test_exact_original_list_restored_and_active_list_deduplicated(self):
        commands = []
        with patch.object(signer.subprocess, 'run', side_effect=self.native(commands)):
            with self.scope():
                active = [command for command in commands if command[1:5] == ['list-keychains', '-d', 'user', '-s']]
                self.assertEqual(active[-1][5:], [KEYCHAIN, ORIGINAL[0], ORIGINAL[1]])
        self.assertEqual(commands[0], ['/usr/bin/security', 'list-keychains', '-d', 'user'])
        self.assertEqual(commands[1][1], 'create-keychain')
        selection = next(i for i, command in enumerate(commands) if command[1:5] == ['list-keychains', '-d', 'user', '-s'])
        identity = next(i for i, command in enumerate(commands) if command[1] == 'find-identity')
        self.assertLess(selection, identity)
        self.assertEqual(commands[-2][5:], ORIGINAL)
        self.assertEqual(commands[-1], ['/usr/bin/security', 'delete-keychain', KEYCHAIN])

    def test_callback_failure_restores_then_deletes_without_logging_assets(self):
        commands, output = [], io.StringIO()
        with patch.object(signer.subprocess, 'run', side_effect=self.native(commands)), redirect_stdout(output), redirect_stderr(output):
            with self.assertRaisesRegex(RuntimeError, 'synthetic signing failure'):
                with self.scope():
                    raise RuntimeError('synthetic signing failure')
        self.assertEqual(commands[-2][5:], ORIGINAL)
        self.assertEqual(commands[-1][1], 'delete-keychain')
        self.assertEqual(output.getvalue(), '')

    def test_import_failure_also_restores_then_deletes(self):
        commands = []
        with patch.object(signer.subprocess, 'run', side_effect=self.native(commands, lambda args: args[1] == 'import')):
            with self.assertRaises(RuntimeError) as raised:
                with self.scope():
                    self.fail('A failed import must not start signing')
        self.assertEqual(commands[-2][5:], ORIGINAL)
        self.assertEqual(commands[-1][1], 'delete-keychain')
        self.assertNotIn('private', str(raised.exception))

    def test_restoration_failure_still_deletes_private_keychain(self):
        commands = []
        def restore_failure(args):
            return args[1:5] == ['list-keychains', '-d', 'user', '-s'] and args[5:] == ORIGINAL
        with patch.object(signer.subprocess, 'run', side_effect=self.native(commands, restore_failure)):
            with self.assertRaises(RuntimeError) as raised:
                with self.scope():
                    pass
        self.assertEqual(commands[-1][1], 'delete-keychain')
        self.assertNotIn('private', str(raised.exception))

    def test_capture_failure_never_creates_or_mutates_a_keychain(self):
        commands = []
        with patch.object(signer.subprocess, 'run', side_effect=self.native(commands, lambda args: args[1:] == ['list-keychains', '-d', 'user'])):
            with self.assertRaises(RuntimeError):
                with self.scope():
                    self.fail('Capture failure must stop before keychain creation')
        self.assertEqual(len(commands), 1)


if __name__ == '__main__':
    unittest.main()
