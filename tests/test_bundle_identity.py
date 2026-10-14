"""Run the adapter's real C identity predicate without an iOS SDK."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = 'com.ayato.bereal493'


class BundleIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('clang') or shutil.which('cc') or shutil.which('gcc')
        if compiler is None:
            raise RuntimeError('A C compiler is required to test the adapter identity predicate')
        cls.directory = tempfile.TemporaryDirectory(prefix='bereal-bundle-identity-')
        cls.addClassCleanup(cls.directory.cleanup)
        directory = Path(cls.directory.name)
        source = directory / 'predicate.c'
        source.write_text('''#include "BRBundleIdentity.h"
#include <stdio.h>
int main(int argc, char **argv) {
    const char *identifier = argc == 2 ? argv[1] : NULL;
    puts(BRBundleIdentityAllowsSandboxFallback(identifier) ? "1" : "0");
    return 0;
}
''')
        cls.executable = directory / 'predicate'
        subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-I', str(Path(__file__).resolve().parents[1]), str(source),
                        '-o', str(cls.executable)], capture_output=True, check=True)

    def allowed(self, identifier):
        arguments = [str(self.executable)]
        if identifier is not None:
            arguments.append(identifier)
        result = subprocess.run(arguments, capture_output=True, check=True, text=True)
        self.assertIn(result.stdout, ('0\n', '1\n'))
        return result.stdout == '1\n'

    def test_delivered_root_and_actual_installed_team_suffix_are_allowed(self):
        self.assertTrue(self.allowed(ROOT))
        self.assertTrue(self.allowed(ROOT + '.2CLB9J3SQB'))

    def test_suffix_requires_exactly_ten_uppercase_ascii_letters_or_digits(self):
        for suffix in ('ABCDEFGHIJ', '0123456789', 'A1B2C3D4E5'):
            with self.subTest(suffix=suffix):
                self.assertTrue(self.allowed(ROOT + '.' + suffix))
        for suffix in ('', 'A12345678', 'A1234567890', '2clb9j3sqb', 'A12345678b',
                       'A1234567-9', 'A1234567_9', 'A1234567 9', 'A1234567.9',
                       'A1234567é'):
            with self.subTest(suffix=suffix):
                self.assertFalse(self.allowed(ROOT + '.' + suffix))

    def test_extensions_with_or_without_team_suffix_are_rejected(self):
        for suffix in ('.iMessageExtension', '.RealMojiNotificationContentExtension',
                       '.NotificationServiceExtension', '.Widgets'):
            for team in ('', '.2CLB9J3SQB'):
                with self.subTest(extension=suffix, team=team):
                    self.assertFalse(self.allowed(ROOT + suffix + team))

    def test_nil_empty_foreign_roots_prefix_matches_and_multiple_suffixes_are_rejected(self):
        for identifier in (None, '', 'AlexisBarreyat.BeReal', 'com.ayato.y3posclient',
                           'com.ayato.bereal494.2CLB9J3SQB', 'COM.AYATO.BEREAL493.2CLB9J3SQB',
                           ROOT + '2CLB9J3SQB', ROOT + 'extra.2CLB9J3SQB',
                           ROOT + '..2CLB9J3SQB', ROOT + '.2CLB9J3SQB.2CLB9J3SQB',
                           ROOT + '.2CLB9J3SQB.extra', ' ' + ROOT, ROOT + '.2CLB9J3SQB '):
            with self.subTest(identifier=identifier):
                self.assertFalse(self.allowed(identifier))


if __name__ == '__main__':
    unittest.main()
