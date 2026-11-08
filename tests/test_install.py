import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='agent-guard-install-')
        self.home = Path(self.tmp.name) / 'home'
        self.home.mkdir()
        self.env = {**os.environ, 'HOME': str(self.home)}
        self.prefix = self.home / '.local/lib/agent-guard'

    def tearDown(self):
        self.tmp.cleanup()

    def install(self, *args):
        return subprocess.run(['sh', str(ROOT / 'install-user.sh'), *args],
                              cwd=ROOT, env=self.env, text=True, capture_output=True)

    def test_explicit_deployment_gate(self):
        self.assertNotEqual(self.install().returncode, 0)
        self.assertFalse(self.prefix.exists())

    def test_installs_only_user_private_paths(self):
        before = hashlib.sha256(Path('/usr/bin/rm').read_bytes()).hexdigest()
        r = self.install('--deploy-reviewed')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.prefix / 'libexec/guard-rm').read_bytes(),
                         (ROOT / 'build/guard-rm').read_bytes())
        self.assertEqual((self.prefix / 'bin/rm').read_bytes(), (ROOT / 'bin/rm').read_bytes())
        link = self.home / '.local/bin/rm'
        self.assertTrue(link.is_symlink())
        self.assertEqual(link.resolve(), self.prefix / 'bin/rm')
        self.assertEqual(before, hashlib.sha256(Path('/usr/bin/rm').read_bytes()).hexdigest())

    def test_preserves_current_guard_before_upgrade(self):
        old = self.prefix / 'bin/rm'
        old.parent.mkdir(parents=True)
        old.write_text('old guard sentinel\n')
        self.assertEqual(self.install('--deploy-reviewed').returncode, 0)
        backups = list((self.home / '.local/state/agent-guard/backups').glob('*/rm.before'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), 'old guard sentinel\n')

    def test_does_not_overwrite_unrelated_user_rm(self):
        user_rm = self.home / '.local/bin/rm'
        user_rm.parent.mkdir(parents=True)
        user_rm.write_text('user custom rm\n')
        self.assertNotEqual(self.install('--deploy-reviewed').returncode, 0)
        self.assertEqual(user_rm.read_text(), 'user custom rm\n')
        self.assertFalse((self.prefix / 'bin/rm').exists())

    def test_refuses_symlinked_install_ancestors(self):
        outside = Path(self.tmp.name) / 'outside'
        outside.mkdir()
        (self.home / '.local').symlink_to(outside, target_is_directory=True)
        self.assertNotEqual(self.install('--deploy-reviewed').returncode, 0)
        self.assertEqual(list(outside.iterdir()), [])

    def test_repeat_install_keeps_own_user_link(self):
        self.assertEqual(self.install('--deploy-reviewed').returncode, 0)
        self.assertEqual(self.install('--deploy-reviewed').returncode, 0)
        self.assertEqual((self.home / '.local/bin/rm').resolve(), self.prefix / 'bin/rm')


if __name__ == '__main__':
    unittest.main()
