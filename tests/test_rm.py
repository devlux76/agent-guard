import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import subprocess
import tempfile
import termios
import time
import unittest

BIN = Path(__file__).resolve().parents[1] / 'build/guard-rm'


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='agent-guard-test-')
        self.home = Path(self.tmp.name) / 'home'
        self.cwd = self.home / 'projects/demo/deep'
        self.cwd.mkdir(parents=True)
        self.target = self.cwd / 'Application Support/test channel'
        self.target.mkdir(parents=True)
        (self.target / 'keep.txt').write_text('sentinel')
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ('AGENT_GUARD_ACTIVE', 'CLAUDECODE', 'CODEX_THREAD_ID', 'OPENCODE')}
        self.env.update(HOME=str(self.home), XDG_STATE_HOME=str(self.home / '.local/state'))

    def tearDown(self):
        self.tmp.cleanup()

    def run_rm(self, *args, input=''):
        return subprocess.run([str(BIN), *map(str, args)], cwd=self.cwd,
                              env=self.env, input=input, text=True, capture_output=True)

    def plan(self, *args):
        r = self.run_rm(*args)
        self.assertEqual(r.returncode, 3, r.stderr)
        m = re.search(r'Plan hash: ([0-9a-f]{64})', r.stdout)
        self.assertIsNotNone(m, r.stdout)
        return m.group(1)

    def human(self, digest, answer='DELETE', after_prompt=None, env=None):
        master, slave = pty.openpty()
        def controlling_terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        proc = subprocess.Popen([str(BIN), '--confirm', digest, '-rf', str(self.target)],
                                cwd=self.cwd, env=env or self.env, stdin=slave,
                                stdout=slave, stderr=slave, preexec_fn=controlling_terminal)
        os.close(slave)
        output = b''
        try:
            deadline = time.monotonic() + 5
            while b'Type DELETE' not in output and time.monotonic() < deadline:
                if select.select([master], [], [], .1)[0]:
                    try:
                        output += os.read(master, 65536)
                    except OSError:
                        break
            self.assertIn(b'Type DELETE', output)
            if after_prompt:
                after_prompt()
            os.write(master, answer.encode() + b'\n')
            return proc.wait(timeout=5)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            os.close(master)

    def test_default_is_preview_even_with_force(self):
        self.plan('-rf', self.target)
        self.assertTrue((self.target / 'keep.txt').exists())

    def test_piped_yes_cannot_confirm(self):
        digest = self.plan('-rf', self.target)
        r = self.run_rm('--confirm', digest, '-rf', self.target, input='DELETE\nyes\n')
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue(self.target.exists())

    def test_human_confirmation_deletes_only_exact_spaced_target(self):
        digest = self.plan('-rf', self.target)
        self.assertEqual(self.human(digest), 0)
        self.assertFalse(self.target.exists())
        self.assertTrue(self.target.parent.exists())
        self.assertNotEqual(self.run_rm('--confirm', digest, '-rf', self.target).returncode, 0)

    def test_cancel_preserves_data(self):
        self.assertNotEqual(self.human(self.plan('-rf', self.target), 'no'), 0)
        self.assertTrue(self.target.exists())

    def test_changed_tree_invalidates_plan(self):
        digest = self.plan('-rf', self.target)
        (self.target / 'new.txt').write_text('new')
        self.assertEqual(self.run_rm('--confirm', digest, '-rf', self.target).returncode, 2)
        self.assertTrue(self.target.exists())

    def test_changed_file_metadata_invalidates_plan(self):
        digest = self.plan('-rf', self.target)
        (self.target / 'keep.txt').write_text('changed content length')
        self.assertEqual(self.run_rm('--confirm', digest, '-rf', self.target).returncode, 2)

    def test_changed_arguments_and_flags_invalidate_plan(self):
        digest = self.plan('-rf', self.target)
        self.assertEqual(self.run_rm('--confirm', digest, '-r', self.target).returncode, 2)
        self.assertEqual(self.run_rm('--confirm', digest, '-rf', self.target.parent).returncode, 2)

    def test_change_while_waiting_for_human_is_detected(self):
        digest = self.plan('-rf', self.target)
        self.assertEqual(self.human(digest, after_prompt=lambda:
                                   (self.target / 'late.txt').write_text('late')), 2)
        self.assertTrue(self.target.exists())

    def test_never_confirm_a_plan_that_was_not_previewed(self):
        self.assertEqual(self.run_rm('--confirm', '0' * 64, '-rf', self.target).returncode, 2)

    def test_protected_roots_and_shallow_home(self):
        for p in ['/', self.home, self.home / 'projects', self.home / 'projects/demo', self.cwd]:
            with self.subTest(p=p):
                self.assertEqual(self.run_rm('-rf', p).returncode, 2)

    def test_xargs_split_historical_parent_is_refused(self):
        intended = self.home / 'Library/Application Support/AgentThreads/channels/test/channel.json'
        intended.parent.mkdir(parents=True)
        intended.write_text('sentinel')
        wrong = subprocess.check_output(['sh', '-c', 'printf "%s\\n" "$1" | xargs -n1 dirname',
                                         'fixture', str(intended)], text=True).splitlines()[0]
        self.assertEqual(wrong, str(self.home / 'Library'))
        self.assertEqual(self.run_rm('-rf', wrong).returncode, 2)
        self.assertTrue(intended.exists())

    def test_git_root_refusal(self):
        (self.target / '.git').mkdir()
        self.assertEqual(self.run_rm('-rf', self.target).returncode, 2)

    def test_ancestor_symlink_is_resolved_before_depth_check(self):
        link = self.cwd / 'home-alias'
        link.symlink_to(self.home, target_is_directory=True)
        self.assertEqual(self.run_rm('-rf', link / 'projects').returncode, 2)

    def test_final_symlink_is_not_followed(self):
        link = self.cwd / 'home link'
        link.symlink_to(self.home)
        self.plan('-rf', link)
        self.assertTrue(link.is_symlink())

    def test_leading_dash_and_newline_names(self):
        for name in ['-rf', 'new\nline']:
            p = self.cwd / name
            p.write_text('keep')
            r = self.run_rm('--', name)
            self.assertEqual(r.returncode, 3, r.stderr)
            self.assertIn(json.dumps(str(p)), r.stdout)
            self.assertTrue(p.exists())

    def test_unknown_options_and_root_override_fail(self):
        for flag in ['--no-preserve-root', '--allow-everything']:
            self.assertEqual(self.run_rm(flag, '-rf', self.target).returncode, 2)

    def test_missing_force_target_is_noop(self):
        self.assertEqual(self.run_rm('-f', self.cwd / 'absent').returncode, 0)

    def test_agent_cannot_treat_its_own_hash_as_human_approval(self):
        digest = self.plan('-rf', self.target)
        self.env['AGENT_GUARD_ACTIVE'] = '1'
        self.assertEqual(self.run_rm('--confirm', digest, '-rf', self.target).returncode, 2)
        self.assertTrue(self.target.exists())


if __name__ == '__main__':
    unittest.main()
