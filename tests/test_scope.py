import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='agent-guard-scope-')
        self.home = Path(self.tmp.name) / 'home'
        self.cwd = self.home / 'projects/demo/deep'
        self.cwd.mkdir(parents=True)
        self.prefix = self.home / '.local/lib/agent-guard'
        (self.prefix / 'bin').mkdir(parents=True)
        (self.prefix / 'libexec').mkdir()
        shutil.copy2(ROOT / 'bin/rm', self.prefix / 'bin/rm')
        (self.prefix / 'bin/rm').chmod(0o755)
        shutil.copy2(ROOT / 'build/guard-rm', self.prefix / 'libexec/guard-rm')
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ('AGENT_GUARD_ACTIVE', 'CLAUDECODE', 'CODEX_THREAD_ID', 'OPENCODE')}
        self.env['HOME'] = str(self.home)
        self.file = self.cwd / 'sentinel'
        self.file.write_text('keep')

    def tearDown(self):
        self.tmp.cleanup()

    def call(self, *args, prefix=()):
        return subprocess.run([*prefix, str(self.prefix / 'bin/rm'), *map(str, args)],
                              cwd=self.cwd, env=self.env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True)

    def isolated(self):
        return ('bwrap', '--unshare-pid', '--ro-bind', '/', '/', '--bind',
                str(self.home), str(self.home), '--proc', '/proc', '--dev', '/dev', '--')

    def test_all_agent_markers_get_preview(self):
        for marker in ('AGENT_GUARD_ACTIVE', 'CLAUDECODE', 'CODEX_THREAD_ID', 'OPENCODE'):
            with self.subTest(marker=marker):
                self.env[marker] = '1'
                r = self.call('-f', self.file, prefix=self.isolated())
                self.assertEqual(r.returncode, 3, r.stderr)
                self.assertTrue(self.file.exists())
                del self.env[marker]

    def test_system_package_callers_keep_plain_rm_even_with_agent_marker(self):
        for name in ('apt-get', 'dpkg', 'mkinitramfs', 'cron'):
            with self.subTest(name=name):
                self.file.write_text('fixture')
                driver = Path(self.tmp.name) / name
                driver.write_text('#!/bin/sh\n"$@"\nresult=$?\nexit "$result"\n')
                driver.chmod(0o755)
                self.env['AGENT_GUARD_ACTIVE'] = '1'
                r = self.call('-f', self.file, prefix=(str(driver),))
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertFalse(self.file.exists())

    def test_user_local_bin_symlink_still_resolves_private_helper(self):
        self.env['AGENT_GUARD_ACTIVE'] = '1'
        localbin = self.home / '.local/bin'
        localbin.mkdir(parents=True)
        link = localbin / 'rm'
        link.symlink_to(self.prefix / 'bin/rm')
        r = subprocess.run([*self.isolated(), str(link), '-f', str(self.file)], cwd=self.cwd,
                           env=self.env, stdin=subprocess.DEVNULL, capture_output=True, text=True)
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertTrue(self.file.exists())

    @unittest.skipUnless(shutil.which('bwrap'), 'PID isolation needs existing bwrap')
    def test_unscoped_noninteractive_system_process_gets_plain_rm(self):
        r = self.call('-f', self.file, prefix=self.isolated())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.file.exists())

    def test_opencode_ancestry_sets_agent_scope_without_an_env_marker(self):
        driver = Path(self.tmp.name) / 'opencode'
        driver.write_text('#!/bin/sh\n"$@"\nresult=$?\nexit "$result"\n')
        driver.chmod(0o755)
        r = self.call('-f', self.file, prefix=(*self.isolated(), str(driver)))
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertTrue(self.file.exists())

    def test_user_terminal_pipeline_is_scoped_despite_non_tty_stdin(self):
        import fcntl
        import pty
        import termios
        master, slave = pty.openpty()
        def terminal():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        try:
            r = subprocess.run([*self.isolated(), 'sh', '-c',
                                'printf ignored | "$1" -f "$2"', 'fixture',
                                str(self.prefix / 'bin/rm'), str(self.file)],
                               cwd=self.cwd, env=self.env, stdin=slave,
                               capture_output=True, text=True, timeout=5, preexec_fn=terminal)
            self.assertEqual(r.returncode, 3, r.stderr)
            self.assertTrue(self.file.exists())
        finally:
            os.close(master)
            os.close(slave)

    def command(self, args):
        self.env['AGENT_GUARD_ACTIVE'] = '1'
        self.env['PATH'] = f'{self.prefix}/bin:{self.env["PATH"]}'
        return subprocess.run([*self.isolated(), *map(str, args)], cwd=self.cwd,
                              env=self.env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=5)

    def test_agent_xargs_pipeline_is_still_gated(self):
        r = self.command(['sh', '-c', 'printf "%s\\0" "$1" | xargs -0 rm -f --',
                          'fixture', self.file])
        self.assertTrue(self.file.exists())
        self.assertIn('Plan hash:', r.stderr)

    def test_agent_find_exec_pipeline_is_still_gated(self):
        r = self.command(['find', self.file, '-maxdepth', '0', '-exec', 'rm', '-f', '--', '{}', ';'])
        self.assertTrue(self.file.exists())
        self.assertIn('Plan hash:', r.stderr)

    def test_shell_eval_in_agent_command_line_stays_gated(self):
        r = self.command(['sh', '-c', 'rm -f -- "$1"', 'fixture', self.file])
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertTrue(self.file.exists())

    def test_python_eval_in_agent_command_line_stays_gated(self):
        r = self.command(['/usr/bin/python3', '-c',
                          'import subprocess,sys;subprocess.run(["rm","-f","--",sys.argv[1]])', self.file])
        self.assertTrue(self.file.exists())
        self.assertIn('Plan hash:', r.stderr)

    def test_bun_eval_in_agent_command_line_stays_gated(self):
        r = self.command([shutil.which('bun'), '--eval',
                          'await Bun.spawn(["rm","-f","--",process.argv[1]]).exited;', self.file])
        self.assertTrue(self.file.exists())
        self.assertIn('Plan hash:', r.stderr)

    def test_executed_shell_script_cleanup_passes_through(self):
        script = self.cwd / 'cleanup'
        script.write_text('#!/bin/sh\nrm -f -- "$1"\nresult=$?\nexit "$result"\n')
        script.chmod(0o755)
        r = self.command([script, self.file])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.file.exists())

    def test_make_clean_internal_rm_passes_through(self):
        makefile = self.cwd / 'Makefile'
        makefile.write_text('clean:\n\trm -f -- sentinel\n')
        r = self.command(['make', 'clean'])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.file.exists())

    def test_single_command_script_cleanup_passes_through(self):
        script = self.cwd / 'cleanup.sh'
        script.write_text('#!/bin/sh\nrm -f -- "$1"\n')
        script.chmod(0o755)
        r = self.command([script, self.file])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.file.exists())

    def test_python_script_teardown_passes_through(self):
        script = self.cwd / 'teardown.py'
        script.write_text('import subprocess,sys\nsubprocess.run(["rm","-f","--",sys.argv[1]], check=True)\n')
        r = self.command(['/usr/bin/python3', script, self.file])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.file.exists())

    def test_bun_script_cleanup_passes_through(self):
        script = self.cwd / 'cleanup.js'
        script.write_text('const p=Bun.spawn(["rm","-f","--",process.argv[2]]);process.exit(await p.exited);\n')
        r = self.command([shutil.which('bun'), script, self.file])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(self.file.exists())


if __name__ == '__main__':
    unittest.main()
