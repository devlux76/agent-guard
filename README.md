# agent-guard

Preview-first `rm` for agent and interactive user shells. The system
`/usr/bin/rm` is never replaced. Issue: `bug:1a30fc8`, parent `shared:fa8bfdd`.

```sh
make
make test
```

The deletion path is a small C binary using the already-installed libcrypto.
The scope shim is POSIX shell. Tests use Python and disposable fake homes;
Python and Bun are not used when running `rm`.

## Preview and approval

```sh
rm -rf -- ./build/generated
# Prints canonical targets, entry count, regular-file bytes, and Plan hash.
# Exit 3 means preview only; nothing was deleted.

rm --confirm FULL_64_CHARACTER_HASH -rf -- ./build/generated
```

The second command requires the same flags and targets and a previously saved
preview. Agents may confirm their own inspected plans without a TTY or further
prompt. Humans type `DELETE` in their controlling terminal. It rescans again before
calling the unchanged system binary. File identity, size, permissions, mtime,
ctime, tree membership, targets, and options contribute to the hash. File
contents are not read. Size is logical regular-file bytes, not disk usage.

Preview and refusal output goes to stderr, keeping stdout clean for scripts.
Guarded runs prune saved plans older than one hour; an expired plan cannot be
confirmed. Agents may self-confirm, but cannot skip the saved preview or use a
changed plan. Piped human answers are refused. There is no `--yes` override.
`--force` does not bypass the preview or hash check. Agent confirmation replaces
GNU per-file `-i`/`-I` prompts; humans retain their requested GNU prompts.

Recursive `/`, HOME and its first two levels, cwd/ancestors, and paths outside
HOME except temporary storage are refused. Git roots are refused with the
existing temporary/worktree exceptions. Parent symlinks are resolved; the final
symlink is previewed as a link to unlink, not as its destination. Control
characters in filenames are escaped. Exit 2 means refusal/error; exit 0 is a
no-op or an executed system-rm result. Canceling returns 3.

## Scope and deployment

Deploy only after the Haiku change review and Opus final acceptance:

```sh
sh install-user.sh --deploy-reviewed
hash -r
```

This backs up the existing user guard and installs the shim/helper under
`~/.local/lib/agent-guard`, plus an `~/.local/bin/rm` symlink. It refuses an
unrelated existing user `rm`, root installs, and symlinked installation paths.
It changes no system files, services, or shell startup files. The existing
Claude SessionStart PATH hook stays intact.

The shim recognizes agent markers (`CLAUDECODE`, `CODEX_THREAD_ID`, `OPENCODE`,
`AGENT_GUARD_ACTIVE`), agent ancestry, and a controlling user terminal. Codex
and the running OpenCode services already have `~/.local/bin` on PATH. Fresh
shells find the shim there. Native parent-argv inspection keeps command-line
pipelines (`xargs`, `find -exec`, nested shell `-c` strings) gated while rm
inside executed shell/interpreter script files, Python modules, and build/test
runners uses plain rm. Compact eval flags and process-substitution input stay
gated. Agent detection uses process names, argv[0] basenames, and Claude's
versioned executable directory, so a version-number process name does not let
the classifier walk past the agent into its launcher script. The shim queries
that same native detector when markers/process names do not identify the host.
Unknown or vanished ancestry stays gated. Existing shells can have a cached system-rm path;
run `hash -r` or open a fresh terminal/session.

Unscoped noninteractive callers retain ordinary GNU rm. Package-manager,
initramfs and cron descendants retain it even if an agent environment leaked
through. Systemd jobs normally have no agent markers/ancestry or terminal and
retain ordinary behavior. The scope does not exempt all systemd descendants,
because normal terminals and agents are also systemd descendants.

## Limits

This prevents accidental deletion through the scoped default command. It is
not an OS sandbox or a defense against a malicious same-user process.
Absolute `/usr/bin/rm`, other deletion APIs, altered PATH, unrecognized agent
hosts and cached command paths can bypass a PATH shim. Do not bypass it from
an agent. An agent must inspect the resolved plan before issuing confirmation;
the hash proves consistency, not human authorization. Sourced code shares its
caller's shell invocation, and erased/unknown process ancestry may conservatively
stay gated. Script-internal calls intentionally use plain rm, so this does not
protect against a destructive script's own logic. Files can still change in the small interval
between the final check and system rm; no claim of adversarial race immunity.
