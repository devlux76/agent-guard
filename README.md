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
preview. It rescans the physical tree, checks the hash, and requires typing
`DELETE` in a controlling terminal. It rescans again after confirmation before
calling the unchanged system binary. File identity, size, permissions, mtime,
ctime, tree membership, targets, and options contribute to the hash. File
contents are not read. Size is logical regular-file bytes, not disk usage.

An agent cannot authorize its own plan: agent-marked confirmation is refused.
Piped answers and unattended confirmation are refused. Ask the operator to run
the confirmation command in their own terminal. There is no `--yes` override.
`--force` does not bypass the preview or approval requirement.

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
shells find the shim there. Existing shells can have a cached system-rm path;
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
an agent or automatically turn a preview into confirmation. Read/inspection
does not establish human approval. Native frontend policy is needed to enforce
that rule against arbitrary tools. Files can still change in the small interval
between the final check and system rm; no claim of adversarial race immunity.
