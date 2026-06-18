# Shell completions for `hort-cli`

`hort-cli` generates its own completion scripts from clap's command tree (so they
never drift from the real commands) and can complete **repository names** live from
the server you're logged into.

## Install (static — all shells)

`hort-cli completions <shell>` prints a completion script. Install it once:

- **bash:** `hort-cli completions bash | sudo tee /etc/bash_completion.d/hort-cli`
- **zsh:** `hort-cli completions zsh > "${fpath[1]}/_hort-cli"` (then restart the shell)
- **fish:** `hort-cli completions fish > ~/.config/fish/completions/hort-cli.fish`
- **powershell:** `hort-cli completions powershell | Out-String | Invoke-Expression` (add to `$PROFILE` to persist)
- **elvish:** `hort-cli completions elvish >> ~/.elvish/rc.elv`

This gives subcommand, flag, and fixed-value (enum) completion on every shell.

## Dynamic repository-name completion (bash / zsh / fish)

For live repository-name completion (e.g. `hort-cli list-versions <TAB>` → the repos you
can see), register the **dynamic** engine instead, which delegates back to the binary at
TAB-time:

- **bash:** `source <(COMPLETE=bash hort-cli)` (add to `~/.bashrc` to persist)
- **zsh:** `source <(COMPLETE=zsh hort-cli)` (add to `~/.zshrc`)
- **fish:** `COMPLETE=fish hort-cli | source` (add to `~/.config/fish/config.fish`)

Repo-name completion is offered on every repository-key argument (`list-versions`,
`prefetch`, `get repo-score --name`, the curation `--repo` flags, and
`admin quarantine ... --repo`).

### How it behaves (and fails)

- It reuses your **existing** session (the same one normal commands use). If you're not
  logged in — or your token has expired — repo completion is simply **empty**; it never
  prompts you to log in, and never refreshes your token, from a keystroke.
- It is **fail-closed and fast**: a ~300 ms timeout bounds the lookup, and any error
  (offline, server down, rate-limited, expired) yields no candidates rather than a hang
  or error. You still get full static command/flag completion in that case.
- It only ever reads (`GET /api/v1/repositories`) the repositories you're already
  authorized to see — the same RBAC filter the rest of the API uses.

> **Note (powershell / elvish):** dynamic repo-name completion is wired for
> bash / zsh / fish; powershell and elvish get the static command/flag completion above.

## Uninstall

Remove the file you installed (bash/zsh/fish), or the `source <(COMPLETE=… )` /
`Invoke-Expression` line from your shell rc.
