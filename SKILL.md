---
name: opensteer-cloud
description: Use when the user wants to attach a local coding agent to an Opensteer Cloud sandbox and operate the sandbox through `opensteer-run` commands and file primitives. Do not use for in-sandbox browser automation; that is the `opensteer` skill.
---

# Opensteer Cloud CLI

Drive an Opensteer Cloud sandbox from a local coding agent. The sandbox is the
source of truth for files, credentials, browser state, packages, scheduled jobs,
SQLite databases, logs, and artifacts.

## Mental Model

- `opensteer-cloud` is the control-plane CLI.
- `opensteer-cloud attach <agent>` selects and wakes the active sandbox.
- `opensteer-run` is the sandbox toolbelt. Use it for every sandbox file read,
  file write, search, patch, and command execution.
- Do not use local filesystem tools for sandbox project state. The local machine
  is only the control surface.

## Default Loop

```bash
opensteer-cloud whoami
opensteer-cloud agent list
opensteer-cloud skills install
opensteer-cloud attach <name-or-id>
opensteer-run ls .
opensteer-run read skills/SKILL.md
opensteer-run "python actions/job.py"
```

## Agent Primitives

```bash
opensteer-run "pytest"                         # execute a command
opensteer-run exec "python run.py"             # explicit execute form
opensteer-run read <path>                      # print remote file bytes
opensteer-run write <path> < local-file        # overwrite remote file
opensteer-run append <path> < input            # append to remote file
opensteer-run patch < change.diff              # apply unified diff in sandbox
opensteer-run ls [path]                        # list remote files
opensteer-run stat <path>                      # JSON stat
opensteer-run mkdir <path>                     # create remote directories
opensteer-run rm [--recursive] <path>          # delete remote path
opensteer-run rg <pattern> [path...]           # ripgrep inside sandbox
```

Commands run from the sandbox workspace root. Use `opensteer-run "cd subdir &&
..."` when a command should execute elsewhere.

## Browser Profiles

Browser profile administration belongs to `opensteer-cloud`, not the in-sandbox
`opensteer` browser runtime.

```bash
opensteer-cloud profiles list
opensteer-cloud profiles create "Work"
opensteer-cloud profiles local
opensteer-cloud profiles sync Work --browser chrome --profile-directory "Profile 2" --domain example.com
opensteer-cloud profiles inspect Work
```

Do not sync cookies without the user's explicit choice of local browser profile
and cloud profile.

## Hard Rules

1. `agent rm` is destructive. Confirm with the user before running it.
2. `agent create` provisions paid resources. Confirm with the user first.
3. Do not use SSH, local mirrors, or manual cloud API calls.
4. For browser automation, run the sandbox-installed `opensteer` CLI through
   `opensteer-run`, for example:

```bash
opensteer-run "opensteer -c 'print(page_info())'"
```
