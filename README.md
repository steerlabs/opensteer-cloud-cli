# opensteer-cloud

Rust CLI for attaching a local coding agent to an Opensteer Cloud agent workspace.

## Install

```bash
curl -fsSL https://opensteer.com/cloud-cli/install.sh | sh
```

Then authenticate and attach a hosted agent:

```bash
opensteer-cloud login
opensteer-cloud attach <agent>
```

## Update

Re-run the installer to update to the latest release:

```bash
curl -fsSL https://opensteer.com/cloud-cli/install.sh | sh
```

To install a specific release, set `OPENSTEER_CLOUD_VERSION`, for example:

```bash
curl -fsSL https://opensteer.com/cloud-cli/install.sh | OPENSTEER_CLOUD_VERSION=0.1.0 sh
```

## Commands

```bash
opensteer-cloud --version
opensteer-cloud login
opensteer-cloud whoami
opensteer-cloud agent create "linkedin sales"
opensteer-cloud agent list
opensteer-cloud attach <agent>
opensteer-cloud profiles list
opensteer-cloud profiles create "LinkedIn"
opensteer-cloud profiles sync LinkedIn --browser chrome --domain linkedin.com

opensteer-run "python run.py"
opensteer-run exec "pytest"
opensteer-run read skills/SKILL.md
opensteer-run write actions/job.py < /tmp/job.py
opensteer-run patch < change.diff
opensteer-run ls .
opensteer-run rg "search_people" actions skills
opensteer-run --version
```

The cloud agent workspace is canonical. `opensteer-run` is the local agent's
remote toolbelt for commands and file operations; it does not use SSH, Daytona
IDs, or a local workspace mirror. Browser control runs from the remote workspace
with the sandbox Opensteer CLI, for example:

```bash
opensteer-run "opensteer open https://linkedin.com"
```

The CLI stores OAuth device-flow credentials under the platform config
directory and stores the active agent attachment in
`.opensteer-cloud/connection.json` under the local project. It targets
`https://opensteer.com` by default. Set `OPENSTEER_CLOUD_URL`, for example
`OPENSTEER_CLOUD_URL=http://localhost:3001`, to point at another deployment.

## Release

Releases are cut from version tags:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The release workflow builds `opensteer-cloud` and `opensteer-run` for macOS and
Linux, publishes versionless release archive names for the hosted installer, and
publishes SHA-256 checksums plus GitHub artifact attestations.
