# opensteer-cloud

Rust CLI for attaching a local coding agent to an OpenSteer Cloud sandbox.

## Commands

```bash
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
```

The sandbox workspace is canonical. `opensteer-run` is the local agent's
remote toolbelt for sandbox commands and file operations; it does not use SSH
or a local workspace mirror.

The CLI stores OAuth device-flow credentials under the platform config
directory and targets `http://localhost:3001` by default. Set
`OPENSTEER_CLOUD_URL` to point at another deployment.
