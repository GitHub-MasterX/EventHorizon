# Researcher John Task-Based Cognitive Walkthrough

This document evaluates whether a technically capable newcomer can complete the
supported EventHorizon deployment workflow using only repository documentation.
It is a task-based cognitive walkthrough, not a usability study.

## Claim boundary

Keep the roles separate:

- **Evaluator:** runs the method, records observations, and proposes revisions.
- **Researcher John persona:** understands Git, SSH, Linux, and Docker, but has
  no undocumented EventHorizon knowledge.
- **System under test:** repository documentation, public deployment command,
  trusted CI proof, authorized VPS, and generated evidence.

Allowed claim:

> A task-based cognitive walkthrough found that the supported workflow could be
> completed without undocumented assistance.

Do not claim that users found the workflow easy or intuitive. A repeated
self-evaluation is workflow regression evidence, not an independent usability
study. Any command, explanation, remembered project fact, or hidden value not
discoverable from `README.md`, `DEPLOYMENT.md`, `VALIDATION.md`, or public
`--help` is recorded as assistance. A run with such assistance cannot support
the allowed claim.

## Evidence and privacy rules

Create a separate timestamped observation log for each walkthrough under the
ignored directory:

```text
validation-output/walkthroughs/<walkthrough-id>/observation.md
```

The walkthrough base, each run directory, and each observation file contain
private evaluation evidence. Create or normalize them before starting:

```bash
WALKTHROUGH_BASE="$PWD/validation-output/walkthroughs"
install -d -m 0700 "$WALKTHROUGH_BASE"
install -d -m 0700 "$WALKTHROUGH_BASE/<walkthrough-id>"
chmod 0600 "$WALKTHROUGH_BASE/<walkthrough-id>/observation.md"
```

The controller rejects an evidence base or ancestor that is group- or
world-writable. The `<walkthrough-id>` recorded inside `observation.md` is the
same identifier every later command for that walkthrough must reuse; do not
generate a second ID after the observation clock starts.

Never record a hostname, IP address, CIDR, username, key path, credential,
target-file value, raw traffic, or payload. Use only `operator-workstation` and
the configured non-sensitive target alias, normally `field-host`.

Record commands as entered, but replace sensitive arguments with placeholders
before copying them into the log. Generated deployment evidence remains in its
own immutable run directory; the walkthrough log references its run ID and
path without copying unrestricted output.

## Success walkthrough

Run the success walkthrough separately from the blocker walkthrough. The
primary success walkthrough starts with an authorized VPS in the documented
initial-deployment state. A later managed-redeployment walkthrough is useful
workflow regression evidence, but label it accurately and do not silently
substitute it for the primary initial-deployment walkthrough.

### Preparing a previously used dedicated VPS

A different deployment directory or Compose project name does not create an
initial-deployment state while stopped containers or an old Compose project
remain anywhere on the VPS. Prefer a genuinely unused authorized VPS for the
primary walkthrough.

If only the same **dedicated validation VPS** is available, reset it before the
walkthrough only after the previous deployment is stopped and its verified
evidence bundle has been retrieved. From the previous evidenced checkout, run
the same three-file Compose selection with its previous project name:

```bash
docker compose \
  -p <PREVIOUS_VPS_PROJECT_NAME> \
  -f docker-compose.yml \
  -f docker-compose.cost.yml \
  -f docker-compose.field.yml \
  down
```

Do not add `--volumes` or `--rmi`. This removes the stopped containers and
Compose network while preserving named volumes, images, the checkout, and
deployment evidence. Do not use this reset on a shared or production host.
Confirm that the dedicated VPS has no remaining containers or Compose projects:

```bash
docker ps -a
docker compose ls --all
```

Both commands must report no entries. Then use an absent or empty deployment
directory and a non-conflicting project name for the primary initial-deployment
walkthrough. This reset is evaluator preparation; it is not rollback and does
not establish any validation state.

### Starting state

- supported Linux operator workstation;
- repository access and authenticated read-only `gh`;
- Git, SSH, Bash-compatible tooling, and Python 3.10+;
- authorized Linux `x86_64` VPS with Docker Compose and no conflicting workload;
- no existing Docker containers or Compose projects, including stopped ones;
- ignored target configuration with mode `0600`;
- exact trusted-upstream SHA whose push workflow can establish `CI_VALIDATED`;
- only `README.md` and links discoverable from it as starting guidance;
- no remembered commands, private notes, or undocumented cleanup.

### Success observation-log template

Copy this section into a new `observation.md` before starting:

```markdown
# Researcher John Success Walkthrough

- Walkthrough ID: success-<UTC>-<short-id>
- Evaluator: <name or stable non-sensitive identifier>
- Persona: Researcher John
- System-under-test commit: <full SHA>
- Target alias: field-host
- VPS starting state: INITIAL_DEPLOYMENT
- Start UTC: <YYYY-MM-DDTHH:MM:SSZ>
- End UTC: <pending>
- Result: IN_PROGRESS
- Deployment run ID: <pending>
- Assistance given: none

| Task | Start/end UTC | Command or action | Documentation consulted | Outcome | Assistance or finding |
| ---: | --- | --- | --- | --- | --- |
| 1 | | Identify supported and explicitly untested topology | | | |
| 2 | | Identify prerequisites, authorization, exposure, and firewall boundary | | | |
| 3 | | Select one full trusted-upstream deployment SHA | | | |
| 4 | | Run side-effect-free public `--help` | | | |
| 5 | | Run `--check-only` and interpret state versus outcome | | | |
| 6 | | Create and validate the strict ignored target file | | | |
| 7 | | Explain the authorization phrase and public-observation boundary | | | |
| 8 | | Run the single supported deployment command | | | |
| 9 | | Interpret all nine phases and any warning or skipped phase | | | |
| 10 | | Confirm `ENVIRONMENT_VALIDATED` | | | |
| 11 | | Locate result, CI proof, smoke evidence, and both indexes | | | |
| 12 | | Confirm mutation and running-service state | | | |
| 13 | | Confirm that public observation was not authorized | | | |
| 14 | | Locate documented stop and rollback procedures | | | |

## Completion measurements

- Total completion time: <duration>
- Failed command count: <integer>
- Documentation lookups: <integer>
- Unfamiliar terms: <list or none>
- Missing prerequisites: <list or none>
- Interpretation errors: <list or none>
- Undocumented assistance: <list or none>
- Unsafe assumptions considered: <list or none>
- Evidence located: <run ID and allowlisted filenames>
- Revisions proposed: <list or none>
- Revisions made during run: none
- Final result: PASS | FAIL
- Supported claim allowed: yes | no
```

Do not revise documentation during the run. Record a finding, finish or stop the
walkthrough honestly, then revise and rerun as a new workflow-regression
walkthrough.

### Success acceptance

The walkthrough passes only when:

- all 14 tasks complete without undocumented assistance;
- `--check-only` reports `PASS / CI_VALIDATED` with no remote mutation;
- deployment reports `PASS / ENVIRONMENT_VALIDATED`;
- the operator correctly identifies the result, next action, mutation, running
  services, and evidence directory;
- management ports are not observed reachable from the workstation;
- no sensitive target values enter retained evidence or the observation log;
- no public-observation workflow begins;
- stop and rollback guidance is found without guessing.

## Injected-blocker walkthrough

Run this as a separate walkthrough after the success evaluation. Inject only a
safe, deterministic, pre-mutation controller mismatch. Do not weaken a firewall,
use a real secret failure, dirty the authorized VPS, or create uncontrolled
remote activity.

The recommended injection uses a disposable detached Git worktree, so the main
working tree stays clean. Start from the repository root and run the entire
block as one command. Replace both placeholders; do not reuse shell variables
from an earlier walkthrough:

```bash
(
  set -euo pipefail

  REPOSITORY_ROOT="$(git rev-parse --show-toplevel)"
  DEPLOY_COMMIT="<full-40-character-sha>"
  WALKTHROUGH_BASE="$REPOSITORY_ROOT/validation-output/walkthroughs"
  BLOCKER_ID="<existing-observation-log-walkthrough-id>"
  BLOCKER_DIR="/tmp/eventhorizon-$BLOCKER_ID"
  BLOCKER_OUTPUT="$WALKTHROUGH_BASE/$BLOCKER_ID"
  WORKTREE_ADDED=false

  cleanup() {
    if [[ "$WORKTREE_ADDED" == true ]]; then
      git -C "$REPOSITORY_ROOT" worktree remove --force "$BLOCKER_DIR"
      WORKTREE_ADDED=false
    fi
  }
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  [[ "$DEPLOY_COMMIT" =~ ^[0-9a-f]{40}$ ]]
  [[ "$BLOCKER_ID" =~ ^blocker-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$ ]]
  [[ ! -e "$BLOCKER_DIR" && ! -L "$BLOCKER_DIR" ]]
  test -f "$BLOCKER_OUTPUT/observation.md"
  grep -Fqx -- "- Walkthrough ID: $BLOCKER_ID" \
    "$BLOCKER_OUTPUT/observation.md"
  grep -Fqx -- "- System-under-test commit: $DEPLOY_COMMIT" \
    "$BLOCKER_OUTPUT/observation.md"
  chmod 0700 "$WALKTHROUGH_BASE" "$BLOCKER_OUTPUT"
  chmod 0600 "$BLOCKER_OUTPUT/observation.md"

  git -C "$REPOSITORY_ROOT" worktree add --detach \
    "$BLOCKER_DIR" "$DEPLOY_COMMIT"
  WORKTREE_ADDED=true
  printf '\n# WALKTHROUGH_ONLY_PROTECTED_PATH_MISMATCH\n' \
    >> "$BLOCKER_DIR/docker-compose.field.yml"

  set +e
  cd "$BLOCKER_DIR"
  ./scripts/vps_field_deploy.sh \
    --check-only \
    --commit "$DEPLOY_COMMIT" \
    --output-dir "$BLOCKER_OUTPUT"
  CONTROLLER_STATUS=$?
  set -e

  if [[ "$CONTROLLER_STATUS" -ne 2 ]]; then
    printf 'Expected blocker exit 2; received %s.\n' \
      "$CONTROLLER_STATUS" >&2
  fi
  exit "$CONTROLLER_STATUS"
)
```

The subshell stops immediately if the ID, commit, observation log, permissions,
or disposable path is inconsistent. Its exit trap removes only a worktree that
this invocation successfully created, including after the expected exit `2`.
The ignored observation directory and generated evidence remain intact.

This invocation must stop during local candidate/controller verification. It
must not load `deploy/vps-field.env`, request authorization, initiate SSH to the
authorized VPS, or mutate the VPS. Refreshing the trusted upstream Git ref may
still use the repository's configured HTTPS or SSH transport. Expected result:

```text
Outcome: BLOCKED
Remote mutation occurred: no
Field services remain running: no
```

The highest proven state may be `NONE` because the protected-path compatibility
gate is part of proving `DEPLOYMENT_CANDIDATE`.

After recording and preserving the generated blocker evidence, confirm that
the exit trap removed the disposable worktree and that the main tree is clean:

```bash
git worktree list
git status --short
```

The output must not list the blocker worktree. The main worktree must remain
clean. Do not manually remove an arbitrary path based on a leftover shell
variable.

### Blocker observation-log template

```markdown
# Researcher John Injected-Blocker Walkthrough

- Walkthrough ID: blocker-<UTC>-<short-id>
- Evaluator: <name or stable non-sensitive identifier>
- Persona: Researcher John
- System-under-test commit: <full SHA>
- Target alias: field-host
- Injection: disposable-worktree protected-path mismatch
- Start UTC: <YYYY-MM-DDTHH:MM:SSZ>
- End UTC: <pending>
- Result: IN_PROGRESS
- Blocked run ID: <pending>
- Assistance given: none

| Task | Start/end UTC | Command or action | Documentation consulted | Outcome | Assistance or finding |
| ---: | --- | --- | --- | --- | --- |
| 1 | | Create the documented safe pre-mutation injection | | | |
| 2 | | Run the same public `--check-only` entry point | | | |
| 3 | | Distinguish `BLOCKED` from `FAIL` and `ERROR` | | | |
| 4 | | Identify observed condition, required condition, and next action | | | |
| 5 | | Confirm no target values were loaded or exposed | | | |
| 6 | | Confirm no authorized-VPS SSH or remote mutation occurred | | | |
| 7 | | Locate and preserve partial result and index evidence | | | |
| 8 | | Remove the disposable injection and confirm the main tree is clean | | | |

## Completion measurements

- Total completion time: <duration>
- Failed command count: <integer>
- Documentation lookups: <integer>
- Interpretation errors: <list or none>
- Undocumented assistance: <list or none>
- Sensitive values observed: none | <stop and report>
- Remote contact observed: no | <stop and report>
- Remote mutation observed: no | <stop and report>
- Evidence located: <run ID and allowlisted filenames>
- Revisions proposed: <list or none>
- Final result: PASS | FAIL
- Supported blocker claim allowed: yes | no
```

### Blocker acceptance

- overall outcome is `BLOCKED` with exit code `2`;
- individual deployment-candidate check is a `BLOCKER`;
- no target configuration, authorization, authorized-VPS SSH, or remote
  mutation occurs;
- evidence provides a safe next action without exposing the changed file's
  contents or any target value;
- the disposable condition is removed and the main working tree stays clean.

## Reporting

Report the success and blocker runs separately. A concise Week 10 report should
identify the exact system-under-test commit, walkthrough type, starting state,
completion result, assistance count, failed-command count, documentation
findings, deployment or blocker run ID, and revisions made afterward. Publish
only an explicitly reviewed redacted summary; keep raw local run evidence
ignored and private.
