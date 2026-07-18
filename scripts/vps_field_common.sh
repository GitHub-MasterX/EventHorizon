#!/usr/bin/env bash

vps_field_die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

vps_field_repo_root() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$script_dir/.." && pwd
}

vps_field_load_env() {
    VPS_FIELD_REPO_ROOT="$(vps_field_repo_root)"
    VPS_FIELD_ENV_FILE="${VPS_FIELD_ENV_FILE:-$VPS_FIELD_REPO_ROOT/deploy/vps-field.env}"

    [[ -f "$VPS_FIELD_ENV_FILE" ]] || vps_field_die \
        "missing $VPS_FIELD_ENV_FILE; copy deploy/vps-field.env.example and provide authorized VPS values"

    if ! git -C "$VPS_FIELD_REPO_ROOT" check-ignore -q "$VPS_FIELD_ENV_FILE"; then
        vps_field_die "$VPS_FIELD_ENV_FILE is not ignored by Git"
    fi

    # This operator-owned file contains connection parameters, not credentials.
    # Shell syntax allows quoted paths such as VPS_DEPLOY_DIR='~/eventhorizon-field'.
    set -a
    # shellcheck disable=SC1090
    source "$VPS_FIELD_ENV_FILE"
    set +a

    local required variable
    required=(
        VPS_HOST VPS_USER VPS_SSH_PORT VPS_SSH_KEY VPS_DEPLOY_DIR
        VPS_PROJECT_NAME REPOSITORY_URL DEPLOY_BRANCH DEPLOY_COMMIT
        ADMIN_SOURCE_CIDR FIELD_DURATION_HOURS SNAPSHOT_INTERVAL_HOURS
        FIELD_TARPIT_CPU_LIMIT
    )
    for variable in "${required[@]}"; do
        [[ -n "${!variable:-}" ]] || vps_field_die "required parameter $variable is empty"
    done

    [[ "$VPS_HOST" =~ ^[A-Za-z0-9][A-Za-z0-9._:-]*$ ]] || vps_field_die "VPS_HOST contains unsupported characters"
    [[ "$VPS_USER" =~ ^[A-Za-z0-9._-]+$ ]] || vps_field_die "VPS_USER contains unsupported characters"
    [[ "$VPS_SSH_PORT" =~ ^[0-9]+$ ]] && ((VPS_SSH_PORT >= 1 && VPS_SSH_PORT <= 65535)) || \
        vps_field_die "VPS_SSH_PORT must be between 1 and 65535"
    [[ "$VPS_PROJECT_NAME" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || vps_field_die "VPS_PROJECT_NAME is not a safe Compose project name"
    [[ "$DEPLOY_BRANCH" == "GSoC_2026" ]] || vps_field_die "DEPLOY_BRANCH must be GSoC_2026"
    [[ "$DEPLOY_COMMIT" =~ ^[0-9a-fA-F]{40}$ ]] || vps_field_die "DEPLOY_COMMIT must be a full 40-character Git commit"
    [[ "$FIELD_DURATION_HOURS" =~ ^[0-9]+$ ]] && ((FIELD_DURATION_HOURS >= 24 && FIELD_DURATION_HOURS <= 36)) || \
        vps_field_die "FIELD_DURATION_HOURS must be between 24 and 36"
    [[ "$SNAPSHOT_INTERVAL_HOURS" =~ ^[0-9]+$ ]] && ((SNAPSHOT_INTERVAL_HOURS >= 1 && SNAPSHOT_INTERVAL_HOURS <= FIELD_DURATION_HOURS)) || \
        vps_field_die "SNAPSHOT_INTERVAL_HOURS must be between 1 and FIELD_DURATION_HOURS"
    [[ "$FIELD_TARPIT_CPU_LIMIT" =~ ^[0-9]+([.][0-9]+)?$ ]] || vps_field_die "FIELD_TARPIT_CPU_LIMIT must be numeric"
    [[ "$ADMIN_SOURCE_CIDR" =~ ^[A-Za-z0-9.:/-]+$ ]] || vps_field_die "ADMIN_SOURCE_CIDR contains unsupported characters"
    [[ "$REPOSITORY_URL" =~ ^[A-Za-z0-9@._:/+-]+$ ]] || vps_field_die "REPOSITORY_URL contains unsupported characters"
    if [[ "$REPOSITORY_URL" =~ ^https?://[^/@]+:[^/@]+@ ]]; then
        vps_field_die "REPOSITORY_URL must not embed credentials"
    fi
    [[ "$VPS_DEPLOY_DIR" =~ ^(~\/|\/)[A-Za-z0-9._/-]+$ ]] || \
        vps_field_die "VPS_DEPLOY_DIR must begin with ~/ or / and contain only safe path characters"
    [[ "$VPS_DEPLOY_DIR" != "/" && "$VPS_DEPLOY_DIR" != *"/../"* && "$VPS_DEPLOY_DIR" != *"/.." ]] || \
        vps_field_die "VPS_DEPLOY_DIR is too broad or contains a parent-directory traversal"
    if [[ -n "${FIELD_TARPIT_MEMORY_LIMIT:-}" ]]; then
        [[ "$FIELD_TARPIT_MEMORY_LIMIT" =~ ^[0-9]+([bBkKmMgG]|[kKmMgG][bB])?$ ]] || \
            vps_field_die "FIELD_TARPIT_MEMORY_LIMIT must be a Docker size such as 256m or 1g"
    fi

    case "$VPS_SSH_KEY" in
        "~/"*) VPS_SSH_KEY="$HOME/${VPS_SSH_KEY#\~/}" ;;
    esac
    [[ -f "$VPS_SSH_KEY" && -r "$VPS_SSH_KEY" ]] || vps_field_die "VPS_SSH_KEY is not a readable file"

    local key_path repo_path
    key_path="$(realpath -m "$VPS_SSH_KEY")"
    repo_path="$(realpath -m "$VPS_FIELD_REPO_ROOT")"
    case "$key_path" in
        "$repo_path"|"$repo_path"/*) vps_field_die "the SSH private key must not be stored inside the repository" ;;
    esac

    VPS_FIELD_SSH=(
        ssh
        -o BatchMode=yes
        -o IdentitiesOnly=yes
        -o StrictHostKeyChecking=yes
        -o ConnectTimeout=10
        -p "$VPS_SSH_PORT"
        -i "$VPS_SSH_KEY"
    )
    VPS_FIELD_SCP=(
        scp
        -o BatchMode=yes
        -o IdentitiesOnly=yes
        -o StrictHostKeyChecking=yes
        -o ConnectTimeout=10
        -P "$VPS_SSH_PORT"
        -i "$VPS_SSH_KEY"
    )
    VPS_FIELD_TARGET="$VPS_USER@$VPS_HOST"
}

vps_field_ssh() {
    "${VPS_FIELD_SSH[@]}" "$VPS_FIELD_TARGET" "$@"
}

vps_field_require_clean_commit() {
    local branch head remote_head
    branch="$(git -C "$VPS_FIELD_REPO_ROOT" branch --show-current)"
    head="$(git -C "$VPS_FIELD_REPO_ROOT" rev-parse HEAD)"

    [[ "$branch" == "$DEPLOY_BRANCH" ]] || vps_field_die "local branch $branch does not match $DEPLOY_BRANCH"
    [[ "$head" == "$DEPLOY_COMMIT" ]] || vps_field_die "local HEAD $head does not match DEPLOY_COMMIT $DEPLOY_COMMIT"
    [[ -z "$(git -C "$VPS_FIELD_REPO_ROOT" status --porcelain --untracked-files=normal)" ]] || \
        vps_field_die "working tree is not clean; review and commit before deployment"
    git -C "$VPS_FIELD_REPO_ROOT" diff --check
    git -C "$VPS_FIELD_REPO_ROOT" cat-file -e "$DEPLOY_COMMIT^{commit}"

    remote_head="$(git ls-remote "$REPOSITORY_URL" "refs/heads/$DEPLOY_BRANCH" | awk 'NR == 1 {print $1}')"
    [[ -n "$remote_head" ]] || vps_field_die "could not resolve $DEPLOY_BRANCH from REPOSITORY_URL"
    [[ "$remote_head" == "$DEPLOY_COMMIT" ]] || vps_field_die \
        "remote branch tip $remote_head does not match DEPLOY_COMMIT $DEPLOY_COMMIT; push the reviewed commit first"
}

vps_field_compose_args() {
    VPS_FIELD_COMPOSE=(
        docker compose
        -p "$VPS_PROJECT_NAME"
        -f docker-compose.yml
        -f docker-compose.cost.yml
        -f docker-compose.field.yml
    )
}
