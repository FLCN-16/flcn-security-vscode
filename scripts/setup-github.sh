#!/usr/bin/env bash
# Run once after `gh auth login` to configure the GitHub repo settings.
# Usage: bash scripts/setup-github.sh

set -euo pipefail

REPO="FLCN-16/flcn-security-vscode"

echo "==> Configuring $REPO"

# ---------------------------------------------------------------------------
# 1. Main branch protection
# ---------------------------------------------------------------------------
echo "--> Branch protection: main"
gh api "repos/$REPO/branches/main/protection" \
  --method PUT \
  --header "Accept: application/vnd.github+json" \
  --field "required_status_checks[strict]=true" \
  --field "required_status_checks[contexts][]=build" \
  --field "enforce_admins=true" \
  --field "required_pull_request_reviews[required_approving_review_count]=1" \
  --field "required_pull_request_reviews[dismiss_stale_reviews]=true" \
  --field "required_pull_request_reviews[require_code_owner_reviews]=false" \
  --field "restrictions=null" \
  --field "allow_force_pushes=false" \
  --field "allow_deletions=false" \
  --field "required_linear_history=true"

# ---------------------------------------------------------------------------
# 2. Require signed commits on main
# ---------------------------------------------------------------------------
echo "--> Require signed commits on main"
gh api "repos/$REPO/branches/main/protection/required_signatures" \
  --method POST \
  --header "Accept: application/vnd.github+json"

# ---------------------------------------------------------------------------
# 3. Repo-level settings
# ---------------------------------------------------------------------------
echo "--> Repo settings"
gh api "repos/$REPO" \
  --method PATCH \
  --field "has_issues=true" \
  --field "has_projects=false" \
  --field "has_wiki=false" \
  --field "allow_squash_merge=true" \
  --field "allow_merge_commit=false" \
  --field "allow_rebase_merge=false" \
  --field "delete_branch_on_merge=true" \
  --field "allow_auto_merge=false"

# ---------------------------------------------------------------------------
# 4. Enable vulnerability alerts and Dependabot
# ---------------------------------------------------------------------------
echo "--> Enable vulnerability alerts"
gh api "repos/$REPO/vulnerability-alerts" \
  --method PUT \
  --header "Accept: application/vnd.github+json"

echo "--> Enable Dependabot security updates"
gh api "repos/$REPO/automated-security-fixes" \
  --method PUT \
  --header "Accept: application/vnd.github+json"

echo ""
echo "Done. Verify at: https://github.com/$REPO/settings/branches"
