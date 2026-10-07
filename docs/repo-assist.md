# Repo Assist for this fork

Repo Assist maintains **Artic0din/Prismarr** at 07:30 Australia/Melbourne each day, including daylight saving.
It can also run manually from Actions on `main`.
It never sends pull requests, comments or other writes to Shoshuo/Prismarr.
Existing copied upstream issues and pull requests are checked before starting work so it does not duplicate them.

## What this installation does

Each run chooses one issue investigation, triage item, documentation task, existing Repo Assist PR or justified stale-PR nudge.
It then updates its owned Memory and Monthly Activity issues.
The prompt retains the eleven-task maintenance catalogue, but this initial profile cannot publish PHP, Twig, migration, dependency, infrastructure or workflow changes.

The only permitted PR paths are `README.md`, `CHANGELOG.md` and Markdown files under `docs/`.
The changelog exception permits the entry required by Prismarr's contribution rules.
Documentation proposals still require the repository's validation gate and its current PR template.
If that gate cannot run, the workflow records the proposal for a maintainer instead of publishing an unverified PR.

Prismarr's application checks are `make check`, which runs PHP syntax lint, Twig lint and PHPUnit inside the Prismarr Docker container.
The credential-free model tool container has no PHP application runtime or Docker socket.
Application work therefore remains investigation or a proposal, with the missing test capability stated in the monthly report.
Adding a PHP testing runtime later requires its own reviewed change and isolation tests; granting the model the Docker socket is not an acceptable shortcut.

New PRs are ready for review, use a Conventional Commit title with `[repo-assist]`, and carry only `automation` and `repo-assist` labels.
The workflow cannot merge, enable auto-merge, force-push, write to `main`, close human issues or PRs, publish releases, or change its own instructions.
The existing application CI remains intact and runs alongside the new automation validation job on every PR.

## One-time owner setup

No credentials are included in this repository.
On initial inspection, this fork had workflows disabled, no Actions secrets, and no environments.
Those observations do not establish the current settings; verify them before activation.

1. Enable workflows on the [fork's Actions page](https://github.com/Artic0din/Prismarr/actions).
   The inherited Beta workflow is manual-only, Release requires a newly pushed stable version tag, and Docker Hub README sync is guarded to run only in the upstream repository.
   Enabling workflows does not authorize running those publishing workflows.
2. In [Environments](https://github.com/Artic0din/Prismarr/settings/environments), create `repo-assist` and `repo-assist-publisher`.
   For each, choose **Selected branches and tags** and allow only a **branch** named `main`, with no tag patterns.
   Do not use **Protected branches only** as a substitute, because this fork may have no branch protection.
   Daily unattended runs require no per-run environment reviewer; a reviewer gate intentionally pauses each run instead.
3. The owner enters `CLAUDE_CODE_OAUTH_TOKEN` only in the `repo-assist` environment.
   [Anthropic documents `claude setup-token`](https://github.com/anthropics/claude-code-action/blob/main/docs/setup.md) for Pro/Max subscription authentication.
   Enter the value directly in GitHub, never in chat, source, issues or logs.
4. The owner enters `REPO_ASSIST_GITHUB_TOKEN` only in `repo-assist-publisher`.
   Use a fine-grained token owned by `Artic0din`, restricted to **Artic0din/Prismarr only**, with Contents, Issues and Pull requests **read and write**.
   No Workflows, Actions-write, administration, organization or account permissions are needed.
   Use an expiration and renew it through the owner's secure credential process.
5. Keep the repository's default `GITHUB_TOKEN` read-only and **Allow GitHub Actions to create and approve pull requests** off.
   That setting [governs the built-in token](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#preventing-github-actions-from-creating-or-approving-pull-requests).
   The dedicated publisher token authenticates separately and allows published PR events to start downstream CI.

Organization secrets cannot be shared directly with this personal-account fork.
Do not expand another repository's token or move credentials between repositories without the owner's specific approval.
The publishing account is checked as `Artic0din`; changing it also requires deliberate migration of owned state issues.

After the installation PR's checks and review pass, the owner must authorize merging it.
Then run Repo Assist manually on `main` and inspect the agent, independent detector, ownership validator and publisher results, plus actual created or updated issues and PRs.
Offline tests, compilation and synthetic authentication fixtures do not prove a live subscription token works.
Disable the Repo Assist workflow in Actions to stop future scheduled runs.

## Credential and execution boundaries

The final workflow uses official Claude Code **2.1.273** with `claude-sonnet-4-6` and subscription OAuth.
There is no API-credit fallback.
Missing OAuth or competing API/cloud-provider authentication fails before model execution.
Included subscription allowance is consumed and plan limits can stop a run; execution limits are not a subscription spending cap.

The trusted Claude controller receives OAuth but exposes no built-in tools and has no repository mount.
Its sole repository interface is a fixed HTTP MCP service in a separate credential-free container.
That container performs repository reads, shell commands and edits without OAuth, GitHub credentials, a controller mount or shared process namespace.
It never mounts the Docker socket or the runner's home directory.
The controller disables repository settings, hooks, plugins, slash commands, external connectors and automatic updates.
The official pinned CLI's actual dispatcher is tested against synthetic model requests for forbidden tools.

An independent detector has its own controller, read-only repository tools and a private loopback verdict sink.
Repository code cannot write the verdict or reach that private listener.
Malformed, missing, failed or threatening verdicts block publication.
The trusted publisher runs in a separate job and environment after successful model completion, detection and ownership validation.
Its token is never passed to either model controller or repository tools.
The source compiler ignores custom-job environment fields, so the reviewed transform explicitly inserts the publisher environment and tests that every other publisher byte remains unchanged.
The conclusion job uses the built-in read-only token and records detection outcomes only in Actions logs; it cannot create diagnostic issues outside the publication budget.

The model containers run non-root with read-only root filesystems, separate temporary storage and process namespaces, no Linux capabilities, and `no-new-privileges`.
Their internal network has no direct internet route.
A credential-free gateway permits only TLS CONNECT to `api.anthropic.com:443`, checking the authority, TLS server name and public DNS addresses.
Native read-only GitHub proxies and inert safe-output proposals remain outside the model containers.

These boundaries depend on the pinned CLI, trusted adapters, container runtime and reviewed workflow code.
They are not a claim that these components contain no security bugs.
Repository administrators and writers who can change trusted `main` remain trusted maintainers.
Main-only environments prevent ordinary PR branches from obtaining these credentials; they do not protect against a malicious administrator.

## Publication checks and limits

- Only same-repository `repo-assist/*` branches with the title marker and both automation labels may be updated
- Existing PR diffs are checked completely, including rename sources, against the documentation allowlist
- Memory and reports require the exact title, `repo-assist` label, publishing account and native workflow marker
- State changes made after the run started block replacement, preserving concurrent maintainer edits
- A trusted gitleaks scan checks outgoing commits, metadata and complete Git bundles; patch-only fallback fails closed

The exact OAuth value is also checked in files, Git objects and output artifacts after all model containers stop.
Git configuration is restored and hooks disabled before trusted publication operations.
Both output-ingestion and artifact-upload paths require the guard to pass.
Exact-token scanning is defense in depth; credential separation is what prevents repository code from reading the token.

Each run is capped at four new PRs, four own-PR updates, ten comments, three comments on other PRs, thirty label additions, five removals and four new issues.
The issue cap includes missing Memory and Monthly Activity issues.
Eight open Repo Assist PRs or another active installation stop execution.
Runs queue rather than cancel one another.

The controller has a 60-turn limit and 55-minute model timeout within a 60-minute job.
Detection has 20 turns and a seven-minute model timeout, with eight minutes for its full process.
Each confined container has two CPUs, 4 GiB RAM, 256 processes and a 1 GiB temporary filesystem.
Repository commands have a sixty-second timeout and bounded input/output sizes.
At thirty repository calls, advisory guidance switches to reporting and finalization; this is not a count of model turns.
Only a final successful, nonblank Claude result qualifies as completed maintenance.

The native daily guard stops at 5,000 estimated AIC over the preceding 24 hours.
Complete final receipts use the pinned model catalogue; missing component receipts apply a conservative 1,000-AIC whole-run fallback.
These are operational estimates, not API charges or subscription-quota readings.

## Validation and regeneration

Edit `.github/workflows/repo-assist.md`, compile with the pinned **gh-aw v0.90.0** source plus the reviewed prerequisite patch, then run the guarded subscription transform.
Never commit or activate the untransformed compiler output: it is an API-authentication intermediate fixture, not the runnable subscription workflow.
The compiler source is pinned to `d534c311af32e1e3d26f2015d9b95d738633a2b5`.
The build script checks its source, patch digest and Go 1.27.0 before compiling.
The runtime uses digest-pinned firewall 0.28.27 containers, gateway 0.4.27 and native detector 0.5.2.

```sh
export RUNNER_TEMP="$(mktemp -d)"
git clone https://github.com/github/gh-aw.git "$RUNNER_TEMP/gh-aw-source"
git -C "$RUNNER_TEMP/gh-aw-source" checkout --detach d534c311af32e1e3d26f2015d9b95d738633a2b5
bash .github/scripts/build-repo-assist-compiler.sh "$RUNNER_TEMP/gh-aw-source"
export REPO_ASSIST_COMPILER_SOURCE="$RUNNER_TEMP/gh-aw-source"
"$RUNNER_TEMP/gh-aw-repo-assist" compile repo-assist --strict --validate --shellcheck --no-check-update --action-mode action --action-tag v0.90.0
python -m pip install PyYAML==6.0.3
python .github/scripts/transform-repo-assist-subscription.py .github/workflows/repo-assist.lock.yml
npm ci --prefix .github/repo-assist-cli --no-audit --no-fund
npm ci --prefix .github/tests/expression-evaluator --ignore-scripts --no-audit --no-fund
python -m unittest discover -s .github/tests -p 'test_repo_assist*.py' -v
python -m unittest discover -s .github/tests -p test_prismarr_contract.py -v
actionlint .github/workflows/agentic-workflows.yml .github/workflows/repo-assist.lock.yml .github/workflows/ci.yml
```

The CI validation job requires the real pinned CLI, Docker isolation tests and native detector integration, with synthetic credentials and no provider calls.
Local runs without Docker explicitly skip those lifecycle checks; a local partial pass is not a hosted pass.
The CI job recompiles and rejects stale generated workflow files.
`CI passed` requires both the unchanged application check and automation validation, including failure and skipped-job cases.
Commit the Markdown, generated lock, action lock, worker, fixtures and changed tests together.
Changed compiler behavior must be reviewed and explicitly fingerprinted; the transformer never learns approval from arbitrary input.
