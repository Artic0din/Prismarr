"""Exercise Repo Assist's scheduled trigger and real preflight shell."""

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/repo-assist.md"


def configuration() -> dict:
    """Load the Markdown frontmatter without YAML 1.1 boolean key coercion."""
    return yaml.load(WORKFLOW.read_text().split("---", 2)[1], Loader=yaml.BaseLoader)



class PublishingScanTests(unittest.TestCase):
    @staticmethod
    def step(name: str) -> dict:
        return next(
            step for step in configuration()["jobs"]["validate_updates"]["steps"]
            if step.get("name") == name
        )

    def test_pr_scan_gate_preserves_issue_only_maintenance(self) -> None:
        detect = self.step("Detect PR publishing requests")
        for kind, expected in (
            ("create_issue", "false"), ("create_pull_request", "true"),
            ("push_to_pull_request_branch", "true"),
        ):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "agent_output.json").write_text(json.dumps({"items": [{"type": kind}]}))
                output = root / "step-output"
                subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", detect["run"]],
                    check=True, capture_output=True, text=True,
                    env={**os.environ, "REPO_ASSIST_OUTPUT": str(root / "agent_output.json"),
                         "GITHUB_OUTPUT": str(output)},
                )
                self.assertEqual(output.read_text().strip(), f"required={expected}")
        for name in ("Set up trusted scanner Go", "Check out trusted scan base", "Scan proposed PR artifacts"):
            step = self.step(name)
            self.assertEqual(step["if"], "steps.pr_scan.outputs.required == 'true'")
            self.assertNotEqual(step.get("continue-on-error"), "true")

    @staticmethod
    def create_bundle_fixture(source: Path, checkout: Path, artifacts: Path) -> str:
        def git(*arguments: str, cwd: Path = source) -> str:
            return subprocess.run(
                ["git", *arguments], cwd=cwd, check=True,
                capture_output=True, text=True,
            ).stdout.strip()
        git("init", "-b", "main")
        git("config", "user.name", "Fixture")
        git("config", "user.email", "fixture@example.invalid")
        git("config", "core.hooksPath", "/dev/null")
        (source / "notes.txt").write_text("base\n")
        git("add", ".")
        git("commit", "-m", "test: base")
        base = git("rev-parse", "HEAD")
        git("clone", str(source), str(checkout))
        (source / "notes.txt").write_text("new\n")
        git("commit", "-am", "test: outgoing")
        git("checkout", "-b", "feature", base)
        (source / "feature.txt").write_text("feature\n")
        git("add", ".")
        git("commit", "-m", "test: feature")
        git("checkout", "main")
        git("merge", "--no-ff", "feature", "-m", "test: merge metadata")
        head = git("rev-parse", "HEAD")
        git("bundle", "create", str(artifacts / "aw-fixture.bundle"), "main", f"^{base}")
        return head

    def test_install_and_both_scanners_fail_closed(self) -> None:
        step = self.step("Scan proposed PR artifacts")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, checkout, artifacts, binaries = (
                root / name for name in ("source", "checkout", "artifacts", "bin")
            )
            for path in (source, artifacts, binaries):
                path.mkdir()
            (artifacts / "agent_output.json").write_text('{"items": []}')
            (artifacts / "aw-fixture.patch").write_text("fixture patch")
            (artifacts / "diagnostic.log").write_text("unpublished runner diagnostics")
            nested = artifacts / "logs" / "repository"
            nested.mkdir(parents=True)
            (nested / "ordinary.bundle").write_text("not a Git transport")
            head = self.create_bundle_fixture(source, checkout, artifacts)
            scanner = binaries / "scanner"
            scanner.write_text(
                f"#!{sys.executable}\nimport json, os, sys\nfrom pathlib import Path\n"
                "if sys.argv[1] == 'dir':\n"
                "    files = {p.name for p in Path(sys.argv[2]).iterdir()}\n"
                "    assert files == {'agent_output.json', 'commit-0.txt'}\n"
                "    metadata = (Path(sys.argv[2]) / 'commit-0.txt').read_text()\n"
                "    assert 'test: merge metadata' in metadata\n"
                "    assert 'author Fixture <fixture@example.invalid>' in metadata\n"
                "with open(os.environ['SCANNER_LOG'], 'a') as output:\n"
                "    output.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                "raise SystemExit(1 if os.environ['FAIL_MODE'] == sys.argv[1] else 0)\n"
            )
            scanner.chmod(0o700)
            go = binaries / "go"
            go.write_text(
                '#!/bin/sh\n[ "$FAIL_MODE" = install ] && exit 3\n'
                'ln -sf "$FAKE_SCANNER" "$GOBIN/gitleaks"\n'
            )
            go.chmod(0o700)
            for failure in ("none", "install", "dir", "git", "missing_bundle", "missing_companion"):
                with self.subTest(failure=failure):
                    log = root / f"{failure}.jsonl"
                    bundle = artifacts / "aw-fixture.bundle"
                    missing_patch = artifacts / "aw-missing.patch"
                    if failure == "missing_bundle":
                        bundle.rename(root / "saved.bundle")
                    if failure == "missing_companion":
                        missing_patch.write_text("patch without scanned bundle")
                    result = subprocess.run(
                        ["bash", "-euo", "pipefail", "-c", step["run"]],
                        capture_output=True, text=True, check=False,
                        env={**os.environ, "PATH": f"{binaries}:{os.environ['PATH']}",
                             "RUNNER_TEMP": str(root), "REPO_ASSIST_ARTIFACTS": str(artifacts),
                             "REPO_ASSIST_SCAN_BASE": str(checkout), "FAKE_SCANNER": str(scanner),
                             "SCANNER_LOG": str(log), "FAIL_MODE": failure},
                    )
                    self.assertEqual(result.returncode == 0, failure == "none", result.stderr)
                    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
                    if failure in ("install", "missing_bundle", "missing_companion"):
                        self.assertEqual(calls, [])
                    else:
                        self.assertEqual(calls[0][0], "dir")
                        self.assertIn("--ignore-gitleaks-allow", calls[0])
                    if failure in ("none", "git"):
                        self.assertEqual(calls[1][0], "git")
                        self.assertIn(f"{head} --not --all --diff-merges=first-parent", calls[1])
                        self.assertIn("--redact", calls[1])
                    if failure == "missing_bundle":
                        (root / "saved.bundle").rename(bundle)
                    missing_patch.unlink(missing_ok=True)

class RepoAssistTests(unittest.TestCase):
    def test_linux_profile_has_one_task_and_explicit_publication_paths(self) -> None:
        prompt = WORKFLOW.read_text().split("---", 2)[2]
        selection = prompt.split("## Step 2", 1)[1].split("## Task 1", 1)[0]
        self.assertIn("Select exactly one eligible task from Tasks 1, 2, 5, 6 and 7", selection)
        self.assertIn("README.md, CHANGELOG.md and Markdown files under docs/", selection)
        for path in ("AGENTS.md", "CLAUDE.md", "CONTRIBUTING.md", ".github/", "symfony/", "docker/", "templates/"):
            self.assertIn(path, selection)
        for conflicting in ("draw three distinct tasks", "Execute the three selected tasks", "scan many more"):
            self.assertNotIn(conflicting, prompt)
        self.assertIn("at most eight candidate issues", prompt)
        self.assertIn("Never start another investigation during finalization", prompt)
        self.assertIn("For the one selected open PR", prompt)
        self.assertIn("already verified during this run", prompt)
        self.assertNotIn("For each open PR labelled", prompt)
        self.assertNotIn("complete list of every pending item", prompt)
        self.assertIn("Carry forward prior unchecked actions", prompt)
        task6 = prompt.split("## Task 6", 1)[1].split("## Task 7", 1)[0]
        self.assertIn("For the one selected open PR", task6)
        self.assertIn("Leave other PRs for later runs", task6)
        self.assertNotIn("For each open PR", task6)
        task11 = prompt.split("## Task 11", 1)[1].split("## Step 3", 1)[0]
        self.assertNotIn("complete list of every pending item", task11)
        self.assertNotIn("all unacknowledged Repo Assist comments", task11)
        self.assertIn("fetch comment history just to make this report exhaustive", task11)
        self.assertIn("unexamined work remains deferred", task11)

    def test_locked_cli_installations_need_no_adhoc_exceptions(self) -> None:
        package = json.loads((ROOT / ".github/repo-assist-cli/package.json").read_text())
        lock = json.loads((ROOT / ".github/repo-assist-cli/package-lock.json").read_text())
        self.assertEqual(package["dependencies"], {"@anthropic-ai/claude-code": "2.1.273"})
        self.assertEqual(lock["packages"][""]["dependencies"], package["dependencies"])
        for name, dependency in lock["packages"].items():
            if not name:
                continue
            self.assertEqual(dependency["version"], "2.1.273")
            self.assertTrue(dependency["resolved"].startswith("https://registry.npmjs.org/@anthropic-ai/"))
            self.assertTrue(dependency["integrity"].startswith("sha512-"))
        compiled = yaml.load((ROOT / ".github/workflows/repo-assist.lock.yml").read_text(), Loader=yaml.BaseLoader)
        for phase in ("agent", "detection"):
            steps = compiled["jobs"][phase]["steps"]
            installs = [step for step in steps if step.get("name") == "Install locked Claude Code CLI"]
            self.assertEqual(len(installs), 1)
            self.assertEqual(installs[0]["run"], 'npm ci --prefix "$RUNNER_TEMP/repo-assist-cli" --no-audit --no-fund')
            self.assertNotIn("secrets.", json.dumps(installs[0]))
            self.assertNotIn("npm install -g", json.dumps(steps))

    def test_subscription_engine_and_detector_do_not_require_api_credentials(self) -> None:
        source = configuration()
        expected = {"id": "claude", "model": "claude-sonnet-4-6"}
        self.assertEqual(source["engine"], expected)
        self.assertEqual(source["safe-outputs"]["threat-detection"]["engine"], expected)
        compiled = yaml.load((ROOT / ".github/workflows/repo-assist.lock.yml").read_text(), Loader=yaml.BaseLoader)
        for phase, execution_id in (("agent", "agentic_execution"), ("detection", "detection_agentic_execution")):
            job = compiled["jobs"][phase]
            self.assertEqual(job["environment"], "repo-assist")
            execution = next(step for step in job["steps"] if step.get("id") == execution_id)
            self.assertEqual(execution["env"]["CLAUDE_CODE_OAUTH_TOKEN"], "${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}")
            self.assertEqual(execution["env"]["ANTHROPIC_MODEL"], "claude-sonnet-4-6")
            for forbidden in ("ANTHROPIC_API_KEY", "COPILOT_GITHUB_TOKEN", "copilot_harness.cjs", "REPO_ASSIST_GITHUB_TOKEN"):
                self.assertNotIn(forbidden, json.dumps(job))

    @staticmethod
    def reflection_fixture(runner: Path) -> bytes:
        content = (
            b'const path = require("node:path"); const os = require("node:os");\n'
            b'const AWF_REFLECT_OUTPUT_PATH = '
            b'path.join(process.env.RUNNER_TEMP || os.tmpdir(), '
            b'"awf-reflect.json");\n'
            b'module.exports = { AWF_REFLECT_OUTPUT_PATH };\n'
        )
        helper = runner / "gh-aw/actions/awf_reflect.cjs"
        helper.parent.mkdir(parents=True)
        helper.write_bytes(content)
        return content

    def test_upstream_fixture_retains_reviewed_reflection_preparation(self) -> None:
        source = configuration()
        preparation = source["safe-outputs"]["threat-detection"]["steps"][0]
        self.assertIn(preparation, source["pre-agent-steps"])
        compiled = yaml.load(
            (ROOT / ".github/tests/fixtures/repo-assist-subscription-input.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        for job_name, execution in (
            ("agent", "Execute Claude Code CLI"),
            ("detection", "Execute threat detection with AWF"),
        ):
            steps = compiled["jobs"][job_name]["steps"]
            names = [step.get("name") for step in steps]
            actual = steps[names.index(preparation["name"])]
            self.assertEqual(actual["run"].rstrip(), preparation["run"].rstrip())
            self.assertEqual(actual["env"], preparation["env"])
            self.assertNotEqual(actual.get("continue-on-error"), "true")
            self.assertLess(names.index(preparation["name"]), names.index(execution))
            self.assertIn(
                "--exclude-env ANTHROPIC_API_KEY",
                steps[names.index(execution)]["run"],
            )
            self.assertIn(
                '${RUNNER_TEMP}/gh-aw:${RUNNER_TEMP}/gh-aw:ro',
                steps[names.index(execution)]["run"],
            )
            self.assertIn(
                "--mount /tmp/gh-aw:/tmp/gh-aw:rw",
                steps[names.index(execution)]["run"],
            )
        names = [step.get("name") for step in compiled["jobs"]["agent"]["steps"]]
        self.assertLess(
            names.index("Require credential cleanup before AI execution"),
            names.index(preparation["name"]),
        )

    def test_subscription_execution_replaces_api_proxy_reflection(self) -> None:
        compiled = yaml.load((ROOT / ".github/workflows/repo-assist.lock.yml").read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(compiled["jobs"]["pre_activation"]["if"], "github.ref == 'refs/heads/main' && github.repository == 'Artic0din/Prismarr'")
        recipients = []
        for phase, job in compiled["jobs"].items():
            for step in job.get("steps", []):
                if "secrets.CLAUDE_CODE_OAUTH_TOKEN" in json.dumps(step):
                    recipients.append((phase, step.get("id", step["name"])))
        self.assertEqual(recipients, [("agent", "agentic_execution"), ("agent", "collect_output"), ("detection", "detection_agentic_execution")])
        for phase, execution_id in (("agent", "agentic_execution"), ("detection", "detection_agentic_execution")):
            steps = compiled["jobs"][phase]["steps"]
            names = [step.get("name") for step in steps]
            execution = next(step for step in steps if step.get("id") == execution_id)
            self.assertEqual(execution["run"].strip(), f'python3 "$RUNNER_TEMP/repo-assist-trusted/repo-assist-worker.py" {phase}')
            for name in ("Install AWF binary", "Prepare writable API proxy reflection artifact"):
                self.assertNotIn(name, names)
            stage = names.index("Stage trusted subscription worker")
            install = names.index("Install locked Claude Code CLI")
            self.assertLess(stage, install)
            self.assertLess(install, steps.index(execution))
            for index in (stage, install):
                self.assertNotEqual(steps[index].get("continue-on-error"), "true")
                self.assertNotIn("secrets.", json.dumps(steps[index]))
            self.assertIn('cp -R .github/repo-assist-worker/. "$RUNNER_TEMP/repo-assist-trusted/"', steps[stage]["run"])
            if phase == "agent":
                self.assertLess(stage, names.index("Checkout PR branch"))
                self.assertLess(names.index("Stop MCP Gateway"), names.index("Ingest agent output"))

    def test_reflection_artifact_is_writable_from_exported_read_only_subtree(self) -> None:
        preparation = configuration()["safe-outputs"]["threat-detection"]["steps"][0]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            host_runner, guest_runner, artifact = (base / name for name in ("host", "guest", "artifacts"))
            original = self.reflection_fixture(host_runner)
            command = preparation["run"].replace("/tmp/gh-aw/sandbox/firewall", str(artifact))
            environment = {
                "PATH": os.environ["PATH"], "RUNNER_TEMP": str(host_runner),
                "REPO_ASSIST_REFLECT_SHA256": hashlib.sha256(original).hexdigest(),
            }
            subprocess.run(["bash", "-e", "-c", command], env=environment, check=True)
            # AWF exports only the gh-aw subtree; host runner-root entries stay outside.
            shutil.copytree(host_runner / "gh-aw", guest_runner / "gh-aw")
            self.assertFalse((guest_runner / "awf-reflect.json").exists())
            for entry in guest_runner.rglob("*"):
                entry.chmod(0o555 if entry.is_dir() else 0o444)
            guest_runner.chmod(0o555)
            try:
                result = subprocess.run(
                    ["node", "-e", "const fs = require('node:fs');"
                     "const path = require('node:path');"
                     "const assert = require('node:assert/strict');"
                     "const rootFile = path.join("
                     "process.env.RUNNER_TEMP, 'awf-reflect.json');"
                     "if (process.getuid() !== 0) {"
                     "assert.throws(() => fs.writeFileSync("
                     "rootFile, 'unmounted'), /EACCES/); }"
                     "const helper = require(path.join(process.env.RUNNER_TEMP,"
                     "'gh-aw/actions/awf_reflect.cjs'));"
                     "fs.writeFileSync(helper.AWF_REFLECT_OUTPUT_PATH,"
                     "JSON.stringify({provider:'anthropic'}));"
                     "console.log(fs.readFileSync("
                     "helper.AWF_REFLECT_OUTPUT_PATH, 'utf8'));"],
                    env={**environment, "RUNNER_TEMP": str(guest_runner)},
                    capture_output=True, text=True, check=True,
                )
                self.assertEqual(json.loads(result.stdout), {"provider": "anthropic"})
                self.assertEqual(
                    json.loads((artifact / "awf-reflect.json").read_text()),
                    {"provider": "anthropic"},
                )
                self.assertFalse((guest_runner / "awf-reflect.json").exists())
            finally:
                guest_runner.chmod(0o755)
                for entry in guest_runner.rglob("*"):
                    if entry.is_dir():
                        entry.chmod(0o755)

    def test_reflection_preparation_rejects_unreviewed_runtime_bytes(self) -> None:
        preparation = configuration()["safe-outputs"]["threat-detection"]["steps"][0]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            runner = base / "runner-temp"
            original = self.reflection_fixture(runner)
            helper = runner / "gh-aw/actions/awf_reflect.cjs"
            command = preparation["run"].replace("/tmp/gh-aw/sandbox/firewall", str(base / "artifacts"))
            result = subprocess.run(
                ["bash", "-e", "-c", command],
                env={"PATH": os.environ["PATH"], "RUNNER_TEMP": str(runner),
                     **preparation["env"]},
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Unexpected pinned reflection helper", result.stderr)
            self.assertEqual(helper.read_bytes(), original)
            self.assertFalse((base / "artifacts").exists())

    def test_reusable_validation_concurrency_is_scoped_to_its_caller(self) -> None:
        workflow = yaml.load(
            (ROOT / ".github/workflows/agentic-workflows.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        self.assertIn("github.workflow", workflow["concurrency"]["group"])

    def test_threat_detection_failure_blocks_publishing(self) -> None:
        compiled = yaml.load(
            (ROOT / ".github/workflows/repo-assist.lock.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        detection = compiled["jobs"]["detection"]
        conclusion = next(
            step for step in detection["steps"]
            if step.get("id") == "detection_conclusion"
        )
        self.assertNotEqual(conclusion.get("continue-on-error"), "true")
        self.assertEqual(
            conclusion["env"]["GH_AW_DETECTION_CONTINUE_ON_ERROR"], "false",
        )
        publisher = compiled["jobs"]["safe_outputs"]
        self.assertIn("detection", publisher["needs"])
        self.assertIn("needs.detection.result == 'success'", publisher["if"])

    def test_native_failure_fallbacks_do_not_create_extra_items(self) -> None:
        compiled = yaml.load(
            (ROOT / ".github/workflows/repo-assist.lock.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        step = next(
            item for item in compiled["jobs"]["safe_outputs"]["steps"]
            if item.get("name") == "Process Safe Outputs"
        )
        handlers = json.loads(step["env"]["GH_AW_SAFE_OUTPUTS_HANDLER_CONFIG"])
        self.assertIs(
            handlers["push_to_pull_request_branch"].get("fallback_as_pull_request", True),
            False,
        )
        self.assertIs(
            handlers["create_pull_request"].get("fallback_as_issue", True), False,
        )

    def test_task_candidates_exclude_only_exact_state_issue_titles(self) -> None:
        command = next(
            line for line in WORKFLOW.read_text().splitlines()
            if line.startswith("gh issue list") and "issues.json" in line
        )
        arguments = shlex.split(command)
        query = arguments[arguments.index("--jq") + 1] if "--jq" in arguments else "."
        issues = [
            {"title": title}
            for title in (
                "[repo-assist] Memory", "[repo-assist] Monthly Activity 2026-09",
                "[repo-assist] Memory corruption",
                "[repo-assist] Monthly Activity 2026-09 rendering bug",
                "[repo-assist] Monthly Activity 2026-13", "Ordinary issue",
            )
        ]
        result = subprocess.run(
            ["jq", "-c", query], input=json.dumps(issues),
            capture_output=True, text=True, check=True,
        )
        self.assertEqual(json.loads(result.stdout), issues[2:])

    def test_validation_downloads_the_same_outputs_as_the_publisher(self) -> None:
        compiled = yaml.load(
            (ROOT / ".github/workflows/repo-assist.lock.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        publisher = next(
            step["with"]
            for step in compiled["jobs"]["safe_outputs"]["steps"]
            if step.get("id") == "download-agent-output"
        )
        validator = next(
            step["with"]
            for step in compiled["jobs"]["validate_updates"]["steps"]
            if step.get("name") == "Download proposed outputs"
        )
        for inputs in (publisher, validator):
            self.assertNotIn("name", inputs)
            self.assertEqual(inputs.get("pattern"), "{agent,agent-output-fallback}")
            self.assertEqual(inputs.get("merge-multiple"), "true")

    def test_memory_lookup_paginates_and_ignores_similar_titles(self) -> None:
        command = next(
            line
            for line in WORKFLOW.read_text().splitlines()
            if line.startswith(("gh issue list", "gh api --paginate"))
        )
        arguments = shlex.split(command)
        self.assertEqual(arguments[:2], ["gh", "api"])
        self.assertIn("--paginate", arguments)
        memory = {
            "number": 102, "title": "[repo-assist] Memory",
            "body": "state\n<!-- gh-aw-workflow-id: repo-assist -->",
        }
        recorded = {
            **memory, "user": {"login": "Artic0din"},
            "labels": [{"name": "repo-assist"}],
        }
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                requests.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                if "page=2" in self.path:
                    payload = [recorded]
                else:
                    self.send_header(
                        "Link",
                        f"<http://127.0.0.1:{self.server.server_port}/issues?page=2>; "
                        'rel="next"',
                    )
                    payload = [
                        {
                            "number": n,
                            "title": "[repo-assist] Memory corruption",
                            "body": "unrelated",
                        }
                        for n in range(1, 101)
                    ]
                    payload.extend([
                        {**recorded, "number": 101, "pull_request": {}},
                        {**recorded, "number": 98, "user": {"login": "someone-else"}},
                        {**recorded, "number": 99, "body": "Human discussion"},
                        {**recorded, "number": 100, "labels": []},
                    ])
                self.end_headers()
                self.wfile.write(json.dumps(payload).encode())

            def log_message(self, format: str, *args: object) -> None:
                pass

        with (
            HTTPServer(("127.0.0.1", 0), Handler) as server,
            tempfile.TemporaryDirectory() as directory,
        ):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            arguments = [
                f"http://127.0.0.1:{server.server_port}/issues"
                if arg.startswith("repos/")
                else arg
                for arg in arguments
            ]
            try:
                result = subprocess.run(
                    arguments,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                    env={
                        **os.environ,
                        "GH_CONFIG_DIR": directory,
                        "GH_TOKEN": "fixture",
                        "GITHUB_TOKEN": "fixture",
                        "GH_ENTERPRISE_TOKEN": "fixture",
                    },
                )
            finally:
                server.shutdown()
                thread.join()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(requests), 2)
        self.assertEqual(json.loads(result.stdout), memory)

    def test_diagnostics_do_not_create_extra_issues(self) -> None:
        compiled = yaml.load(
            (ROOT / ".github/workflows/repo-assist.lock.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        values = {
            key: value
            for job in compiled["jobs"].values()
            for step in job.get("steps", [])
            for key, value in step.get("env", {}).items()
        }
        for key in (
            "GH_AW_MISSING_TOOL_CREATE_ISSUE",
            "GH_AW_REPORT_INCOMPLETE_CREATE_ISSUE",
            "GH_AW_FAILURE_REPORT_AS_ISSUE",
            "GH_AW_REPORT_FAILED_JOBS",
        ):
            self.assertEqual(values.get(key, "false"), "false", key)

    def test_new_pr_markers_and_issue_body_limits_are_enforced(self) -> None:
        script = configuration()["jobs"]["validate_updates"]["steps"][1]["run"]
        cases = (
            (
                {
                    "type": "create_pull_request",
                    "title": "fix(test): [repo-assist] test",
                },
                True,
            ),
            (
                {"type": "create_pull_request", "title": "fix(test): missing marker"},
                False,
            ),
            ({"type": "create_issue", "body": "a" * 60000}, True),
            ({"type": "update_issue", "body": "a" * 60001}, False),
            ({"type": "create_issue", "body": "a" * 60001}, False),
        )
        for item, allowed in cases:
            with (
                self.subTest(kind=item["type"], allowed=allowed),
                tempfile.TemporaryDirectory() as directory,
            ):
                output = Path(directory) / "agent_output.json"
                output.write_text(json.dumps({"items": [item]}))
                result = subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", script],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                    env={
                        **os.environ,
                        "GITHUB_REPOSITORY": "Artic0din/Prismarr",
                        "REPO_ASSIST_OUTPUT": str(output),
                    },
                )
                self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def test_credential_cleanup_fails_closed(self) -> None:
        step = configuration()["pre-agent-steps"][0]
        compiled = yaml.load(
            (ROOT / ".github/workflows/repo-assist.lock.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        steps = compiled["jobs"]["agent"]["steps"]
        names = [item.get("name") for item in steps]
        actual = steps[names.index(step["name"])]
        self.assertNotEqual(actual.get("continue-on-error"), "true")
        self.assertLess(names.index("Checkout PR branch"), names.index(step["name"]))
        self.assertLess(
            names.index(step["name"]), names.index("Execute subscription Claude worker")
        )
        for cleanup_result, residual, allowed in (
            (0, False, True),
            (7, False, False),
            (0, True, False),
        ):
            with (
                self.subTest(cleanup=cleanup_result, residual=residual),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                cleaner = root / "gh-aw/actions/clean_git_credentials.sh"
                cleaner.parent.mkdir(parents=True)
                cleaner.write_text(f"exit {cleanup_result}\n")
                subprocess.run(["git", "init", "-q", directory], check=True)
                if residual:
                    subprocess.run(
                        [
                            "git",
                            "-C",
                            directory,
                            "config",
                            "http.https://github.com/.extraheader",
                            "test",
                        ],
                        check=True,
                    )
                result = subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", step["run"]],
                    cwd=directory,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                    env={
                        **os.environ,
                        "RUNNER_TEMP": directory,
                        "GIT_CONFIG_GLOBAL": os.devnull,
                        "GIT_CONFIG_NOSYSTEM": "1",
                    },
                )
                self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def test_publisher_requires_successful_agent_and_ownership_check(self) -> None:
        compiled = yaml.load(
            (ROOT / ".github/workflows/repo-assist.lock.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        publisher = compiled["jobs"]["safe_outputs"]
        self.assertIn("validate_updates", publisher["needs"])
        self.assertIn("needs.agent.result == 'success'", publisher["if"])
        self.assertIn("needs.validate_updates.result == 'success'", publisher["if"])

    def test_pr_updates_reject_nonautomation_targets(self) -> None:
        script = configuration()["jobs"]["validate_updates"]["steps"][1]["run"]
        repository = "Artic0din/Prismarr"
        valid = {
            "head": {"ref": "repo-assist/fix", "repo": {"full_name": repository}},
            "title": "fix(test): [repo-assist] regression",
            "labels": [{"name": "repo-assist"}, {"name": "automation"}],
            "changed_files": 1,
        }
        cases = (
            ("valid", valid, repository, True),
            (
                "human branch",
                {**valid, "head": {**valid["head"], "ref": "human/fix"}},
                repository,
                False,
            ),
            (
                "fork",
                {
                    **valid,
                    "head": {**valid["head"], "repo": {"full_name": "other/fork"}},
                },
                repository,
                False,
            ),
            (
                "missing automation label",
                {**valid, "labels": [{"name": "repo-assist"}]},
                repository,
                False,
            ),
            (
                "missing marker",
                {**valid, "title": "fix(test): human work"},
                repository,
                False,
            ),
            ("cross-repository output", valid, "other/repository", False),
        )
        for name, pull_request, target, allowed in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output = root / "agent_output.json"
                output.write_text(
                    json.dumps(
                        {
                            "items": [
                                {
                                    "type": "push_to_pull_request_branch",
                                    "pull_request_number": 42,
                                    "repo": target,
                                }
                            ]
                        }
                    )
                )
                fake_gh = root / "gh"
                fake_gh.write_text(
                    f"#!{sys.executable}\n"
                    "import os, sys\n"
                    "if sys.argv[1:] == ['api', '--paginate', '--slurp', 'repos/Artic0din/Prismarr/pulls/42/files?per_page=100']:\n"
                    "    print('[[{\"filename\":\"README.md\"}]]')\n"
                    "    sys.exit(0)\n"
                    "expected = ['api', 'repos/Artic0din/Prismarr/pulls/42']\n"
                    "assert sys.argv[1:] == expected\n"
                    "print(os.environ['FAKE_PR'])\n"
                )
                fake_gh.chmod(0o700)
                result = subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", script],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                    env={
                        **os.environ,
                        "PATH": f"{directory}:{os.environ['PATH']}",
                        "GITHUB_REPOSITORY": repository,
                        "REPO_ASSIST_OUTPUT": str(output),
                        "FAKE_PR": json.dumps(pull_request),
                    },
                )
                self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def test_publishing_is_limited_to_documentation(self) -> None:
        outputs = configuration()["safe-outputs"]
        for name in ("create-pull-request", "push-to-pull-request-branch"):
            with self.subTest(output=name):
                self.assertEqual(
                    outputs[name].get("allowed-files"),
                    ["README.md", "CHANGELOG.md", "docs/*.md", "docs/**/*.md"],
                )
                self.assertNotIn(
                    "CHANGELOG.md", outputs[name]["protected-files"]["exclude"]
                )

    def test_agent_github_tools_use_readonly_job_token(self) -> None:
        compiled = yaml.load((ROOT / ".github/workflows/repo-assist.lock.yml").read_text(), Loader=yaml.BaseLoader)
        steps = compiled["jobs"]["agent"]["steps"]
        native_proxy = next(step for step in steps if step.get("name") == "Start CLI Proxy")
        self.assertEqual(native_proxy["env"]["GH_TOKEN"], "${{ secrets.GITHUB_TOKEN }}")
        execution = next(step for step in steps if step.get("id") == "agentic_execution")
        self.assertEqual(execution["env"]["REPO_ASSIST_READ_TOKEN"], "${{ github.token }}")
        for name in ("GITHUB_MCP_SERVER_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "ANTHROPIC_API_KEY"):
            self.assertNotIn(name, execution["env"])
        self.assertEqual(execution["run"].strip(), 'python3 "$RUNNER_TEMP/repo-assist-trusted/repo-assist-worker.py" agent')

    def test_project_preparation_survives_compilation(self) -> None:
        compiled = yaml.load(
            (ROOT / ".github/workflows/repo-assist.lock.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        names = [step.get("name") for step in compiled["jobs"]["agent"]["steps"]]
        for step in configuration()["steps"]:
            with self.subTest(step=step["name"]):
                self.assertIn(step["name"], names)
                installed = compiled["jobs"]["agent"]["steps"][
                    names.index(step["name"])
                ]
                self.assertEqual(installed.get("continue-on-error"), "true")
                self.assertLess(
                    names.index(step["name"]), names.index("Execute subscription Claude worker")
                )

    def test_publishing_credential_is_not_available_to_agent_tools(self) -> None:
        token = "${{ secrets.REPO_ASSIST_GITHUB_TOKEN }}"
        self.assertEqual(configuration()["safe-outputs"]["github-token"], token)
        compiled = yaml.load(
            (ROOT / ".github/workflows/repo-assist.lock.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        agent = compiled["jobs"]["agent"]
        self.assertTrue(all(value == "read" for value in agent["permissions"].values()))
        self.assertFalse(token in json.dumps(agent.get("env", {})))
        for step in agent["steps"]:
            self.assertNotIn(token, json.dumps(step), f"Publishing credential exposed to {step.get('name')}")
        names = [step.get("name") for step in agent["steps"]]
        self.assertLess(
            names.index("Checkout PR branch"), names.index("Clean credentials")
        )
        self.assertLess(
            names.index("Clean credentials"), names.index("Execute subscription Claude worker")
        )
        self.assertTrue(token in json.dumps(compiled["jobs"]["safe_outputs"]))
        publisher_checkout = next(
            step
            for step in compiled["jobs"]["safe_outputs"]["steps"]
            if step.get("uses", "").startswith("actions/checkout@")
        )
        self.assertEqual(publisher_checkout["with"]["token"], token)

    def test_daily_schedule_keeps_melbourne_wall_time(self) -> None:
        triggers = configuration()["on"]
        self.assertEqual(
            triggers["schedule"],
            [{"cron": "30 7 * * *", "timezone": "Australia/Melbourne"}],
        )
        self.assertIn("workflow_dispatch", triggers)
        self.assertNotIn("pull_request", triggers)
        self.assertNotIn("push", triggers)

    def preflight(
        self,
        *,
        authenticated: bool = True,
        count: int = 0,
        unrelated: int = 0,
        duplicate_path: str | None = None,
        inactive: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        script = configuration()["on"]["steps"][0]["run"]
        workflows = [
            {
                "name": "Repo Assist",
                "path": ".github/workflows/repo-assist.lock.yml",
                "state": "active",
            }
        ]
        validator = yaml.load(
            (ROOT / ".github/workflows/agentic-workflows.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        workflows.append(
            {
                "name": validator["name"],
                "path": ".github/workflows/agentic-workflows.yml",
                "state": "active",
            }
        )
        if duplicate_path:
            workflows.append(
                {
                    "name": "Daily Repo Assist",
                    "path": f".github/workflows/{duplicate_path}",
                    "state": "disabled_manually" if inactive else "active",
                }
            )
        with tempfile.TemporaryDirectory() as directory:
            fake_gh = Path(directory) / "gh"
            fake_gh.write_text(
                f"#!{sys.executable}\n"
                "import os, subprocess, sys\n"
                "command = sys.argv[1:3]\n"
                "if command == ['auth', 'status']:\n"
                "    sys.exit(0 if os.environ['AUTH_OK'] == '1' else 1)\n"
                "elif command == ['repo', 'view']:\n"
                "    print('{}')\n"
                "elif command == ['pr', 'list']:\n"
                "    count = int(os.environ['OPEN_PRS'])\n"
                "    labels = [sys.argv[i + 1] for i, arg in enumerate(sys.argv)\n"
                "              if arg == '--label']\n"
                "    if 'repo-assist' not in labels:\n"
                "        count += int(os.environ['UNRELATED_PRS'])\n"
                "    searches = [sys.argv[i + 1] for i, arg in enumerate(sys.argv)\n"
                "                if arg == '--search']\n"
                "    if 'in:title \"[repo-assist]\"' not in searches:\n"
                "        sys.exit(99)\n"
                "    print(count)\n"
                "elif command == ['workflow', 'list']:\n"
                "    query = sys.argv[sys.argv.index('--jq') + 1]\n"
                "    subprocess.run(['jq', query], input=os.environ['WORKFLOWS'],\n"
                "                   text=True, check=True)\n"
                "else:\n"
                "    sys.exit(99)\n"
            )
            fake_gh.chmod(0o700)
            return subprocess.run(
                ["bash", "-euo", "pipefail", "-c", script],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
                env={
                    **os.environ,
                    "PATH": f"{directory}:{os.environ['PATH']}",
                    "GITHUB_REPOSITORY": "Artic0din/Prismarr",
                    "AUTH_OK": "1" if authenticated else "0",
                    "OPEN_PRS": str(count),
                    "UNRELATED_PRS": str(unrelated),
                    "WORKFLOWS": json.dumps(workflows),
                },
            )

    def test_normal_run_passes_with_seven_open_prs(self) -> None:
        result = self.preflight(count=7)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_eight_open_prs_stop_before_agent_execution(self) -> None:
        result = self.preflight(count=8)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("8 or more open [repo-assist] PRs", result.stdout)

    def test_unlabelled_title_matches_do_not_consume_backlog(self) -> None:
        result = self.preflight(count=7, unrelated=8)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_authentication_stops_before_agent_execution(self) -> None:
        result = self.preflight(authenticated=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("gh CLI is not authenticated", result.stdout)

    def test_another_active_repo_assist_stops_execution(self) -> None:
        result = self.preflight(duplicate_path="repo-assist-old.lock.yml")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("another Repo Assist workflow", result.stdout)

    def test_disabled_old_workflow_does_not_block(self) -> None:
        result = self.preflight(
            duplicate_path="repo-assist-old.lock.yml", inactive=True
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_renamed_active_repo_assist_stops_execution(self) -> None:
        result = self.preflight(duplicate_path="daily-maintenance.yml")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("another Repo Assist workflow", result.stdout)

    def test_disabled_renamed_workflow_does_not_block(self) -> None:
        result = self.preflight(duplicate_path="daily-maintenance.yml", inactive=True)
        self.assertEqual(result.returncode, 0, result.stderr)


class GeneratedWorkflowTests(unittest.TestCase):
    def test_validation_runs_for_every_pull_request(self) -> None:
        config = yaml.load(
            (ROOT / ".github/workflows/ci.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        self.assertIn("pull_request", config["on"])
        self.assertIn("agentic-validation", config["jobs"]["ci-passed"]["needs"])
        self.assertEqual(
            config["jobs"]["agentic-validation"]["uses"],
            "./.github/workflows/agentic-workflows.yml",
        )
        script = config["jobs"]["ci-passed"]["steps"][0]["run"]
        for status in ("success", "failure", "skipped", "cancelled"):
            with self.subTest(status=status):
                result = subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", script],
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                    env={
                        **os.environ,
                        "CHECK_RESULT": "success",
                        "AGENTIC_RESULT": status,
                    },
                )
                self.assertEqual(result.returncode == 0, status == "success")

    def check_generated(
        self, *, untracked: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        config = yaml.load(
            (ROOT / ".github/workflows/agentic-workflows.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        step = next(
            step
            for step in config["jobs"]["validate"]["steps"]
            if step["name"] == "Verify generated Repo Assist workflow"
        )
        artifacts = [
            ".github/workflows/repo-assist.lock.yml",
            ".github/aw/actions-lock.json",
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet", directory], check=True)
            script = root / ".github/scripts/transform-repo-assist-subscription.py"
            script.parent.mkdir(parents=True)
            shutil.copy2(ROOT / ".github/scripts/transform-repo-assist-subscription.py", script)
            baseline = ROOT / ".github/tests/fixtures/repo-assist-subscription-input.yml"
            shutil.copy2(baseline, root / "compiler-output.yml")
            for artifact in artifacts:
                path = root / artifact
                path.parent.mkdir(parents=True, exist_ok=True)
                if artifact.endswith("repo-assist.lock.yml"):
                    shutil.copy2(baseline, path)
                    subprocess.run([sys.executable, str(script), str(path)], check=True)
                else:
                    path.write_text("generated\n")
                if artifact != untracked:
                    subprocess.run(["git", "add", artifact], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.com",
                    "commit",
                    "--quiet",
                    "-m",
                    "test: generated fixture",
                ],
                cwd=root,
                check=True,
            )
            compiler = root / "gh-aw-repo-assist"
            compiler.write_text('#!/bin/sh\ncp "$RUNNER_TEMP/compiler-output.yml" .github/workflows/repo-assist.lock.yml\n')
            compiler.chmod(0o700)
            return subprocess.run(
                ["bash", "-euo", "pipefail", "-c", step["run"]],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
                env={**os.environ, "RUNNER_TEMP": directory},
            )

    def test_tracked_unchanged_artifacts_pass(self) -> None:
        result = self.check_generated()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_recreated_untracked_artifacts_fail(self) -> None:
        for artifact in (
            ".github/workflows/repo-assist.lock.yml",
            ".github/aw/actions-lock.json",
        ):
            with self.subTest(artifact=artifact):
                result = self.check_generated(untracked=artifact)
                self.assertNotEqual(
                    result.returncode,
                    0,
                    "Uncommitted generated output passed validation",
                )


class ReportOwnershipTests(unittest.TestCase):
    def test_native_report_closing_comment_accepts_default_completed_reason(self) -> None:
        item = {
            "type": "close_issue", "issue_number": 42,
            "body": "Closing the previous monthly activity report because its calendar month ended.",
        }
        for compiled in (False, True):
            for fields in ({}, {"state_reason": "completed"}, {
                "repo": "Artic0din/Prismarr", "rationale": "Previous month completed",
                "confidence": "HIGH",
            }):
                with self.subTest(fields=fields, compiled=compiled):
                    result = self.run_guard({**item, **fields}, self.recorded_issue(), compiled=compiled)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_report_closing_comment_rejects_invalid_native_bodies(self) -> None:
        for fields in ({}, {"body": None}, {"body": 42}, {"body": []},
                       {"body": ""}, {"body": " \n\t"}):
            with self.subTest(fields=fields):
                result = self.run_guard(
                    {"type": "close_issue", "issue_number": 42, **fields},
                    self.recorded_issue(),
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Closing reports requires a nonblank string body", result.stderr)

    def test_closing_comment_preserves_publication_restrictions(self) -> None:
        item = {"type": "close_issue", "issue_number": 42, "body": "Previous month ended."}
        for fields, error in (
            ({"body": "Please @CLAUDE act on this"}, "privileged Claude workflow"),
            ({"state_reason": "not_planned"}, "only be closed as completed"),
            ({"state_reason": "duplicate", "duplicate_of": 99}, "unsupported fields"),
            ({"comment": "Unexpected comment"}, "unsupported fields"),
            ({"repo": "someone-else/example"}, "Cross-repository state updates"),
        ):
            with self.subTest(fields=fields):
                result = self.run_guard({**item, **fields}, self.recorded_issue())
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(error, result.stderr)

    def test_state_update_body_limit_accepts_exact_boundary(self) -> None:
        for size, allowed in ((60000, True), (60001, False)):
            with self.subTest(size=size):
                item = {
                    "type": "update_issue", "issue_number": 42,
                    "operation": "replace", "body": "a" * size,
                }
                result = self.run_guard(item, self.recorded_issue("2026-09"))
                self.assertEqual(result.returncode == 0, allowed, result.stderr)
                if not allowed:
                    self.assertIn("60000", result.stderr)

    def run_guard(
        self, item: dict | list[dict], issue: dict | list[list[dict]], *, pr: dict | None = None,
        now: str = "2026-09-08T00:00:00+00:00",
        compiled: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        workflow = (
            yaml.safe_load(WORKFLOW.with_suffix(".lock.yml").read_text())
            if compiled else configuration()
        )
        step = next(
            step for step in workflow["jobs"]["validate_updates"]["steps"]
            if step.get("name") == "Reject updates to nonautomation PRs"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "outputs.json"
            output.write_text(json.dumps({"items": item if isinstance(item, list) else [item]}))
            fake_gh = root / "gh"
            fake_gh.write_text(
                f"#!{sys.executable}\nimport os, sys\n"
                "expected = ['api', 'repos/Artic0din/Prismarr/issues/42']\n"
                "if sys.argv[1:] == ['api', '--paginate', '--slurp', 'repos/Artic0din/Prismarr/pulls/42/files?per_page=100']:\n"
                "    print(os.environ['FAKE_PR_FILES'])\n"
                "    sys.exit(0)\n"
                "if sys.argv[1:] == ['api', '--paginate', '--slurp', 'repos/Artic0din/Prismarr/issues?state=all&per_page=100']:\n"
                "    print(os.environ['FAKE_ISSUE'])\n"
                "    sys.exit(0)\n"
                "if sys.argv[1:] == expected:\n"
                "    print(os.environ['FAKE_ISSUE'])\n"
                "elif sys.argv[1:] == ['api', 'repos/Artic0din/Prismarr/actions/runs/1']:\n"
                "    print('{\"run_started_at\":\"2026-09-08T00:00:00Z\"}')\n"
                "else:\n"
                "    assert sys.argv[1:] == ['api', 'repos/Artic0din/Prismarr/pulls/42']\n"
                "    print(os.environ['FAKE_PR'])\n"
            )
            fake_gh.chmod(0o700)
            fake_python = root / "python3"
            fake_python.write_text(
                f"#!{sys.executable}\nimport datetime, os, sys\n"
                "real_datetime = datetime.datetime\n"
                "class FixedDatetime(real_datetime):\n"
                "    @classmethod\n"
                "    def now(cls, tz=None):\n"
                "        value = real_datetime.fromisoformat(os.environ['FAKE_NOW'])\n"
                "        return value.astimezone(tz) if tz is not None else value\n"
                "datetime.datetime = FixedDatetime\n"
                "exec(compile(sys.stdin.read(), '<publishing-guard>', 'exec'))\n"
            )
            fake_python.chmod(0o700)
            return subprocess.run(
                ["bash", "-euo", "pipefail", "-c", step["run"]],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
                env={
                    **os.environ,
                    "PATH": f"{directory}:{os.environ['PATH']}",
                    "GITHUB_REPOSITORY": "Artic0din/Prismarr",
                    "REPO_ASSIST_PUBLISHER": step["env"]["REPO_ASSIST_PUBLISHER"],
                    "REPO_ASSIST_OUTPUT": str(output),
                    "FAKE_ISSUE": json.dumps(issue),
                    "GITHUB_RUN_ID": "1",
                    "FAKE_PR": json.dumps(pr or {}),
                    "FAKE_PR_FILES": json.dumps((pr or {}).get("files", [[]])),
                    "FAKE_NOW": now,
                },
            )

    def test_state_creation_rejects_existing_and_duplicate_titles(self) -> None:
        for title in ("Memory", "Monthly Activity 2026-09"):
            item = {"type": "create_issue", "title": title, "body": self.memory_body()}
            full_title = f"[repo-assist] {title}"
            for pages, items, allowed in (
                ([[]], item, True),
                ([[], [{"title": full_title}]], item, False),
                ([[{"title": full_title, "pull_request": {}}]], item, True),
                ([[]], [item, {**item, "title": full_title}], False),
                ([[], [{"title": full_title, "state": "closed"}]], item, False),
            ):
                with self.subTest(title=title, pages=pages, items=items):
                    result = self.run_guard(items, pages)
                    self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def test_pr_updates_reject_existing_nondocumentation_changes(self) -> None:
        pr = {
            "head": {"ref": "repo-assist/docs", "repo": {"full_name": "Artic0din/Prismarr"}},
            "title": "docs: [repo-assist] guide",
            "labels": [{"name": "automation"}, {"name": "repo-assist"}],
        }
        for pages, total, allowed in (
            ([[{"filename": "README.md"}]], 1, True),
            ([[{"filename": "README.md"}], [{"filename": "docs/guide.md"}]], 2, True),
            ([[{"filename": "README.md"}], [{"filename": "symfony/src/Kernel.php"}]], 2, False),
            ([[{"filename": "docs/guide.md", "previous_filename": "symfony/src/Kernel.php"}]], 1, False),
            ([[{"filename": "README.md"}]], 2, False),
        ):
            with self.subTest(pages=pages, total=total):
                result = self.run_guard(
                    {"type": "push_to_pull_request_branch", "pull_request_number": 42},
                    {}, pr={**pr, "changed_files": total, "files": pages},
                )
                self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def memory_body(self) -> str:
        memory = {
            "cursor_issue_number": 0, "comments_made": {}, "fix_attempts": {},
            "ideas_submitted": [], "labelled": {}, "nudged_prs": {},
            "checked_off_actions": [], "todo": [], "notes": [], "pending_claims": {},
        }
        return chr(96) * 3 + "json\n" + json.dumps(memory) + "\n" + chr(96) * 3

    def test_memory_writes_require_valid_json_state(self) -> None:
        valid = self.memory_body()
        for body in (
            valid + "\n" + chr(96) * 3 + "json\n{",
            valid.replace('"notes": []', '"notes": [NaN]'),
            valid.replace('"notes": []', '"notes": [Infinity]'),
            valid.replace('"notes": []', '"notes": [-Infinity]'),
        ):
            with self.subTest(nonstandard=body):
                result = self.run_guard(
                    {"type": "create_issue", "title": "Memory", "body": body}, [[]]
                )
                self.assertNotEqual(result.returncode, 0)
        for body, allowed in (
            (valid, True), ("", False), ("plain text", False),
            (valid.replace('"cursor_issue_number": 0', '"cursor_issue_number": true'), False),
            (valid.replace('"cursor_issue_number": 0', '"cursor_issue_number": -1'), False),
            (valid.replace('"todo": []', '"todo": {}'), False),
            (valid.replace('"notes": []', '"notes": null'), False),
            (valid.replace('"comments_made": {}', '"comments_made": []'), False),
            (valid[:-2], False), (valid + "\n" + valid, False),
        ):
            for kind in ("create_issue", "update_issue"):
                with self.subTest(body=body, kind=kind):
                    item = {"type": kind, "body": body}
                    if kind == "create_issue":
                        item["title"] = "Memory"
                        issue = [[]]
                    else:
                        item.update(issue_number=42, operation="replace")
                        issue = {**self.recorded_issue(), "title": "[repo-assist] Memory"}
                    result = self.run_guard(item, issue)
                    self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def test_created_reports_use_current_month_and_pr_labels_are_bounded(self) -> None:
        for month, allowed in (("2026-09", True), ("2026-08", False), ("9999-12", False)):
            result = self.run_guard(
                {"type": "create_issue", "title": f"Monthly Activity {month}", "body": "Report"}, [[]]
            )
            self.assertEqual(result.returncode == 0, allowed, result.stderr)
        for labels, allowed in (
            ([], True), (["automation", "repo-assist"], True),
            (["automation", "repo-assist", "documentation"], False),
            (["testflight"], False), (["repo-assist", "deploy"], False),
            ("repo-assist", False), (None, False),
        ):
            result = self.run_guard(
                {"type": "create_pull_request", "title": "docs: [repo-assist] notes", "labels": labels},
                {},
            )
            self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def test_prompt_explicitly_forbids_extra_repo_assist_pr_labels(self) -> None:
        prompt = WORKFLOW.read_text()
        self.assertIn(
            "Pull requests are not an issue-triage surface; leave PR labels unchanged in this task, and never copy issue-triage labels such as `documentation` onto Repo Assist PRs.",
            prompt,
        )
        self.assertIn(
            "Label it exactly `automation` and `repo-assist`; do not add `documentation` or any other issue-triage label.",
            prompt,
        )
        self.assertIn(
            "Label every new Repo Assist PR exactly `automation` and `repo-assist`; never add issue-triage labels such as `documentation`.",
            prompt,
        )
        self.assertIn(
            "Label every new PR exactly `automation` and `repo-assist`; do not add `documentation` or any other issue-triage label.",
            prompt,
        )

    def test_prompt_drains_the_needs_triage_queue(self) -> None:
        prompt = WORKFLOW.read_text()
        for required in (
            "Task 1 is eligible when a filtered open issue is unlabelled or still labelled `needs-triage`",
            "Process issues that are unlabelled or still labelled `needs-triage`, "
            "resuming from `cursor_issue_number`.",
            "Triaging an issue means resolving its triage state: remove `needs-triage` and apply "
            "exactly one of `needs-info`, `ready-for-agent`, `ready-for-human`, or `wontfix`.",
        ):
            self.assertIn(required, prompt)
        # Issues arrive from the issue forms pre-labelled `bug` and `needs-triage`, so scoping
        # Task 1 to issues with no labels at all left the triage queue permanently undrained.
        for forbidden in (
            "filtered open issues with no labels",
            "all open issues already labelled",
            "Process unlabelled issues,",
        ):
            self.assertNotIn(forbidden, prompt)

    def test_published_bodies_cannot_invoke_the_privileged_claude_workflow(self) -> None:
        for kind in ("create_issue", "add_comment", "update_issue", "create_pull_request"):
            for body, allowed in (("Useful finding", True), ("Quote: @claude fix this", False),
                                  ("@CLAUDE fix this", False)):
                with self.subTest(kind=kind, body=body):
                    item = {"type": kind, "body": body}
                    issue = {"state": "open"}
                    if kind == "create_issue":
                        item["title"] = "Engineering finding"
                    elif kind == "add_comment":
                        item["item_number"] = 42
                    elif kind == "create_pull_request":
                        item["title"] = "docs: [repo-assist] finding"
                    else:
                        item.update(issue_number=42, operation="replace")
                        issue = {**self.recorded_issue(), "title": "[repo-assist] Monthly Activity 2026-09"}
                    result = self.run_guard(item, issue)
                    self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def test_report_replacements_only_target_the_current_month(self) -> None:
        for month, allowed in (
            ("2026-08", False), ("2026-09", True), ("2026-10", False),
        ):
            with self.subTest(month=month):
                result = self.run_guard(
                    {"type": "update_issue", "issue_number": 42,
                     "operation": "replace", "body": "Current activity"},
                    self.recorded_issue(month),
                )
                self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def recorded_issue(self, month: str = "2026-08") -> dict:
        publisher = configuration()["jobs"]["validate_updates"]["steps"][1]["env"]
        return {
            "title": f"[repo-assist] Monthly Activity {month}",
            "state": "open",
            "updated_at": "2026-08-01T00:00:00Z",
            "labels": [{"name": "repo-assist"}],
            "user": {"login": publisher["REPO_ASSIST_PUBLISHER"]},
            "body": "<!-- gh-aw-workflow-call-id: Artic0din/Prismarr/repo-assist -->"
            "\n<!-- gh-aw-workflow-id: repo-assist -->",
        }

    def test_state_replacements_reject_edits_since_the_run_started(self) -> None:
        item = {
            "type": "update_issue", "issue_number": 42,
            "operation": "replace", "body": "Agent replacement",
        }
        for updated_at, allowed in (
            ("2026-09-07T23:59:59Z", True),
            ("2026-09-08T00:00:00Z", False),
            ("2026-09-08T00:00:01Z", False),
            (None, False), ("invalid", False),
        ):
            with self.subTest(updated_at=updated_at):
                result = self.run_guard(
                    item, {**self.recorded_issue("2026-09"), "updated_at": updated_at}
                )
                self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def test_state_batches_reject_repeated_replacements_and_invalid_closures(self) -> None:
        update = {
            "type": "update_issue", "issue_number": 42,
            "body": "Final state", "operation": "replace",
        }
        current_report = self.recorded_issue("2026-09")
        single = self.run_guard(update, current_report)
        self.assertEqual(single.returncode, 0, single.stderr)
        result = self.run_guard([update, update], current_report)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Each state issue may be replaced only once per run", result.stderr)
        for fields, allowed in (
            ({}, True), ({"state_reason": "completed"}, True),
            ({"state_reason": "not_planned"}, False),
            ({"rationale": "Previous month completed", "confidence": "HIGH"}, True),
            (
                {
                    "state_reason": "completed",
                    "body": (
                        "🤖 *Repo Assist closing this September 2026 activity issue — "
                        "the calendar month has ended.*"
                    ),
                },
                True,
            ),
            ({"state_reason": "duplicate", "duplicate_of": 99}, False),
            ({"comment": "Unexpected comment"}, False),
            ({"body": 42}, False),
        ):
            with self.subTest(fields=fields):
                result = self.run_guard(
                    {"type": "close_issue", "issue_number": 42, "body": "Previous month ended.", **fields},
                    self.recorded_issue(),
                )
                self.assertEqual(result.returncode == 0, allowed, result.stderr)
        result = self.run_guard(
            {"type": "close_issue", "issue_number": 42, "body": "Previous month ended."},
            {**self.recorded_issue(), "updated_at": "2026-09-08T00:00:01Z"},
        )
        self.assertNotEqual(result.returncode, 0)

    def test_closed_state_cannot_be_updated_or_closed_again(self) -> None:
        for kind in ("update_issue", "close_issue"):
            item = {"type": kind, "issue_number": 42, "body": "Previous month ended."}
            if kind == "update_issue":
                item.update(body=self.memory_body(), operation="replace")
            for state in ("closed", None):
                with self.subTest(kind=kind, state=state):
                    result = self.run_guard(item, {**self.recorded_issue(), "state": state})
                    self.assertNotEqual(result.returncode, 0)

    def test_report_closure_observes_melbourne_month_boundaries(self) -> None:
        cases = (
            ("2026-08", "2026-08-31T13:59:00+00:00", False),
            ("2026-08", "2026-08-31T14:00:00+00:00", True),
            ("2026-10", "2026-10-31T12:59:00+00:00", False),
            ("2026-10", "2026-10-31T13:00:00+00:00", True),
            ("9999-12", "2026-09-08T00:00:00+00:00", False),
        )
        for month, now, allowed in cases:
            with self.subTest(month=month, now=now):
                issue = {**self.recorded_issue(), "title": f"[repo-assist] Monthly Activity {month}"}
                result = self.run_guard(
                    {"type": "close_issue", "issue_number": 42, "body": "Previous month ended."},
                    issue, now=now,
                )
                self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def test_label_changes_only_target_open_issues(self) -> None:
        for kind in ("add_labels", "remove_labels"):
            for fields, allowed in (
                ({}, True), ({"pull_request": {}}, False), ({"state": "closed"}, False),
            ):
                with self.subTest(kind=kind, fields=fields):
                    result = self.run_guard(
                        {"type": kind, "item_number": 42, "labels": ["bug"]},
                        {"state": "open", **fields},
                    )
                    self.assertEqual(result.returncode == 0, allowed, result.stderr)

    def test_comment_nudges_have_a_separate_three_pr_budget(self) -> None:
        owned = {
            "head": {"ref": "repo-assist/fix", "repo": {"full_name": "Artic0din/Prismarr"}},
            "title": "fix(test): [repo-assist] example",
            "labels": [{"name": "automation"}, {"name": "repo-assist"}],
        }
        comment = {"type": "add_comment", "item_number": 42, "body": "Useful comment"}
        for count, target_is_pr, target, allowed in (
            (3, True, {}, True), (4, True, {}, False),
            (4, True, owned, True), (10, False, {}, True),
        ):
            with self.subTest(count=count, target_is_pr=target_is_pr, owned=bool(target)):
                issue = {"state": "open", **({"pull_request": {}} if target_is_pr else {})}
                result = self.run_guard([comment] * count, issue, pr=target)
                self.assertEqual(result.returncode == 0, allowed, result.stderr)
        for changes in ({"comment_id": 7}, {"pr_number": 9}, {"item_number": None}):
            result = self.run_guard({**comment, **changes}, {"state": "open"})
            self.assertNotEqual(result.returncode, 0)

    def test_closure_requires_the_recorded_report_publisher_and_markers(self) -> None:
        valid = self.recorded_issue()
        cases = (
            (valid, True),
            ({**valid, "title": "[repo-assist] Memory"}, True),
            ({**valid, "labels": []}, False),
            ({**valid, "title": valid["title"] + " discussion"}, False),
            ({**valid, "body": "A human report discussion"}, False),
            ({**valid, "user": {"login": "someone-else"}}, False),
            ({**valid, "pull_request": {}}, False),
        )
        for kind, issue, allowed in (
            (kind, issue, allowed)
            for kind in ("close_issue", "update_issue")
            for issue, allowed in cases
        ):
            with self.subTest(kind=kind, issue=issue):
                item = {"type": kind, "issue_number": 42, "body": "Previous month ended."}
                candidate_issue = issue
                if kind == "update_issue":
                    item.update(body=self.memory_body(), operation="replace")
                    if issue["title"] == valid["title"]:
                        candidate_issue = {
                            **issue, "title": "[repo-assist] Monthly Activity 2026-09",
                        }
                result = self.run_guard(item, candidate_issue)
                expected = allowed and not (
                    kind == "close_issue" and issue["title"] == "[repo-assist] Memory"
                )
                self.assertEqual(result.returncode == 0, expected, result.stderr)

    def test_consecutive_replacements_accept_the_native_retained_marker(self) -> None:
        self.assertEqual(configuration()["safe-outputs"]["update-issue"]["footer"], "false")
        issue = self.recorded_issue("2026-09")
        for generation in (1, 2):
            body = f"Updated state {generation}"
            result = self.run_guard(
                {"type": "update_issue", "issue_number": 42,
                 "operation": "replace", "body": body}, issue,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            # Native gh-aw replacement with footer disabled retains this marker.
            issue["body"] = body + "\n\n<!-- gh-aw-workflow-id: repo-assist -->"

    def test_state_updates_only_replace_a_string_body(self) -> None:
        valid = {
            "type": "update_issue", "issue_number": 42,
            "body": self.memory_body(), "operation": "replace",
        }
        cases = [({}, True)] + [(fields, False) for fields in (
            {"title": "Renamed"}, {"status": "closed"}, {"state": "closed"},
            {"labels": []}, {"assignees": []}, {"milestone": 1},
            {"operation": "append"}, {"operation": "prepend"},
            {"operation": None}, {"body": None}, {"body": {}},
        )]
        for title in ("[repo-assist] Memory", "[repo-assist] Monthly Activity 2026-09"):
            for fields, allowed in cases:
                with self.subTest(title=title, fields=fields):
                    result = self.run_guard(
                        {**valid, **fields}, {**self.recorded_issue(), "title": title}
                    )
                    self.assertEqual(result.returncode == 0, allowed, result.stderr)
            for missing in ("operation", "body"):
                item = {key: value for key, value in valid.items() if key != missing}
                result = self.run_guard(item, {**self.recorded_issue(), "title": title})
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
