"""Prove the guarded subscription overlay retains the native publication contract."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github/scripts/transform-repo-assist-subscription.py"
FIXTURE = ROOT / ".github/tests/fixtures/repo-assist-subscription-input.yml"


def parsed(text):
    return yaml.load(text, Loader=yaml.BaseLoader)


def raw_job(text, name):
    tree = yaml.compose(text)
    jobs = next(value for key, value in tree.value if key.value == "jobs")
    for index, (key, value) in enumerate(jobs.value):
        if key.value == name:
            end = jobs.value[index + 1][0].start_mark.line if index + 1 < len(jobs.value) else len(text.splitlines())
            return "".join(text.splitlines(keepends=True)[key.start_mark.line:end])
    raise AssertionError(name)


def detection_step_spans(source):
    """Locate native step blocks without changing YAML types or formatting."""
    tree = yaml.compose(source)
    jobs = next(value for key, value in tree.value if key.value == "jobs")
    detection = next(value for key, value in jobs.value if key.value == "detection")
    steps = next(value for key, value in detection.value if key.value == "steps")
    return {
        next(value.value for key, value in step.value if key.value == "name"):
        (step.start_mark.line, step.end_mark.line)
        for step in steps.value
    }


class SubscriptionTransformTests(unittest.TestCase):
    def test_native_converter_keeps_surviving_http_safeoutputs_configuration(self):
        final = parsed(self.transform())
        step = next(step for step in final['jobs']['agent']['steps'] if step['name'] == 'Start MCP Gateway')
        self.assertEqual(step['env'].get('GH_AW_MCP_CLI_SERVERS'), '[]')
        compiler = Path(os.environ.get('REPO_ASSIST_COMPILER_SOURCE', ROOT / '.repo-assist-compiler'))
        converter = compiler / 'actions/setup/js/convert_gateway_config_claude.cjs'
        self.assertTrue(converter.is_file(), 'Pinned native converter is required')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gateway = root / 'gateway-output.json'
            gateway.write_text(json.dumps({'mcpServers': {'safeoutputs': {
                'url': 'http://localhost:8080/mcp/safeoutputs', 'tools': ['*'],
                'headers': {'Authorization': 'synthetic-mcp-capability'}}}}))
            result = subprocess.run(['node', str(converter)], capture_output=True, text=True,
                env={**os.environ, 'MCP_GATEWAY_OUTPUT': str(gateway), 'MCP_GATEWAY_DOMAIN': 'awmg-mcpg',
                     'MCP_GATEWAY_PORT': '8080', 'GH_AW_MCP_CLI_SERVERS': step['env']['GH_AW_MCP_CLI_SERVERS'],
                     'RUNNER_TEMP': str(root)}, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            gateway.unlink()  # Native setup removes this transient file.
            config = json.loads((root / 'gh-aw/mcp-config/mcp-servers.json').read_text())
            self.assertEqual(config, {'mcpServers': {'safeoutputs': {'type': 'http',
                'url': 'http://awmg-mcpg:8080/mcp/safeoutputs',
                'headers': {'Authorization': 'synthetic-mcp-capability'}}}})

    def transform(self, text=None, allowed=True):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "repo-assist.lock.yml"
            original = FIXTURE.read_text() if text is None else text
            path.write_text(original)
            result = subprocess.run([sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode == 0, allowed, result.stderr)
            actual = path.read_text()
            if not allowed:
                self.assertEqual(actual, original, "Rejected input must remain untouched")
            return actual

    def test_preserves_publisher_ownership_schedule_and_agent_images_byte_for_byte(self):
        before = FIXTURE.read_text()
        after = self.transform()
        for job in ("safe_outputs", "validate_updates"):
            expected = raw_job(before, job)
            if job == "safe_outputs":
                header, rest = expected.split("\n", 1)
                expected = header + "\n    environment: repo-assist-publisher\n" + rest
            self.assertEqual(expected, raw_job(after, job))
        baseline, final = parsed(before), parsed(after)
        original_conclusion = baseline["jobs"]["conclusion"]
        actual_conclusion = final["jobs"]["conclusion"]
        expected_conclusion = json.loads(json.dumps(original_conclusion).replace(
            "secrets.REPO_ASSIST_GITHUB_TOKEN", "github.token"))
        expected_conclusion["permissions"] = {"contents": "read"}
        logger = next(step for step in expected_conclusion["steps"] if step.get("name") == "Log detection run")
        logger["with"]["script"] = (
            "core.info('Independent detection: ' + JSON.stringify({\n"
            "  conclusion: process.env.GH_AW_DETECTION_CONCLUSION || 'unavailable',\n"
            "  reason: process.env.GH_AW_DETECTION_REASON || '',\n"
            "}));\n"
        )
        self.assertEqual(actual_conclusion, expected_conclusion)
        for key in ("on", "concurrency", "permissions"):
            self.assertEqual(baseline[key], final[key])
        image_step = lambda data: next(s for s in data["jobs"]["agent"]["steps"] if s.get("name") == "Download container images")
        self.assertEqual(image_step(baseline), image_step(final))

    def test_oauth_only_three_recipients_and_never_publisher_token_in_agent(self):
        final = parsed(self.transform())
        recipients = []
        for phase, job in final["jobs"].items():
            if phase in ("agent", "detection"):
                self.assertEqual(job["environment"], "repo-assist")
                self.assertNotIn("REPO_ASSIST_GITHUB_TOKEN", json.dumps(job))
            for step in job.get("steps", []):
                if "secrets.CLAUDE_CODE_OAUTH_TOKEN" in json.dumps(step):
                    recipients.append((phase, step.get("id", step["name"])))
        self.assertEqual(recipients, [("agent", "agentic_execution"), ("agent", "collect_output"), ("detection", "detection_agentic_execution")])
        self.assertNotIn("ANTHROPIC_API_KEY", json.dumps(final))

    def test_preserves_native_detector_failure_contract(self):
        baseline, final = parsed(FIXTURE.read_text()), parsed(self.transform())
        original, actual = baseline["jobs"]["detection"], final["jobs"]["detection"]
        for key in ("needs", "if", "outputs", "timeout-minutes"):
            self.assertEqual(original[key], actual[key])
        by_id = lambda job, key: next(s for s in job["steps"] if s.get("id") == key)
        for key in ("threat_detect_install", "detection_conclusion", "detection_guard"):
            self.assertEqual(by_id(original, key), by_id(actual, key))
        for key in ("if", "continue-on-error", "timeout-minutes"):
            self.assertEqual(by_id(original, "detection_agentic_execution")[key], by_id(actual, "detection_agentic_execution")[key])

    def test_detector_usage_summary_does_not_invent_empty_accounting(self):
        original = parsed(FIXTURE.read_text())["jobs"]["detection"]["steps"]
        final = parsed(self.transform())["jobs"]["detection"]["steps"]
        expected = next(step for step in original if step.get("id") == "parse_detection_token_usage")
        expected["env"]["GH_AW_WRITE_EMPTY_USAGE"] = "false"
        actual = next(step for step in final if step.get("id") == "parse_detection_token_usage")
        self.assertEqual(actual, expected)

    def test_rejects_injected_detector_step_before_verdict_conclusion(self):
        source = FIXTURE.read_text()
        injected = (
            "      - name: Rewrite detector verdict\n"
            "        run: printf '{}\\n' > /tmp/gh-aw/threat-detection/detection_result.json\n"
        )
        self.transform(source.replace("      - name: Conclude threat detection", injected + "      - name: Conclude threat detection", 1), allowed=False)

    def test_rejects_changed_unselected_detector_step_body(self):
        source = FIXTURE.read_text()
        lines = source.splitlines(keepends=True)
        start, end = detection_step_spans(source)["Render detection log"]
        lines[start:end] = [
            "      - name: Render detection log\n"
            "        run: printf '{}\\n' > /tmp/gh-aw/threat-detection/detection_result.json\n"
        ]
        self.transform("".join(lines), allowed=False)

    def test_rejects_removed_unselected_detector_step(self):
        source = FIXTURE.read_text()
        lines = source.splitlines(keepends=True)
        start, end = detection_step_spans(source)["Clear MCP Config for detection"]
        del lines[start:end]
        self.transform("".join(lines), allowed=False)

    def test_rejects_reordered_unmodified_detector_steps(self):
        source = FIXTURE.read_text()
        lines = source.splitlines(keepends=True)
        spans = detection_step_spans(source)
        first_start, first_end = spans["Clear inherited Copilot session state"]
        second_start, second_end = spans["Clean stale firewall files from agent artifact"]
        self.assertEqual(first_end, second_start)
        lines[first_start:second_end] = lines[second_start:second_end] + lines[first_start:first_end]
        self.transform("".join(lines), allowed=False)

    def test_rejects_changed_unselected_detector_action_configuration(self):
        source = FIXTURE.read_text()
        lines = source.splitlines(keepends=True)
        start, end = detection_step_spans(source)["Upload threat detection artifact"]
        block = "".join(lines[start:end])
        self.assertIn("/tmp/gh-aw/threat-detection/", block)
        lines[start:end] = [block.replace("/tmp/gh-aw/threat-detection/", "/tmp/unreviewed-detection/", 1)]
        self.transform("".join(lines), allowed=False)

    def test_rejects_changed_detector_usage_summary_anchor(self):
        source = FIXTURE.read_text().replace("name: Parse threat detection token usage for step summary", "name: Changed usage summary", 1)
        self.transform(source, allowed=False)

    def test_trusted_staging_precedes_pr_checkout_and_install_has_no_secret(self):
        final = parsed(self.transform())
        self.assertEqual(final["jobs"]["pre_activation"]["if"], "github.ref == 'refs/heads/main' && github.repository == 'Artic0din/Prismarr'")
        for phase, identifier in (("agent", "agentic_execution"), ("detection", "detection_agentic_execution")):
            steps = final["jobs"][phase]["steps"]
            names = [s.get("name") for s in steps]
            execution = next(s for s in steps if s.get("id") == identifier)
            self.assertEqual(execution["run"].strip(), f'python3 "$RUNNER_TEMP/repo-assist-trusted/repo-assist-worker.py" {phase}')
            self.assertNotIn("GH_TOKEN", execution["env"])
            checkout = next(s for s in steps if s.get("uses", "").startswith("actions/checkout@"))
            self.assertEqual(checkout["with"]["ref"], "${{ github.sha }}")
            self.assertNotIn("if", checkout)
            stage = names.index("Stage trusted subscription worker")
            self.assertIn('python3 "$RUNNER_TEMP/repo-assist-trusted/tool_prerequisites.py" "$RUNNER_TOOL_CACHE"',
                          steps[stage]["run"])
            install = names.index("Install locked Claude Code CLI")
            self.assertLess(stage, install)
            self.assertLess(install, steps.index(execution))
            if phase == "agent":
                self.assertLess(stage, names.index("Checkout PR branch"))
                self.assertEqual(execution["env"]["REPO_ASSIST_READ_TOKEN"], "${{ github.token }}")
                self.assertLess(names.index("Stop MCP Gateway"), names.index("Ingest agent output"))
            for index in (stage, install):
                self.assertNotIn("secrets.", json.dumps(steps[index]))
                self.assertNotEqual(steps[index].get("continue-on-error"), "true")
            self.assertEqual(steps[install]["run"], 'npm ci --prefix "$RUNNER_TEMP/repo-assist-cli" --no-audit --no-fund')
            self.assertNotIn("Install AWF binary", names)
            self.assertNotIn("Prepare writable API proxy reflection artifact", names)

    def test_ingestion_preserves_native_body_between_exact_token_guards(self):
        original = parsed(FIXTURE.read_text())["jobs"]["agent"]["steps"]
        steps = parsed(self.transform())["jobs"]["agent"]["steps"]
        baseline = next(step for step in original if step.get("id") == "collect_output")
        actual = next(step for step in steps if step.get("id") == "collect_output")
        self.assertEqual(actual["id"], "collect_output")
        self.assertEqual(actual["uses"], baseline["uses"])
        self.assertEqual(actual["if"], baseline["if"])
        self.assertNotEqual(actual.get("continue-on-error"), "true")
        for name, value in baseline["env"].items():
            self.assertEqual(actual["env"][name], value)
        self.assertEqual(actual["env"]["SECRET_CLAUDE_CODE_OAUTH_TOKEN"], "${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}")
        script = actual["with"]["script"]
        native = baseline["with"]["script"]
        self.assertEqual(script.count(native), 1)
        self.assertEqual(script.count("await guardPublication();"), 2)
        self.assertLess(script.index("redact_secrets.cjs"), script.index("await guardPublication();"))
        self.assertLess(script.index("await guardPublication();"), script.index(native))
        self.assertLess(script.index(native) + len(native), script.rindex("await guardPublication();"))
        self.assertIn("publication_guard.py", script)
        self.assertIn("--workspace", script)
        self.assertIn("--native-artifact-dir", script)
        self.assertIn("--safeoutputs", script)
        self.assertNotIn("--artifact-root", script)
        self.assertIn("--scratch-parent", script)
        self.assertNotIn("Redact secrets in logs", [step.get("name") for step in steps])

    def test_summaries_and_uploads_require_successful_post_ingestion_guard(self):
        steps = parsed(self.transform())["jobs"]["agent"]["steps"]
        names = [step.get("name") for step in steps]
        collector = names.index("Ingest agent output")
        self.assertLess(names.index("Stop CLI Proxy"), collector)
        self.assertLess(names.index("Stop MCP Gateway"), collector)
        self.assertLess(names.index("Copy Safe Outputs"), collector)
        gated = ("Detect agent errors", "Append agent step summary", "Parse agent logs for step summary",
                 "Parse MCP Gateway logs for step summary", "Parse token usage for step summary",
                 "Generate observability summary", "Write agent output placeholder if missing",
                 "Upload agent output fallback artifact", "Upload agent artifacts")
        for name in gated:
            self.assertGreater(names.index(name), collector, name)
            self.assertEqual(steps[names.index(name)]["if"], "always() && steps.collect_output.outcome == 'success'", name)
        uploads = [step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@")]
        self.assertEqual(len(uploads), 2)
        for step in uploads:
            self.assertIn("steps.collect_output.outcome == 'success'", step["if"])

    def test_combined_gate_aborts_on_each_guard_or_native_ingest_failure(self):
        step = next(s for s in parsed(self.transform())["jobs"]["agent"]["steps"] if s.get("id") == "collect_output")
        harness = r"""
const payload = JSON.parse(process.argv[1]);
const events = []; let calls = 0; let failed = false;
const nativeRequire = require;
function fakeRequire(name) {
  if (name === 'path') return nativeRequire(name);
  if (name.endsWith('setup_globals.cjs')) return {setupGlobals() {}};
  if (name.endsWith('redact_secrets.cjs')) return {async main() { events.push('redact'); }};
  if (name.endsWith('collect_ndjson_output.cjs')) return {async main() {
    events.push('ingest'); if (payload.failure === 'ingest') throw Error('blocked');
  }};
  throw Error('Unexpected require');
}
const exec = {async getExecOutput(command, args, options) {
  events.push('quiescence');
  if (command !== 'docker' || JSON.stringify(args) !== JSON.stringify(['ps', '--quiet']) || options.silent !== true) throw Error('Bad quiescence command');
  if (payload.failure === 'docker') throw Error('Docker unavailable');
  return {exitCode: payload.failure === 'docker_nonzero' ? 1 : 0, stdout: payload.failure === 'running' ? 'a123\n' : '', stderr: ''};
}, async exec(command, args, options) {
  const expected = ['/trusted/repo-assist-trusted/publication_guard.py', '--workspace', '/workspace', '--native-artifact-dir', '/tmp/gh-aw', '--safeoutputs', '/trusted/gh-aw/safeoutputs', '--scratch-parent', '/trusted'];
  if (command !== 'python3' || JSON.stringify(args) !== JSON.stringify(expected) || options.silent !== true) throw Error('Bad guard command');
  calls += 1; events.push('guard' + calls);
  if (payload.failure === 'guard' + calls) throw Error('blocked');
}};
const AsyncFunction = Object.getPrototypeOf(async function() {}).constructor;
(async () => {
  try { await new AsyncFunction('require', 'core', 'github', 'context', 'exec', 'io', 'getOctokit', payload.script)(fakeRequire, {}, {}, {}, exec, {}, {}); }
  catch { failed = true; }
  process.stdout.write(JSON.stringify({events, failed}));
})().catch(() => process.exit(1));
"""
        for failure, expected in (("none", ["quiescence", "redact", "guard1", "ingest", "guard2"]),
                                  ("docker", ["quiescence"]),
                                  ("docker_nonzero", ["quiescence"]),
                                  ("running", ["quiescence"]),
                                  ("guard1", ["quiescence", "redact", "guard1"]),
                                  ("ingest", ["quiescence", "redact", "guard1", "ingest"]),
                                  ("guard2", ["quiescence", "redact", "guard1", "ingest", "guard2"])):
            with self.subTest(failure=failure):
                result = subprocess.run(["node", "-e", harness, json.dumps({"script": step["with"]["script"], "failure": failure})],
                                        env={"PATH": os.environ["PATH"], "RUNNER_TEMP": "/trusted", "GITHUB_WORKSPACE": "/workspace"},
                                        capture_output=True, text=True, check=True)
                self.assertEqual(json.loads(result.stdout), {"events": expected, "failed": failure != "none"})

    def test_rejects_new_step_before_ingestion(self):
        source = FIXTURE.read_text().replace("      - name: Ingest agent output", "      - name: Unreviewed artifact upload\n        run: echo unsafe\n      - name: Ingest agent output", 1)
        self.transform(source, allowed=False)

    def test_rejects_changed_ingestion_or_summary_anchor(self):
        for name in ("Ingest agent output", "Detect agent errors", "Append agent step summary", "Upload agent artifacts"):
            with self.subTest(name=name):
                self.transform(FIXTURE.read_text().replace("name: " + name, "name: Changed " + name, 1), allowed=False)

    def test_deterministic_output_from_fresh_compilation(self):
        self.assertEqual(self.transform(), self.transform())

    def test_rejects_unreviewed_behavior_anywhere_in_original_workflow(self):
        source = FIXTURE.read_text()
        lines = source.splitlines(keepends=True)
        def node(*keys):
            current = yaml.compose(source)
            for key in keys:
                current = next(value for name, value in current.value if name.value == key)
            return current
        def insert(line, text):
            return "".join(lines[:line]) + text + "".join(lines[line:])
        cases = {}
        for job in ("conclusion", "safe_outputs", "validate_updates"):
            cases[f"{job} inserted executable step"] = insert(
                node("jobs", job, "steps").end_mark.line,
                "      - name: Unreviewed executable step\n        run: echo unreviewed\n",
            )
        prep = next(step for step in node("jobs", "agent", "steps").value
                    if any(key.value == "name" and value.value == "Install commit and workflow validation tools"
                           for key, value in step.value))
        cases["agent pre-execution body"] = (
            "".join(lines[:prep.start_mark.line])
            + "      - name: Install commit and workflow validation tools\n        run: echo unreviewed\n"
            + "".join(lines[prep.end_mark.line:])
        )
        cases["agent job environment"] = insert(node("jobs", "agent", "env").end_mark.line, "      UNREVIEWED: enabled\n")
        permissions = node("jobs", "agent", "permissions")
        permission_block = "".join(lines[permissions.start_mark.line:permissions.end_mark.line])
        self.assertIn("contents: read", permission_block)
        cases["agent job permissions"] = (
            "".join(lines[:permissions.start_mark.line])
            + permission_block.replace("contents: read", "contents: write", 1)
            + "".join(lines[permissions.end_mark.line:])
        )
        cases["top-level environment"] = insert(node("env").end_mark.line, "  UNREVIEWED: enabled\n")
        cases["top-level permissions"] = source.replace("permissions: {}", "permissions:\n  contents: write", 1)
        cases["top-level concurrency"] = source.replace("concurrency:\n  cancel-in-progress: false", "concurrency:\n  cancel-in-progress: true", 1)
        for description, mutated in cases.items():
            with self.subTest(description=description):
                self.assertNotEqual(mutated, source)
                self.transform(mutated, allowed=False)

    def test_comment_only_changes_keep_the_same_semantic_output(self):
        source = "# Additional review comment; no behavior change.\n" + FIXTURE.read_text()
        self.assertEqual(parsed(self.transform(source)), parsed(self.transform()))

    def test_rejects_repeated_transform(self):
        self.transform(self.transform(), allowed=False)

    def test_rejects_changed_execution_anchor(self):
        self.transform(FIXTURE.read_text().replace("name: Execute Claude Code CLI", "name: Changed execution"), allowed=False)

    def test_rejects_changed_step_contents(self):
        self.transform(FIXTURE.read_text().replace("npm install -g @anthropic-ai/claude-code@2.1.273", "npm install -g @anthropic-ai/claude-code@2.1.274", 1), allowed=False)

    def test_rejects_changed_native_image_download(self):
        self.transform(FIXTURE.read_text().replace("bash \"${RUNNER_TEMP}/gh-aw/actions/download_docker_images.sh\"", "bash changed-download.sh", 1), allowed=False)

    def test_rejects_extra_root_job(self):
        self.transform(FIXTURE.read_text() + "  unauthorized:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo unsafe\n", allowed=False)

    def test_rejects_changed_dependency_gate(self):
        self.transform(FIXTURE.read_text().replace("needs: pre_activation", "needs: agent", 1), allowed=False)

    def test_rejects_secret_in_job_environment(self):
        self.transform(FIXTURE.read_text().replace("  agent:\n", "  agent:\n    env:\n      TOKEN: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}\n", 1), allowed=False)

    def test_rejects_extra_oauth_recipient(self):
        self.transform(FIXTURE.read_text().replace("env:\n", "env:\n  TOKEN: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}\n", 1), allowed=False)

    def test_rejects_unreviewed_compiler(self):
        self.transform(FIXTURE.read_text().replace('"compiler_version":"v0.90.0"', '"compiler_version":"v0.90.1"'), allowed=False)


if __name__ == "__main__":
    unittest.main()
