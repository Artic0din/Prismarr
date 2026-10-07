#!/usr/bin/env python3
"""Apply Prismarr's reviewed OAuth worker overlay to a freshly compiled gh-aw lock.

This is intentionally not a general workflow rewriter. Changed upstream anchors
or gates require review and new fingerprints. The publisher receives only a
dedicated environment field; its steps and the ownership job stay unchanged.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

import yaml

MARKER = "# repo-assist-subscription-transform: v1"
COMPILER_VERSION = "v0.90.0"
OAUTH = "${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}"
AGENT_IMAGE = "ghcr.io/github/gh-aw-firewall/agent:0.28.27@sha256:8d14865f96d57d9b4f22b30b3e148d2d926384f0aa543a139f15593e450f0e90"

# Fingerprints of the reviewed, untransformed Prismarr compiler fixture.
# Never learn these from the input.
# Complete semantic input, verified against a fresh pinned-compiler run.
# Comments may change; every runtime field requires explicit review.
REVIEWED_WORKFLOW = "d56a998b5156c9d763f52478bb28936bf11ae15358304604b09918a0072e834b"
REVIEWED_GATES = "4b7bb30b8fdc7b9eca3fd715cd0e338bc10f52472588524a90ff4fbdb2aa8cce"
REVIEWED_STEP_NAMES = [
    "activation:Validate ANTHROPIC_API_KEY secret",
    "agent:Checkout repository",
    "agent:Checkout PR branch",
    "agent:Install AWF binary",
    "agent:Install Claude Code CLI",
    "agent:Prepare writable API proxy reflection artifact",
    "agent:Download container images",
    "agent:Execute Claude Code CLI",
    "agent:Print firewall logs",
    "agent:Print AWF reflect summary",
    "agent:Redact secrets in logs",
    "detection:Checkout repository for patch context",
    "detection:Install AWF binary",
    "detection:Install Claude Code CLI",
    "detection:Prepare writable API proxy reflection artifact",
    "detection:Download container images",
    "detection:Execute threat detection with AWF",
    "detection:Copy detection firewall logs",
    "detection:Install threat-detect binary",
    "detection:Conclude threat detection",
    "agent:Ingest agent output",
    "agent:Detect agent errors",
    "agent:Append agent step summary",
    "agent:Parse agent logs for step summary",
    "agent:Parse MCP Gateway logs for step summary",
    "agent:Parse token usage for step summary",
    "agent:Generate observability summary",
    "agent:Write agent output placeholder if missing",
    "agent:Upload agent output fallback artifact",
    "agent:Upload agent artifacts",
    "detection:Parse threat detection token usage for step summary",
    "agent:Start MCP Gateway"
]
REVIEWED_STEP_DIGESTS = [
    "c7c8390c2468f3a5f1999e864551e1c01af9c74fbe47ea5dd37c97c4235ceda9",
    "caccfd1937081ee7b7aff5136684f6ed4ce8ef0ddd45eefd8204f50e4651662c",
    "557566f240afe4f06d13676a44520a834eca92d21de2ca77a50bc72e21659a82",
    "7d39d2465dc5b467312e8e3aba76d2b87715c01aeffb933331ce6358ccd10fde",
    "ea7014d3a0e6f0da393b30c1a1f566f69150755abc55b3dcee1157f6476e610c",
    "48d93f7df8e93fa5afdce985824fbe45803b2c6a90c64736bf6cf3213178632b",
    "89d14dd360b3b4863cb07ab153ec994e2a1966dfba86e53d9ddaf6246055bf60",
    "7a3e89729ca17e3ba780ab7ed02e99e09036a164c000dc00fadf1a033dcea507",
    "07a8ded4d12d3cc6b72e779f5dd9c58c60d20560df47e8a7d1ecbf72f178cdf5",
    "3b65c5a32a6e9d105d4d7d93e4881265d5aa9754236e2093420bdd9eac0dd6f7",
    "01506ac46e537c21a7582380d3fb47794a033ad63fc0a88a85d5c779708ac4a7",
    "f7bca478bb50bb3338afc3b265ba5c1b2e1c642239f55ab1290f57a789fe8a7d",
    "7d39d2465dc5b467312e8e3aba76d2b87715c01aeffb933331ce6358ccd10fde",
    "ea7014d3a0e6f0da393b30c1a1f566f69150755abc55b3dcee1157f6476e610c",
    "c9b01d2c9c3b665dff6685d2ba035eebb9894ef0562f2b097840b296b6ad9728",
    "4a63347b7e55ccfe939d3651f802f2a4582cf0cf578d5857e8a874cf02b9157e",
    "0ffeb97785ef66057c6fdb177e468b5609a586a4beafd781c860e70fc2c71191",
    "5939c4c07959ae3a62d81b9a5cee10c48cdd535dd9a6094f50d3ba1163eb6cfe",
    "b0ebbcb278f174f8ca5f1d0778b0c06651172895c0ff88136006b78ae0d40088",
    "db42b65c684107ace0b0c5833c9babb185e0c7daa8c8e66acfbfd00361d2fe21",
    "90d0a8e28cf040cde961b76a5e002b46924412e8ee8056a22d6f2d22a100d821",
    "d958b7e3d33c7e00e0803d98750338c049c5dc44f093bb161bf1de0e07fcf7a3",
    "1a7126e8b7816434907fdbe6a86d2acfb26dc6b681f436d4be4f2e1e7584fb9e",
    "f75ec619feda88377c87ca583ca5433e84f519623681fdb043d71e77ba3c643a",
    "0c43170aeac84d5870e2049b4b93293de4327b2795b3075ce380cff74896aaef",
    "ca61159d9d9b411c855f6b31069baaa0ffe6d856531a9e77d8dbd9adc35b4aac",
    "e8933f5e3c2611a39557d1398079852c85d65abdc4ee90fe9f5da129018b71ad",
    "a2361b61c55b1b94ef09bf31549bc814bcbb5c79cf938e3099308ea2eac3515d",
    "409653f74a68c936e4cf92c61244b03613e8f25908cfda00fc2447d793656eca",
    "f53f7f4658c2e0d750415b3157822a630066eb4e35211ed9e864b8ff92b2ce75",
    "1e9fe74bf6ea57c0f216d1411876262ad2e6fbd26cf0a75526f090778dccf332",
    "0e75ea7228cdafb2dc19598cc0ca573b0d774fe07c8d8c212d6fa503a09ccf7a"
]
REVIEWED_STEPS = dict(zip(REVIEWED_STEP_NAMES, REVIEWED_STEP_DIGESTS, strict=True))


# Changes to publication ordering or the native post-agent pipeline require review.
REVIEWED_AGENT_STEP_ORDER = '9b78b43154b6432bf37225ae23c1c2aae006ec9d5340b8afae2184fafe0a4e3f'
REVIEWED_AGENT_PUBLICATION = '653440b46c993328d8ef879a46ff2a9cc30994be2347177334e2a595ecc7d418'
# Every detection step can affect the verdict; review additions, removals,
# reordering, and body/configuration changes, not only replaced anchors.
REVIEWED_DETECTION_STEPS = '9bc167dc5d0741b6458111b57d390b3eaa6cfa490087c5faa7bb350df1ba0dac'
PUBLICATION_GATE = "always() && steps.collect_output.outcome == 'success'"

class WorkflowLoader(yaml.SafeLoader):
    """Use YAML 1.2 booleans and reject ambiguous duplicate keys."""

    yaml_implicit_resolvers = {
        key: [(tag, pattern) for tag, pattern in values if tag != "tag:yaml.org,2002:bool"]
        for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError(f"Duplicate YAML key: {key}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$", re.IGNORECASE), list("tTfF")
)


class WorkflowDumper(yaml.SafeDumper):
    pass


def represent_string(dumper, value):
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|" if "\n" in value else None)


WorkflowDumper.add_representer(str, represent_string)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def gates(workflow):
    return {name: {key: job[key] for key in ("needs", "if") if key in job} for name, job in workflow["jobs"].items()}


def mapping(node):
    return {key.value: value for key, value in node.value}


def job_bytes(source, name):
    nodes = mapping(yaml.compose(source, Loader=WorkflowLoader))["jobs"].value
    for index, (key, value) in enumerate(nodes):
        if key.value == name:
            end = nodes[index + 1][0].start_mark.line if index + 1 < len(nodes) else len(source.splitlines())
            return "".join(source.splitlines(keepends=True)[key.start_mark.line:end])
    raise ValueError(f"Missing job: {name}")


def render_steps(steps):
    if not steps:
        return ""
    return "".join("      " + line if line.strip() else line for line in yaml.dump(
        steps, Dumper=WorkflowDumper, sort_keys=False, width=1000, default_flow_style=False
    ).splitlines(keepends=True))


def readonly_conclusion(source):
    """Retain diagnostics without granting access to the publisher environment."""
    original = job_bytes(source, "conclusion")
    token = "${{ secrets.REPO_ASSIST_GITHUB_TOKEN }}"
    permissions = "    permissions:\n      contents: write\n      issues: write\n      pull-requests: write\n"
    if original.count(token) != 5 or original.count(permissions) != 1:
        raise ValueError("Unreviewed conclusion credential or permission layout")
    job = yaml.load(original, Loader=WorkflowLoader)["conclusion"]
    nodes = mapping(yaml.compose(original, Loader=WorkflowLoader))["conclusion"]
    index = next(index for index, step in enumerate(job["steps"]) if step.get("name") == "Log detection run")
    step = copy.deepcopy(job["steps"][index])
    step["with"]["script"] = (
        "core.info('Independent detection: ' + JSON.stringify({\n"
        "  conclusion: process.env.GH_AW_DETECTION_CONCLUSION || 'unavailable',\n"
        "  reason: process.env.GH_AW_DETECTION_REASON || '',\n"
        "}));\n"
    )
    node = mapping(nodes)["steps"].value[index]
    lines = original.splitlines(keepends=True)
    lines[node.start_mark.line:node.end_mark.line] = [render_steps([step])]
    original = "".join(lines)
    return original.replace(token, "${{ github.token }}").replace(
        permissions,
        "    permissions:\n      contents: read\n",
    )


def stage_step():
    return {
        "name": "Stage trusted subscription worker",
        "run": """set -euo pipefail
test "$GITHUB_REF" = refs/heads/main
install -d -m 700 "$RUNNER_TEMP/repo-assist-trusted" "$RUNNER_TEMP/repo-assist-cli"
cp -R .github/repo-assist-worker/. "$RUNNER_TEMP/repo-assist-trusted/"
cp -R .github/repo-assist-cli/. "$RUNNER_TEMP/repo-assist-cli/"
chmod -R a-w "$RUNNER_TEMP/repo-assist-trusted"
python3 "$RUNNER_TEMP/repo-assist-trusted/tool_prerequisites.py" "$RUNNER_TOOL_CACHE"
""",
    }


def transform(source):
    if MARKER in source:
        raise ValueError("Subscription overlay requires freshly compiled input, not an already transformed lock")
    header = re.search(r"^# gh-aw-metadata: (.+)$", source, re.MULTILINE)
    if not header:
        raise ValueError("Missing gh-aw metadata")
    metadata = json.loads(header.group(1))
    if metadata.get("compiler_version") != COMPILER_VERSION or metadata.get("agent_id") != "claude" or metadata.get("detection_agent_id") != "claude":
        raise ValueError("Unreviewed compiler or engine metadata")
    original = yaml.load(source, Loader=WorkflowLoader)
    if fingerprint(gates(original)) != REVIEWED_GATES:
        raise ValueError("Unreviewed job set or dependency/condition gate")
    if fingerprint(original["jobs"]["detection"]["steps"]) != REVIEWED_DETECTION_STEPS:
        raise ValueError("Unreviewed native detection step sequence or body")
    agent_steps = original["jobs"]["agent"]["steps"]
    if fingerprint([step.get("name") for step in agent_steps]) != REVIEWED_AGENT_STEP_ORDER:
        raise ValueError("Unreviewed agent step order")
    execution_index = next(index for index, step in enumerate(agent_steps) if step.get("id") == "agentic_execution")
    if fingerprint(agent_steps[execution_index:]) != REVIEWED_AGENT_PUBLICATION:
        raise ValueError("Unreviewed native post-agent publication pipeline")
    tree = mapping(yaml.compose(source, Loader=WorkflowLoader))
    job_nodes = mapping(tree["jobs"])
    edits = []
    reviewed = {}

    # Validate every reviewed anchor before changing any text. Match exactly once.
    for key, expected in REVIEWED_STEPS.items():
        phase, name = key.split(":", 1)
        steps = original["jobs"][phase]["steps"]
        found = [(index, step) for index, step in enumerate(steps) if step.get("name") == name]
        if len(found) != 1 or fingerprint(found[0][1]) != expected:
            raise ValueError(f"Missing or changed reviewed step: {key}")
        index, step = found[0]
        node = mapping(job_nodes[phase])["steps"].value[index]
        reviewed[key] = (step, node)

    # Keep specific diagnostics above, then reject all other behavioral drift.
    if fingerprint(original) != REVIEWED_WORKFLOW:
        raise ValueError("Unreviewed compiled workflow behavior")

    conclusion = readonly_conclusion(source)
    start = next(key.start_mark.line for key, _ in tree["jobs"].value if key.value == "conclusion")
    edits.append((start, start + len(job_bytes(source, "conclusion").splitlines()), conclusion))

    def replace(phase, name, new_steps):
        _, node = reviewed[f"{phase}:{name}"]
        edits.append((node.start_mark.line, node.end_mark.line, render_steps(new_steps)))

    def modify(phase, name, change):
        step = copy.deepcopy(reviewed[f"{phase}:{name}"][0])
        change(step)
        replace(phase, name, [step])

    # The controller uses native HTTP safeoutputs directly. Its persistent
    # converted configuration must retain the server even if CLI filters exist.
    modify('agent', 'Start MCP Gateway',
           lambda step: step['env'].update({'GH_AW_MCP_CLI_SERVERS': '[]'}))

    for phase in ("agent", "detection"):
        if "environment" in original["jobs"][phase]:
            raise ValueError(f"Unexpected existing {phase} environment")
        start = job_nodes[phase].start_mark.line
        edits.append((start, start, "    environment: repo-assist\n"))
    if "environment" in original["jobs"]["safe_outputs"]:
        raise ValueError("Unexpected existing publisher environment")
    start = job_nodes["safe_outputs"].start_mark.line
    edits.append((start, start, "    environment: repo-assist-publisher\n"))
    start = job_nodes["pre_activation"].start_mark.line
    edits.append((start, start, "    if: github.ref == 'refs/heads/main' && github.repository == 'Artic0din/Prismarr'\n"))

    replace("activation", "Validate ANTHROPIC_API_KEY secret", [{
        "name": "Defer subscription authentication to restricted workers",
        "id": "validate-secret",
        "run": 'echo "verification_result=deferred" >> "$GITHUB_OUTPUT"',
    }])

    for phase, checkout_name in (("agent", "Checkout repository"), ("detection", "Checkout repository for patch context")):
        checkout = copy.deepcopy(reviewed[f"{phase}:{checkout_name}"][0])
        checkout.pop("if", None)
        checkout["with"]["ref"] = "${{ github.sha }}"
        checkout["with"]["persist-credentials"] = False
        replace(phase, checkout_name, [checkout, stage_step()])
        replace(phase, "Install Claude Code CLI", [{
            "name": "Install locked Claude Code CLI",
            "run": 'npm ci --prefix "$RUNNER_TEMP/repo-assist-cli" --no-audit --no-fund',
        }])
        for name in ("Install AWF binary", "Prepare writable API proxy reflection artifact"):
            replace(phase, name, [])

    def readonly_checkout(step):
        step["env"]["GH_TOKEN"] = "${{ github.token }}"
        step["with"]["github-token"] = "${{ github.token }}"

    modify("agent", "Checkout PR branch", readonly_checkout)
    for phase, old_name, new_name in (
        ("agent", "Execute Claude Code CLI", "Execute subscription Claude worker"),
        ("detection", "Execute threat detection with AWF", "Execute independent subscription detector"),
    ):
        def execution(step, phase=phase, new_name=new_name):
            step["name"] = new_name
            step["run"] = f'python3 "$RUNNER_TEMP/repo-assist-trusted/repo-assist-worker.py" {phase}\n'
            for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_MAX_RETRIES", "GH_AW_HARNESS_MAX_RETRIES", "GH_AW_LLM_PROVIDER", "GH_TOKEN"):
                step["env"].pop(key, None)
            step["env"]["CLAUDE_CODE_OAUTH_TOKEN"] = OAUTH
            if phase == "agent":
                # Trusted launcher gives this token only to the read-only CLI sidecar.
                step["env"]["REPO_ASSIST_READ_TOKEN"] = "${{ github.token }}"
        modify(phase, old_name, execution)

    def detector_images(step):
        step["run"] = f'bash "${{RUNNER_TEMP}}/gh-aw/actions/download_docker_images.sh" {AGENT_IMAGE}'

    modify("detection", "Download container images", detector_images)
    # Unknown subscription usage stays unknown. Do not let the native parser
    # replace a missing receipt with a zero-cost record or summary.
    modify("detection", "Parse threat detection token usage for step summary",
           lambda step: step["env"].update({"GH_AW_WRITE_EMPTY_USAGE": "false"}))
    # Agent image download is intentionally retained verbatim: native preparation
    # also needs MCP Gateway, Safe Outputs node, and GitHub MCP images.
    for phase, name in (("agent", "Print firewall logs"), ("agent", "Print AWF reflect summary"), ("detection", "Copy detection firewall logs")):
        replace(phase, name, [])

    def redact(step):
        names = step["env"]["GH_AW_SECRET_NAMES"].split(",")
        names = ["CLAUDE_CODE_OAUTH_TOKEN" if n == "ANTHROPIC_API_KEY" else n for n in names if n != "REPO_ASSIST_GITHUB_TOKEN"]
        step["env"]["GH_AW_SECRET_NAMES"] = ",".join(names)
        step["env"].pop("SECRET_ANTHROPIC_API_KEY")
        step["env"].pop("SECRET_REPO_ASSIST_GITHUB_TOKEN")
        step["env"]["SECRET_CLAUDE_CODE_OAUTH_TOKEN"] = OAUTH

    redactor = copy.deepcopy(reviewed["agent:Redact secrets in logs"][0])
    redact(redactor)
    collector = copy.deepcopy(reviewed["agent:Ingest agent output"][0])
    collector["env"].update(redactor["env"])
    # Keep both native entrypoint bodies verbatim in separate lexical scopes.
    # There are no services on this dedicated hosted runner: any remaining
    # container, or an unavailable Docker daemon, makes publication unsafe.
    collector["with"]["script"] = """const publicationContainers = await exec.getExecOutput('docker', ['ps', '--quiet'], {silent: true});
if (publicationContainers.exitCode !== 0 || publicationContainers.stdout.trim() !== '') {
  throw new Error('Publication blocked: container quiescence was not established');
}
async function guardPublication() {
  const guard = require('path').join(process.env.RUNNER_TEMP, 'repo-assist-trusted', 'publication_guard.py');
  await exec.exec('python3', [guard,
    '--workspace', process.env.GITHUB_WORKSPACE,
    '--native-artifact-dir', '/tmp/gh-aw',
    '--safeoutputs', require('path').join(process.env.RUNNER_TEMP, 'gh-aw', 'safeoutputs'),
    '--scratch-parent', process.env.RUNNER_TEMP,
  ], {silent: true});
}
{
""" + redactor["with"]["script"] + "}\nawait guardPublication();\n{\n" + collector["with"]["script"] + "}\nawait guardPublication();\n"
    replace("agent", "Redact secrets in logs", [])
    relocated = []
    for name in ("Detect agent errors", "Append agent step summary"):
        step = copy.deepcopy(reviewed[f"agent:{name}"][0])
        step["if"] = PUBLICATION_GATE
        relocated.append(step)
        replace("agent", name, [])
    replace("agent", "Ingest agent output", [collector, *relocated])
    for name in (
        "Parse agent logs for step summary", "Parse MCP Gateway logs for step summary",
        "Parse token usage for step summary", "Generate observability summary",
        "Write agent output placeholder if missing", "Upload agent output fallback artifact",
        "Upload agent artifacts",
    ):
        modify("agent", name, lambda step: step.update({"if": PUBLICATION_GATE}))
    lines = source.splitlines(keepends=True)
    for start, end, replacement in sorted(edits, reverse=True):
        lines[start:end] = [replacement]
    result = MARKER + "\n" + "".join(lines)
    # Remaining references are the compiler's documentary secret manifest only.
    result = "".join(
        line.replace("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN") if line.startswith("#") else line
        for line in result.splitlines(keepends=True)
    )
    final = yaml.load(result, Loader=WorkflowLoader)
    for name in ("safe_outputs", "validate_updates", "conclusion"):
        expected = job_bytes(source, name)
        if name == "safe_outputs":
            header, rest = expected.split("\n", 1)
            expected = header + "\n    environment: repo-assist-publisher\n" + rest
        if name == "conclusion":
            expected = readonly_conclusion(source)
        if expected != job_bytes(result, name):
            raise ValueError(f"Native job changed: {name}")
    for key in ("on", "concurrency", "permissions"):
        if original[key] != final[key]:
            raise ValueError(f"Workflow contract changed: {key}")
    recipients = []
    for phase, job in final["jobs"].items():
        if phase != "safe_outputs" and "secrets.REPO_ASSIST_GITHUB_TOKEN" in json.dumps(job):
            raise ValueError(f"Publisher secret referenced outside publisher: {phase}")
        if phase in ("agent", "detection") and "REPO_ASSIST_GITHUB_TOKEN" in json.dumps(job):
            raise ValueError(f"Publisher token leaked to {phase}")
        for step in job.get("steps", []):
            if OAUTH in json.dumps(step):
                recipients.append((phase, step.get("id", step["name"])))
    if recipients != [("agent", "agentic_execution"), ("agent", "collect_output"), ("detection", "detection_agentic_execution")]:
        raise ValueError("Unexpected OAuth recipient")
    if json.dumps(final).count(OAUTH) != 3:
        raise ValueError("OAuth credential is present outside its three reviewed recipients")
    if "ANTHROPIC_API_KEY" in result:
        raise ValueError("API credential survived subscription transform")
    return result


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: transform-repo-assist-subscription.py path/to/repo-assist.lock.yml")
    path = Path(sys.argv[1])
    result = transform(path.read_text())
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            output.write(result)
        os.chmod(temporary, path.stat().st_mode & 0o777)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, yaml.YAMLError) as error:
        raise SystemExit(f"Repo Assist subscription transform rejected input: {error}") from error
