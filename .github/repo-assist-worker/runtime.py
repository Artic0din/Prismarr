"""Pure construction and result validation for the subscription worker."""
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

AGENT_IMAGE = 'ghcr.io/github/gh-aw-firewall/agent:0.28.27@sha256:8d14865f96d57d9b4f22b30b3e148d2d926384f0aa543a139f15593e450f0e90'
CLI_IMAGE = 'ghcr.io/github/gh-aw-firewall/cli-proxy:0.28.27@sha256:7536c8d5b9b4f77d48f3617df6b3d303d363945c7490bd0e708ddb420986448d'


def require_auth(environment: dict[str, str]) -> None:
    if not environment.get('CLAUDE_CODE_OAUTH_TOKEN', '').strip():
        raise ValueError('Subscription credential is missing')
    competing = ('ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_BASE_URL',
                 'ANTHROPIC_CUSTOM_HEADERS', 'ANTHROPIC_PROFILE', 'ANTHROPIC_FEDERATION_RULE_ID',
                 'ANTHROPIC_ORGANIZATION_ID',
                 'CLAUDE_CODE_USE_BEDROCK', 'CLAUDE_CODE_USE_VERTEX', 'CLAUDE_CODE_USE_FOUNDRY',
                 'ANTHROPIC_BEDROCK_BASE_URL', 'AWS_BEARER_TOKEN_BEDROCK',
                 'CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR', 'CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR')
    if any(environment.get(name, '').strip() for name in competing):
        raise ValueError('Competing provider authentication is forbidden')


def confinement(name: str, network: str) -> list[str]:
    return ['docker', 'create', '--name', name, '--network', network,
            '--user', f'{os.getuid()}:{os.getgid()}', '--read-only', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--pids-limit', '256',
            '--memory', '4g', '--cpus', '2', '--ulimit', 'nofile=1024:1024',
            '--tmpfs', '/tmp:rw,nosuid,nodev,size=1g,mode=1777']


def mount(source: Path, destination: str, writable: bool = False) -> list[str]:
    if not source.is_absolute() or not destination.startswith('/') or ',' in str(source) + destination:
        raise ValueError('Mount paths must be absolute and contain no commas')
    value = f'type=bind,src={source},dst={destination}'
    return ['--mount', value + ('' if writable else ',readonly')]


def model_environment() -> list[str]:
    values = ['CLAUDE_CODE_OAUTH_TOKEN', 'HOME=/tmp/claude-home',
              'PATH=/trusted/bin:/opt/claude/node_modules/.bin:/usr/local/bin:/usr/bin:/bin',
              'HTTP_PROXY=http://repo-assist-egress:8080', 'HTTPS_PROXY=http://repo-assist-egress:8080',
              'NO_PROXY=localhost,127.0.0.1,awmg-mcpg,repo-assist-tools',
              'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1', 'DISABLE_TELEMETRY=1',
              'DISABLE_ERROR_REPORTING=1', 'DISABLE_AUTOUPDATER=1',
              'CLAUDE_CODE_DISABLE_ARTIFACT=1', 'ENABLE_CLAUDEAI_MCP_SERVERS=false',
              'CLAUDE_CODE_DISABLE_FAST_MODE=1', 'CI=true']
    return [part for value in values for part in ('--env', value)]


def tool_environment() -> list[str]:
    # Literal values only: Docker must never forward the host's credentials.
    values = ['HOME=/tmp/tool-home', 'PATH=/trusted/bin:/opt/validation:/usr/local/bin:/usr/bin:/bin',
              'AWF_CLI_PROXY_URL=http://repo-assist-cli:11000', 'CI=true',
              'GIT_AUTHOR_NAME=Repo Assist', 'GIT_COMMITTER_NAME=Repo Assist',
              'GIT_AUTHOR_EMAIL=repo-assist@users.noreply.github.com',
              'GIT_COMMITTER_EMAIL=repo-assist@users.noreply.github.com',
              'GIT_CONFIG_COUNT=1', 'GIT_CONFIG_KEY_0=core.hooksPath', 'GIT_CONFIG_VALUE_0=/dev/null']
    return [part for value in values for part in ('--env', value)]


def agent_command() -> list[str]:
    settings = json.dumps({'disableAllHooks': True, 'disableClaudeAiConnectors': True})
    # --bare would disable OAuth; explicit settings isolation preserves subscription auth.
    # The credentialed client exposes only remote tools in another container.
    # Repeating --tools accumulates in the pinned CLI; never append an override.
    return ['/opt/claude/node_modules/.bin/claude', '--print', '--verbose', '--no-chrome',
            '--restricted', '--setting-sources', '', '--settings', settings,
            '--disable-slash-commands', '--strict-mcp-config', '--mcp-config', '/controller/mcp.json',
            '--tools', '', '--allowedTools', 'mcp__repository__execute,mcp__safeoutputs',
            '--append-system-prompt',
            'All repository reads, edits, shell commands and gh requests use mcp__repository__execute. '
            'Its default working directory is the repository checkout in a separate tool container. '
            'References to Bash, Read, Edit or local files in the maintenance instructions mean this remote tool. '
            'Use the mcp__safeoutputs tools directly for proposals. The controller has no local repository tools. '
            'Plan for the hard 60-turn limit: spend at most 10 turns on setup, memory, task applicability and selection. '
            'Select exactly one eligible maintenance task and one focused work item, then complete Task 11 and memory. '
            'Do not start another task after a useful result. Publishable paths are only README.md, CHANGELOG.md and Markdown files under docs/. '
            'Never edit or commit AGENTS.md, CLAUDE.md, CONTRIBUTING.md, .github/, symfony/, docker/ or templates/. '
            'Batch independent reads in a single repository command, inspect only evidence needed for selected tasks, '
            'and do not repeat whole-codebase searches after a useful bounded action is identified. '
            'The repository tool maintenance_progress reports repository_calls_started, not model turns. '
            'At 30 repository calls, switch to finalization: finish validation and path cleanup, then reporting and proposals. '
            'Do not treat this advisory count as remaining Claude turns or let it justify skipping validation. '
            'Reserve at least the final 15 turns for the mandatory Task 11 report and memory, applicable validation, '
            'safe-output proposals and a final completion response. Stop starting new investigations by turn 45. '
            'Report the selected task actual outcome and deferred work when no supported action is available; never fabricate findings '
            'or claim an unverified task complete to fit the budget. The publication and validation gates still apply.',
            '--permission-mode', 'dontAsk', '--model', 'claude-sonnet-4-6',
            '--max-turns', '60', '--output-format', 'stream-json']


def agent_mcp_configuration(path: Path) -> dict:
    """Copy only the trusted native HTTP transport, never executable MCP config."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError('Expected bounded trusted MCP configuration')
    value = json.loads(path.read_text())
    if (not isinstance(value, dict) or set(value) != {'mcpServers'}
            or not isinstance(value['mcpServers'], dict) or set(value['mcpServers']) != {'safeoutputs'}):
        raise ValueError('Unexpected native MCP server')
    server = value['mcpServers']['safeoutputs']
    if (not isinstance(server, dict) or set(server) - {'type', 'url', 'headers', 'tools'}
            or server.get('type', 'http') != 'http' or not isinstance(server.get('url'), str)):
        raise ValueError('Native MCP must be a fixed HTTP transport')
    url = urlsplit(server['url'])
    if (url.scheme != 'http' or url.hostname not in ('awmg-mcpg', 'localhost', '127.0.0.1')
            or url.port != 8080 or url.username or url.password or url.query or url.fragment
            or url.path != '/mcp/safeoutputs'):
        raise ValueError('Unexpected native MCP destination')
    headers = server.get('headers', {})
    if (not isinstance(headers, dict) or set(headers) - {'Authorization'}
            or any(not isinstance(v, str) or '\n' in v or '\r' in v for v in headers.values())):
        raise ValueError('Unexpected native MCP headers')
    native = {'type': 'http', 'url': 'http://awmg-mcpg:8080/mcp/safeoutputs', 'headers': headers}
    return {'mcpServers': {'safeoutputs': native,
                          'repository': {'type': 'http', 'url': 'http://repo-assist-tools:8081/mcp'}}}


def detector_environment(environment: dict[str, str]) -> list[str]:
    has_patch = environment.get('HAS_PATCH', 'false')
    if has_patch not in ('true', 'false'):
        raise ValueError('Invalid detector patch-presence flag')
    # Native threat-detect defaults to warn mode if this setting is omitted.
    values = ['GH_AW_DETECTION_CONTINUE_ON_ERROR=false', 'HAS_PATCH=' + has_patch]
    for name in ('WORKFLOW_NAME', 'WORKFLOW_DESCRIPTION'):
        value = environment.get(name, '')
        if len(value) > 4096 or '\x00' in value:
            raise ValueError('Invalid detector workflow context')
        values.append(name + '=' + value)
    return [part for value in values for part in ('--env', value)]


def require_completion(text: str) -> dict:
    result = None
    for line in text.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            if line.lstrip().startswith('{'):
                result = None
            continue
        if isinstance(value, dict) and value.get('type') == 'result':
            result = value
    if (result is None or result.get('subtype') != 'success' or result.get('is_error') is not False
            or not isinstance(result.get('result'), str) or not result['result'].strip()):
        raise ValueError('Claude did not finish with a successful nonblank result')
    return result


def read_detector_result(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError('Detector result must be a bounded regular file')
    value = json.loads(path.read_text())
    flags = ('prompt_injection', 'secret_leak', 'malicious_patch')
    if (not isinstance(value, dict) or set(value) - {*flags, 'reasons', 'warnings'}
            or any(type(value.get(key)) is not bool for key in flags)
            or not isinstance(value.get('reasons'), list) or len(value['reasons']) > 20
            or any(not isinstance(reason, str) or not reason.strip() or len(reason) > 2000 for reason in value['reasons'])):
        raise ValueError('Detector result is incomplete or malformed')
    result = {**{key: value[key] for key in flags}, 'reasons': []}
    if 'warnings' in value:
        warnings = value['warnings']
        limits = {'field': 64, 'code': 64, 'message': 2000}
        if (not isinstance(warnings, list) or len(warnings) > 20
                or any(not isinstance(warning, dict) or set(warning) != set(limits)
                       or any(not isinstance(warning[key], str) or not warning[key].strip()
                              or len(warning[key]) > limit for key, limit in limits.items())
                       for warning in warnings)):
            raise ValueError('Detector warnings are malformed')
        result['warnings'] = warnings
    return result
