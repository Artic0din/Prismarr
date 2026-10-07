// Exercise actual pinned scanner, component coverage, and model prices offline.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const [compiler, artifactDirectory, unknownFile] = process.argv.slice(2);
const actions = path.join(compiler, 'actions/setup/js');
const { getRunAIC } = require(path.join(actions, 'check_daily_aic_workflow_guardrail.cjs'));
const { scanDailyAIC } = require(path.join(actions, 'daily_aic_scan.cjs'));
const { createAPIBudget } = require(path.join(actions, 'daily_aic_api_budget.cjs'));
const messages = [];
const outputs = [];
global.core = { info: value => messages.push(value), warning: value => messages.push(value),
  setOutput: (...args) => outputs.push(args), exportVariable: () => {},
  setFailed: message => { throw new Error(message); } };
const now = Date.parse('2026-10-04T12:00:00Z');
const start = '2026-10-04T10:00:00Z';
const completed = '2026-10-04T10:05:00Z';
const runs = Array.from({ length: 5 }, (_, index) => ({ id: index + 1, status: 'completed',
  conclusion: 'success', run_attempt: 1, created_at: start, run_started_at: start,
  updated_at: completed }));
const jobs = ['agent', 'detection'].map((name, index) => ({ id: index + 20, name,
  status: 'completed', conclusion: 'success', run_attempt: 1, started_at: start, completed_at: completed }));
const github = { rest: { actions: {
  getWorkflowRun: async () => ({ data: { workflow_id: 80 }, headers: {} }),
  listJobsForWorkflowRun: async () => ({ data: { jobs }, headers: {} }),
} } };
const artifactClient = {
  listArtifacts: async () => ({ artifacts: [{ id: 50, name: 'usage',
    createdAt: new Date('2026-10-04T10:10:00Z') }] }),
  downloadArtifact: async (_id, options) => {
    fs.cpSync(artifactDirectory, options.path, { recursive: true });
    return { downloadPath: options.path };
  },
};
async function scan(count, cacheName) {
  return scanDailyAIC({ github, context: { repo: { owner: 'fixture', repo: 'example' }, runId: 99 },
    budget: createAPIBudget(), artifactClient, getRunAIC, token: 'synthetic', fallbackAIC: 1000, now,
    cachePath: path.join(artifactDirectory, cacheName),
    listPage: async () => ({ response: { data: { workflow_runs: runs.slice(0, count) }, headers: {} },
      sourceRunCount: count, lookupMode: 'workflow_id' }),
  });
}
(async () => {
  // Run actual native parse_token_usage.main, relocating only its hardcoded
  // scratch paths. An unknown receipt must not become a numeric-zero summary.
  const parserRoot = path.join(artifactDirectory, '..', 'parser');
  const parserInput = path.join(parserRoot, 'sandbox/firewall/logs/api-proxy-logs/token-usage.jsonl');
  fs.mkdirSync(path.dirname(parserInput), { recursive: true });
  const parserFile = path.join(actions, 'parse_token_usage.cjs');
  const parser = new Module(parserFile, module);
  parser.filename = parserFile;
  parser.paths = Module._nodeModulePaths(actions);
  parser._compile(fs.readFileSync(parserFile, 'utf8').replaceAll('/tmp/gh-aw', parserRoot), parserFile);
  process.env.GH_AW_WRITE_EMPTY_USAGE = 'false';
  process.env.GH_AW_AGENT_USAGE_PATH = path.join(parserRoot, 'detection_usage.json');
  process.env.GH_AW_AGENT_USAGE_JSONL_PATH = path.join(parserRoot, 'detection_usage.jsonl');
  process.env.GITHUB_STEP_SUMMARY = path.join(parserRoot, 'step-summary.md');
  fs.copyFileSync(unknownFile, parserInput);
  await parser.exports.main(path.join(parserRoot, 'no-copilot-session'));
  assert.equal(fs.existsSync(process.env.GH_AW_AGENT_USAGE_PATH), false);
  assert.equal(fs.existsSync(process.env.GH_AW_AGENT_USAGE_JSONL_PATH), false);
  assert.equal(fs.existsSync(process.env.GITHUB_STEP_SUMMARY), false);
  assert.equal(outputs.length, 0);
  fs.copyFileSync(path.join(artifactDirectory, 'detection/token_usage.jsonl'), parserInput);
  await parser.exports.main(path.join(parserRoot, 'no-copilot-session'));
  assert.ok(JSON.parse(fs.readFileSync(process.env.GH_AW_AGENT_USAGE_PATH, 'utf8')).ai_credits > 0);
  assert.ok(outputs.some(([name, value]) => name === 'aic' && Number(value) > 0));
  const measured = await scan(1, 'measured-cache.jsonl');
  const measuredAIC = measured.countedRuns[0].aic;
  assert.ok(measuredAIC > 0 && measuredAIC < 1000);
  assert.ok(messages.some(line => line.includes('"reason":"covered_components"')));
  const receipt = path.join(artifactDirectory, 'detection/token_usage.jsonl');
  fs.copyFileSync(unknownFile, receipt);
  const unknown = await scan(1, 'unknown-cache.jsonl');
  assert.equal(unknown.countedRuns[0].aic, 1000);
  assert.ok(messages.some(line => line.includes('"reason":"max_ai_credits_fallback"')));
  const five = await scan(5, 'five-cache.jsonl');
  process.stdout.write(JSON.stringify({ measuredAIC, unknownAIC: unknown.countedRuns[0].aic, unknownSummaryOmitted: true,
    fiveUnknownRunsAIC: five.countedRuns.reduce((sum, run) => sum + run.aic, 0) }));
})().catch(error => { console.error(error); process.exitCode = 1; });
