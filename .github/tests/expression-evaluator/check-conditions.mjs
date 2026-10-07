import assert from 'node:assert/strict';
import fs from 'node:fs';
import {Lexer, Parser, Evaluator, data} from '@actions/expressions';

function asData(value) {
  if (value === null || value === undefined) return new data.Null();
  if (typeof value === 'boolean') return new data.BooleanData(value);
  if (typeof value === 'number') return new data.NumberData(value);
  if (typeof value === 'string') return new data.StringData(value);
  return new data.Dictionary(...Object.entries(value).map(([key, v]) => ({key, value: asData(v)})));
}

function evaluate(expression, currentJobStatus, context) {
  // Matches actions/runner SuccessFunction: normal steps consult this job's
  // status, not needs.agent.result. The expression parser/evaluator is GitHub's.
  const functions = new Map([
    ['always', {name: 'always', minArgs: 0, maxArgs: 0, call: () => new data.BooleanData(true)}],
    ['success', {name: 'success', minArgs: 0, maxArgs: 0, call: () => new data.BooleanData(currentJobStatus === 'success')}],
    ['failure', {name: 'failure', minArgs: 0, maxArgs: 0, call: () => new data.BooleanData(currentJobStatus === 'failure')}],
    ['cancelled', {name: 'cancelled', minArgs: 0, maxArgs: 0, call: () => new data.BooleanData(currentJobStatus === 'cancelled')}],
  ]);
  const tokens = new Lexer(expression.trim().replace(/^\$\{\{\s*|\s*\}\}$/g, '')).lex().tokens;
  const tree = new Parser(tokens, Object.keys(context), [...functions.values()]).parse();
  return new Evaluator(tree, asData(context), functions).evaluate().coerceString() === 'true';
}

const workflows = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const failures = [];
let assertions = 0;
for (const workflow of workflows) {
  const base = {
    steps: {
      detection_guard: {outputs: {run_detection: 'true'}},
      threat_detect_install: {outcome: 'success'},
      detection_staging_reset: {outcome: 'success'},
    },
    needs: {agent: {result: 'success'}, detection: {result: 'success'}, validate_updates: {result: 'success'}},
  };
  const check = (name, actual, expected) => {
    assertions++;
    try { assert.equal(actual, expected, `${workflow.repo}: ${name}`); }
    catch (error) { failures.push(error.message); }
  };
  check('failed preparation blocks detector', evaluate(workflow.execute_if, 'failure', base), false);
  check('successful preparation permits detector', evaluate(workflow.execute_if, 'success', base), true);
  check('cancelled detection job blocks detector', evaluate(workflow.execute_if, 'cancelled', base), false);
  const failedAgent = structuredClone(base);
  failedAgent.needs.agent.result = 'failure';
  check('failed agent still permits detection job', evaluate(workflow.job_if, 'success', failedAgent), true);
  check('failed agent does not invalidate successful detector prerequisites', evaluate(workflow.execute_if, 'success', failedAgent), true);
  const skippedAgent = structuredClone(base);
  skippedAgent.needs.agent.result = 'skipped';
  check('skipped agent skips detection job', evaluate(workflow.job_if, 'success', skippedAgent), false);
  const failedInstall = structuredClone(base);
  failedInstall.steps.threat_detect_install.outcome = 'failure';
  check('failed detector installation blocks execution', evaluate(workflow.execute_if, 'success', failedInstall), false);
  const noOutputs = structuredClone(base);
  noOutputs.steps.detection_guard.outputs.run_detection = 'false';
  check('no outputs skips detection', evaluate(workflow.execute_if, 'success', noOutputs), false);
  for (const diagnostic of workflow.diagnostics) {
    check(`${diagnostic.name} survives preparation failure`, evaluate(diagnostic.if, 'failure', base), true);
  }
  const failedDetection = structuredClone(base);
  failedDetection.needs.detection.result = 'failure';
  check('failed detection blocks publication', evaluate(workflow.publication_if, 'success', failedDetection), false);
  check('successful detection and validation permit publication', evaluate(workflow.publication_if, 'success', base), true);
}
console.log(JSON.stringify({evaluator: '@actions/expressions@0.3.61', workflows: workflows.length, assertions, failures}, null, 2));
process.exitCode = failures.length ? 1 : 0;
