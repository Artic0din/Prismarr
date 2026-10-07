"""No-model agent lifecycle fixture for the Docker worker contract.

The real pinned CLI image runs its normal entrypoint, liveness check, gh binary,
and HTTP exec server against synthetic services. Upstream contract:
https://github.com/github/gh-aw-firewall/tree/73db24db0371305c55baaa2fd0f970608e8c7f3d/containers/cli-proxy
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from runtime import AGENT_IMAGE, CLI_IMAGE, confinement, require_completion, mount
from tool_prerequisites import require_jq


# These fixtures are run inside the pinned image, never with a real model/token.
AGENT_FIXTURE = r'''#!/usr/bin/env python3
import http.client,json,os,shutil,socket,ssl,subprocess,sys
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request,urlopen

assert os.environ['CLAUDE_CODE_OAUTH_TOKEN']=='synthetic-only-no-model-call'
for name in ('GH_TOKEN','GITHUB_TOKEN','REPO_ASSIST_READ_TOKEN','ACTIONS_RUNTIME_TOKEN','RUNNER_TEMP',
             'ANTHROPIC_API_KEY','ANTHROPIC_AUTH_TOKEN','ANTHROPIC_BASE_URL'):
 assert name not in os.environ, name
assert sys.stdin.read()=='Synthetic agent lifecycle prompt\n'
assert sys.argv[sys.argv.index('--tools')+1]==''
assert not Path('.git').exists()
assert Path.cwd()==Path('/tmp/controller')
assert not Path('/opt/validation').exists()
assert not Path('/tmp/gh-aw/agent').exists()

config=json.loads(Path(sys.argv[sys.argv.index('--mcp-config')+1]).read_text())
tool_probe="""import json,os,socket,subprocess
from pathlib import Path
for name in ('CLAUDE_CODE_OAUTH_TOKEN','ANTHROPIC_API_KEY','GH_TOKEN','GITHUB_TOKEN','ACTIONS_RUNTIME_TOKEN'):
 assert name not in os.environ, name
for path in ('/controller/mcp.json','/opt/claude','/var/run/docker.sock'):
 assert not Path(path).exists(), path
readable=0
for path in Path('/proc').glob('[0-9]*/environ'):
 try: data=path.read_bytes()
 except OSError: continue
 readable+=1
 assert b'CLAUDE_CODE_OAUTH_TOKEN=' not in data
assert readable>0
assert not Path('/tmp/gh-aw/host-fixture-marker').exists()
scratch=Path('/tmp/gh-aw/agent/issues.json')
scratch.write_text('[{"number":1,"title":"synthetic issue"}]')
jq=subprocess.run(['jq','-er','.[0].number',str(scratch)],capture_output=True,text=True,timeout=10)
assert jq.returncode==0 and jq.stdout.strip()=='1', (jq.stdout,jq.stderr)
version=subprocess.check_output(['jq','--version'],text=True).strip()
assert version=='jq-1.8.1', version
try: Path('/opt/validation/jq').open('ab').close()
except OSError: pass
else: raise AssertionError('jq mount is writable')
try: Path('/opt/validation/write-probe').write_text('denied')
except OSError: pass
else: raise AssertionError('validation mount is writable')
for host in ('169.254.169.254','1.1.1.1'):
 try: socket.create_connection((host,443),timeout=1).close()
 except OSError: pass
 else: raise AssertionError('tool container has direct network access')
read=subprocess.run(['gh','api','repos/fixture/repo/issues/1'],capture_output=True,text=True,timeout=30)
assert read.returncode==0, read.stderr
assert json.loads(read.stdout)=={'number':1,'title':'synthetic issue'}
with Path('.git/config').open('a') as config:
 config.write('\\n[fixture]\\n\\tchanged = true\\n')
Path('agent-proof.json').write_text(json.dumps({'gh_read':True,'mcp':True,'tls':True,'direct_denied':True,'jq':True,'scratch':True}))
print('credential-free repository operations passed')
"""
import shlex
repository=config['mcpServers']['repository']
request=Request(repository['url'],data=json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/call',
 'params':{'name':'execute','arguments':{'command':'python3 -c '+shlex.quote(tool_probe),'timeout_seconds':30}}}).encode(),
 headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream'})
with urlopen(request,timeout=40) as response:
 result=json.load(response)['result']
assert not result.get('isError'), result
assert 'credential-free repository operations passed' in json.dumps(result)
progress=json.loads(result['content'][0]['text'])['maintenance_progress']
assert progress['repository_calls_started']==1 and progress['phase']=='setup'
assert progress['advisory'] is True
mcp=config['mcpServers']['safeoutputs']
assert mcp['type']=='http'
for method,params in [('initialize',{'protocolVersion':'2024-11-05','capabilities':{},
                                   'clientInfo':{'name':'fixture','version':'1'}}),('tools/list',{})]:
 request=Request(mcp['url'],data=json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),
                 headers={**mcp['headers'],'Content-Type':'application/json','Accept':'application/json, text/event-stream'})
 with urlopen(request,timeout=10) as response:
  result=json.load(response)['result']
 if method=='initialize': assert result['serverInfo']['name']=='synthetic-native-mcp'
 else: assert result['tools'][0]['name']=='noop'

proxy=urlsplit(os.environ['HTTPS_PROXY'])
context=ssl.create_default_context(cafile='/trusted/fixture-ca.crt')
connection=http.client.HTTPSConnection(proxy.hostname,proxy.port,context=context,timeout=10)
connection.set_tunnel('api.anthropic.com',443)
connection.request('GET','/fixture-completion')
response=connection.getresponse()
assert response.status==200
assert json.loads(response.read())=={'fixture':'allowed TLS'}
connection.close()
denied=http.client.HTTPSConnection(proxy.hostname,proxy.port,context=context,timeout=10)
denied.set_tunnel('example.com',443)
try: denied.request('GET','/')
except OSError as error: assert '403' in str(error), str(error)
else: raise AssertionError('gateway allowed an unlisted CONNECT destination')
finally: denied.close()
upstream=json.loads(Path('/trusted/fixture-upstream.json').read_text())
for host,port in [('169.254.169.254',443),('1.1.1.1',443),(upstream['ip'],18444)]:
 try: socket.create_connection((host,port),timeout=1).close()
 except OSError: pass
 else: raise AssertionError('worker has direct external network access')

print(json.dumps({'type':'result','subtype':'success','is_error':False,'result':'Synthetic lifecycle complete'}))
'''


NATIVE_FIXTURE = r'''import json,ssl,sys,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path

lock=threading.Lock()
def record(value):
 with lock, Path('/proof/requests.jsonl').open('a') as output:
  output.write(json.dumps(value)+'\n')

class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def respond(self,status,value):
  body=json.dumps(value).encode()
  self.send_response(status)
  self.send_header('Content-Type','application/json')
  self.send_header('Content-Length',str(len(body)))
  self.end_headers()
  self.wfile.write(body)
 def do_GET(self):
  record({'service':self.server.service,'method':'GET','path':self.path,
          'user_agent':self.headers.get('User-Agent','')})
  path=self.path.removeprefix('/api/v3')
  if self.server.service=='difc' and path=='/rate_limit':
   self.respond(200,{'resources':{'core':{'remaining':5000}}})
  elif self.server.service=='difc' and path=='/repos/fixture/repo/issues/1':
   self.respond(200,{'number':1,'title':'synthetic issue'})
  elif self.server.service=='model-tls' and path=='/fixture-completion':
   self.respond(200,{'fixture':'allowed TLS'})
  else: self.respond(404,{'error':'unexpected fixture request'})
 def do_POST(self):
  request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
  record({'service':self.server.service,'method':request.get('method'),'path':self.path})
  if (self.server.service!='mcp' or self.path!='/mcp/safeoutputs'
      or self.headers.get('Authorization')!='Bearer synthetic-mcp-token'):
   self.respond(403,{'error':'invalid MCP fixture request'})
  elif request['method']=='initialize':
   self.respond(200,{'jsonrpc':'2.0','id':request['id'],'result':{'protocolVersion':'2024-11-05',
                    'capabilities':{'tools':{}},'serverInfo':{'name':'synthetic-native-mcp','version':'1'}}})
  elif request['method']=='tools/list':
   self.respond(200,{'jsonrpc':'2.0','id':request['id'],'result':{
                    'tools':[{'name':'noop','description':'Fixture only','inputSchema':{'type':'object'}}]}})
  else: self.respond(404,{'error':'unexpected MCP method'})

def server(service,port,tls=False):
 http=ThreadingHTTPServer(('0.0.0.0',port),Handler)
 http.service=service
 if tls:
  context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  context.load_cert_chain('/fixture/ca.crt','/fixture/key.pem')
  context.set_servername_callback(lambda sock,name,ctx: record({'service':service,'sni':name}))
  http.socket=context.wrap_socket(http.socket,server_side=True)
 return http

if sys.argv[1]=='mcp': server('mcp',8080).serve_forever()
elif sys.argv[1]=='difc': server('difc',18443,True).serve_forever()
else: server('model-tls',18444,True).serve_forever()
'''


def fixture_jq(test) -> Path:
    try:
        cache = os.environ.get('RUNNER_TOOL_CACHE')
        if not cache:
            raise ValueError('No fixture cache configured')
        return require_jq(Path(cache)) / 'jq'
    except (OSError, ValueError):
        message = 'Stage pinned jq with tool_prerequisites.py CACHE and set RUNNER_TOOL_CACHE=CACHE'
        if os.environ.get('REPO_ASSIST_REQUIRE_DOCKER') == '1':
            test.fail(message)
        test.skipTest(message)


def exercise_agent_lifecycle(test, worker, worker_root):
    jq = fixture_jq(test)
    for image in (AGENT_IMAGE, CLI_IMAGE):
        subprocess.run(['docker', 'pull', image], check=True, capture_output=True)
    # Never replace native sidecars belonging to another workflow.
    for name in ('awmg-mcpg', 'awmg-cli-proxy'):
        existing = subprocess.run(['docker', 'inspect', name], capture_output=True)
        test.assertNotEqual(existing.returncode, 0, 'Native sidecar already exists: ' + name)
    with tempfile.TemporaryDirectory(prefix='repo-assist-agent-fixture-', dir='/tmp') as directory:
        base = Path(directory)
        runner, workspace, fixture = (base / name for name in ('runner', 'workspace', 'fixture'))
        for path in (runner, workspace, fixture, base / 'mcp-proof', base / 'difc-proof', base / 'model-proof'):
            path.mkdir()
        validation = runner / 'cache/repo-assist/bin'
        validation.mkdir(parents=True)
        shutil.copy2(jq, validation / 'jq')
        trusted = Path(shutil.copytree(worker_root, runner / 'trusted', ignore=shutil.ignore_patterns('__pycache__')))
        cli = runner / 'repo-assist-cli/node_modules/.bin'
        cli.mkdir(parents=True)
        (cli / 'claude').write_text(AGENT_FIXTURE)
        (cli / 'claude').chmod(0o755)
        (fixture / 'server.py').write_text(NATIVE_FIXTURE)
        # Ephemeral, synthetic CA/server key. No live GitHub/Anthropic access.
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:api.anthropic.com',
                        '-keyout', str(fixture / 'key.pem'), '-out', str(fixture / 'ca.crt')],
                       check=True, capture_output=True)
        shutil.copyfile(fixture / 'ca.crt', trusted / 'fixture-ca.crt')
        git_env = {'PATH': os.environ['PATH'], 'HOME': str(base), 'GIT_CONFIG_NOSYSTEM': '1',
                   'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_AUTHOR_NAME': 'Fixture',
                   'GIT_COMMITTER_NAME': 'Fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
                   'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}
        for args in (['init', '--template=', str(workspace)],
                     ['-C', str(workspace), 'commit', '--allow-empty', '-m', 'Synthetic fixture']):
            subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', *args],
                           env=git_env, check=True, capture_output=True)
        original_config = (workspace / '.git/config').read_bytes()
        mcp = runner / 'gh-aw/mcp-config/mcp-servers.json'
        mcp.parent.mkdir(parents=True)
        mcp.write_text(json.dumps({'mcpServers': {'safeoutputs': {'type': 'http',
            'url': 'http://localhost:8080/mcp/safeoutputs', 'headers': {'Authorization': 'Bearer synthetic-mcp-token'},
            'tools': ['*']}}}))
        env = {key: os.environ[key] for key in ('PATH', 'HOME', 'DOCKER_HOST', 'DOCKER_CONTEXT',
               'DOCKER_CONFIG', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY') if key in os.environ}
        env.update({'RUNNER_TEMP': str(runner), 'RUNNER_TOOL_CACHE': str(runner / 'cache'),
            'GITHUB_WORKSPACE': str(workspace), 'GITHUB_REPOSITORY': 'fixture/repo',
            'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1',
            'CLAUDE_CODE_OAUTH_TOKEN': 'synthetic-only-no-model-call',
            'REPO_ASSIST_READ_TOKEN': 'synthetic-read-token', 'GH_TOKEN': 'synthetic-host-token',
            'GITHUB_TOKEN': 'synthetic-host-token', 'ACTIONS_RUNTIME_TOKEN': 'synthetic-host-token'})
        network = 'repo-assist-native-' + base.name
        tls_container = network + '-tls'
        created = []
        artifacts = Path('/tmp/gh-aw')
        backup = base / 'native-artifacts-backup'
        # CI executes these tests twice; preserve any earlier native artifacts.
        if os.path.lexists(artifacts):
            artifacts.rename(backup)
        try:
            (artifacts / 'aw-prompts').mkdir(parents=True)
            (artifacts / 'host-fixture-marker').write_text('host scratch must not be mounted')
            (artifacts / 'aw-prompts/prompt.txt').write_text('Synthetic agent lifecycle prompt\n')
            (artifacts / 'difc-proxy-tls').mkdir()
            shutil.copyfile(fixture / 'ca.crt', artifacts / 'difc-proxy-tls/ca.crt')
            worker.docker('network', 'create', '--internal', network)
            for name, mode, port, attached_network in (
                    ('awmg-mcpg', 'mcp', 8080, network), ('awmg-cli-proxy', 'difc', 18443, network),
                    (tls_container, 'model', 18444, 'bridge')):
                args = confinement(name, attached_network) + mount(fixture, '/fixture')
                args += mount(base / (mode + '-proof'), '/proof', writable=True)
                args += ['--entrypoint', 'python3', AGENT_IMAGE, '/fixture/server.py', mode]
                subprocess.run(args, check=True, capture_output=True)
                created.append(name)
                worker.docker('start', name)
                for _ in range(60):
                    ready = subprocess.run(['docker', 'exec', name, 'python3', '-c',
                        f'import socket;socket.create_connection(("127.0.0.1",{port}),timeout=1).close()'],
                        capture_output=True, timeout=5)
                    if ready.returncode == 0:
                        break
                    time.sleep(0.1)
                else:
                    test.fail(worker.docker('logs', name))
            tls_state = json.loads(worker.docker('inspect', tls_container))[0]
            upstream_ip = tls_state['NetworkSettings']['Networks']['bridge']['IPAddress']
            (trusted / 'fixture-upstream.json').write_text(json.dumps({'ip': upstream_ip}))
            # Preserve the production CONNECT/SNI handler. Only this temporary
            # copy replaces public DNS/upstream dialing with a controlled TLS
            # endpoint on the EXTERNAL bridge, unreachable directly by the worker.
            # Separate gateway tests cover the real public-address validation.
            egress = trusted / 'repo-assist-egress.py'
            egress.write_text('import asyncio,sys,types\n'
                'module=types.ModuleType("fixture_gateway")\n'
                'sys.modules[module.__name__]=module\n'
                f'exec(compile({egress.read_text()!r},"production-egress.py","exec"),module.__dict__)\n'
                'async def fixture_upstream(self):\n'
                f' return await asyncio.open_connection({upstream_ip!r},18444)\n'
                'module.Gateway.connect_upstream=fixture_upstream\nmodule.main()\n')
            # The probe observes, but never stubs out, the final publication
            # guard and cleanup. Retain synthetic diagnostics for CI failures.
            probe = r'''import importlib.util,subprocess,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
spec=importlib.util.spec_from_file_location('worker',sys.argv[1]+'/repo-assist-worker.py')
worker=importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)
guard,cleanup=worker.enforce_publication,worker.cleanup
def observe_guard(secret,workspace,roots,runner):
 original_metadata='[fixture]' in (workspace/'.git/config').read_text()
 guard(secret,workspace,roots,runner)
 (runner/'guard-passed').write_text(str(original_metadata))
def observe_cleanup(args):
 try:
  if args[:2]==['rm','--force']:
   name=args[2]
   with (Path(sys.argv[2])/(name+'.log')).open('w') as log:
    commands=[]
    if name.endswith('-cli') and sys.exc_info()[0] is not None:
     # No environment/credential dump. Capture the stalled tunnel process and
     # effective cgroup constraints before Docker removes its namespace.
     commands=[['inspect','--format','{{json .State}}',name],
      ['top',name,'-eo','pid,ppid,stat,etime,time,args'],
      ['exec',name,'sh','-c',
       'for f in /sys/fs/cgroup/cpu.stat /sys/fs/cgroup/cpu.max '
       '/sys/fs/cgroup/memory.events /sys/fs/cgroup/memory.current /sys/fs/cgroup/memory.max '
       '/sys/fs/cgroup/pids.current /sys/fs/cgroup/pids.max '
       '/proc/1/limits /proc/1/cgroup /proc/net/tcp /proc/net/tcp6; do echo "=== $f"; cat "$f"; done; '
       'for d in /proc/[0-9]*; do echo "=== $d"; '
       'grep -E "^(Name|State|Pid|PPid|Threads|VmRSS|VmSize):" "$d/status"; '
       'cat "$d/wchan"; echo; done']]
    commands.append(['logs','--timestamps',name])
    for command in commands:
     log.write('=== docker '+command[0]+' '+name+'\n');log.flush()
     try: subprocess.run(['docker',*command],stdout=log,stderr=subprocess.STDOUT,timeout=5)
     except (OSError,subprocess.SubprocessError) as error:
      log.write('Diagnostic unavailable: '+type(error).__name__+'\n')
 finally: cleanup(args)
worker.enforce_publication=observe_guard
worker.cleanup=observe_cleanup
try: worker.run('agent')
except subprocess.CalledProcessError as error:
 print(error.stderr,file=sys.stderr)
 raise
'''
            result = subprocess.run([sys.executable, '-c', probe, str(trusted), str(runner)],
                                    capture_output=True, text=True, env=env, timeout=180)
            logs = '\n'.join(path.read_text() for path in runner.glob('*.log'))
            test.assertEqual(result.returncode, 0, result.stderr + logs)
            test.assertEqual(json.loads((workspace / 'agent-proof.json').read_text()),
                             {'gh_read': True, 'mcp': True, 'tls': True, 'direct_denied': True,
                              'jq': True, 'scratch': True})
            test.assertFalse((artifacts / 'agent/issues.json').exists())
            test.assertEqual((runner / 'guard-passed').read_text(), 'True')
            test.assertEqual((workspace / '.git/config').read_bytes(),
                             original_config + b'\n[core]\n\thooksPath = /dev/null\n')
            test.assertEqual((artifacts / 'agent_execution_exit_code.txt').read_text(), '0')
            require_completion((artifacts / 'agent-stdio.log').read_text())
            usage = artifacts / 'sandbox/firewall/logs/api-proxy-logs/token-usage.jsonl'
            test.assertEqual(usage.read_text(), 'null\n')
            requests = [json.loads(line) for line in (base / 'difc-proof/requests.jsonl').read_text().splitlines()]
            for endpoint in ('/rate_limit', '/repos/fixture/repo/issues/1'):
                test.assertTrue(any(item.get('path', '').removeprefix('/api/v3') == endpoint
                                    and item.get('service') == 'difc' for item in requests), requests)
            tls_requests = [json.loads(line) for line in (base / 'model-proof/requests.jsonl').read_text().splitlines()]
            test.assertIn({'service': 'model-tls', 'sni': 'api.anthropic.com'}, tls_requests)
            methods = [json.loads(line).get('method')
                       for line in (base / 'mcp-proof/requests.jsonl').read_text().splitlines()]
            test.assertEqual(methods, ['initialize', 'tools/list'])
            for name in created:
                state = json.loads(worker.docker('inspect', name))[0]
                test.assertEqual(set(state['NetworkSettings']['Networks']),
                                 {'bridge'} if name == tls_container else {network})
        finally:
            for name in reversed(created):
                worker.cleanup(['rm', '--force', name])
            worker.cleanup(['network', 'rm', network])
            if artifacts.exists():
                shutil.rmtree(artifacts)
            if os.path.lexists(backup):
                backup.rename(artifacts)
