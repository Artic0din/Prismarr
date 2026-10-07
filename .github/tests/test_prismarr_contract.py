"""Check the fork-specific installation and credential boundaries."""
import os
import json
from pathlib import Path
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]


class PrismarrContractTests(unittest.TestCase):
    def source(self) -> dict:
        return yaml.load((ROOT / '.github/workflows/repo-assist.md').read_text().split('---', 2)[1], Loader=yaml.BaseLoader)

    def test_foreign_repository_fails_before_any_github_command(self):
        script = self.source()['on']['steps'][0]['run']
        result = subprocess.run(['bash', '-euo', 'pipefail', '-c', script],
                                env={'PATH': '/usr/bin:/bin', 'GITHUB_REPOSITORY': 'Shoshuo/Prismarr'},
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Only Artic0din/Prismarr', result.stdout)

    def test_publisher_uses_a_separate_main_only_environment(self):
        self.assertEqual(self.source()['jobs']['safe_outputs'].get('environment'), 'repo-assist-publisher')
        compiled = yaml.load((ROOT / '.github/workflows/repo-assist.lock.yml').read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(compiled['jobs']['safe_outputs'].get('environment'), 'repo-assist-publisher')

    def test_documentation_allowlist_includes_required_changelog_only(self):
        outputs = self.source()['safe-outputs']
        expected = ['README.md', 'CHANGELOG.md', 'docs/*.md', 'docs/**/*.md']
        for kind in ('create-pull-request', 'push-to-pull-request-branch'):
            self.assertEqual(outputs[kind]['allowed-files'], expected)

    def test_publisher_secret_is_scoped_to_publisher_job(self):
        compiled = yaml.load((ROOT / '.github/workflows/repo-assist.lock.yml').read_text(), Loader=yaml.BaseLoader)
        for name, job in compiled['jobs'].items():
            if name != 'safe_outputs':
                self.assertNotIn('secrets.REPO_ASSIST_GITHUB_TOKEN', str(job), name)
        self.assertEqual(compiled['jobs']['conclusion']['permissions'],
                         {'contents': 'read'})
        step = next(step for step in compiled['jobs']['conclusion']['steps'] if step['name'] == 'Log detection run')
        self.assertNotIn('handle_detection_runs.cjs', step['with']['script'])
        program = "const core = {info: value => process.stdout.write(JSON.stringify(value))};" + step['with']['script']
        result = subprocess.run(['node', '-e', program], capture_output=True, text=True,
                                env={'PATH': os.environ['PATH'], 'GH_AW_DETECTION_CONCLUSION': 'failure',
                                     'GH_AW_DETECTION_REASON': 'untrusted\n::error::message'})
        self.assertEqual(result.returncode, 0, result.stderr)
        logged = json.loads(result.stdout)
        self.assertTrue(logged.startswith('Independent detection: '))
        self.assertNotIn('\n', logged)

    def test_prompt_names_real_project_checks_and_public_fork_boundary(self):
        prompt = (ROOT / '.github/workflows/repo-assist.md').read_text().split('---', 2)[2]
        self.assertIn('PHP 8.4', prompt)
        self.assertIn('make check', prompt)
        self.assertIn('Never open a pull request against Shoshuo/Prismarr', prompt)
        self.assertNotIn('Plaintext-Lab', prompt)
        self.assertNotIn('Release Please', prompt)
        self.assertNotIn('Xcode', prompt)


if __name__ == '__main__':
    unittest.main()
