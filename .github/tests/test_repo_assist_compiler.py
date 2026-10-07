"""Exercise generated detection conditions and compiler provenance boundaries."""

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]
BUILD_SCRIPT = ROOT / ".github/scripts/build-repo-assist-compiler.sh"
PATCH = ROOT / ".github/patches/gh-aw-detection-prerequisites.patch"


class CompilerRegressionTests(unittest.TestCase):
    def test_reviewed_source_fixture_does_not_fetch_lfs_assets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            filter_script = root / "lfs-filter"
            filter_script.write_text(
                '#!/bin/sh\n[ "$GIT_LFS_SKIP_SMUDGE" = 1 ] || exit 91\ncat\n'
            )
            filter_script.chmod(0o700)
            config = {
                "GIT_LFS_SKIP_SMUDGE": "0",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_COUNT": "3",
                "GIT_CONFIG_KEY_0": "filter.lfs.clean",
                "GIT_CONFIG_VALUE_0": "cat",
                "GIT_CONFIG_KEY_1": "filter.lfs.smudge",
                "GIT_CONFIG_VALUE_1": str(filter_script),
                "GIT_CONFIG_KEY_2": "filter.lfs.required",
                "GIT_CONFIG_VALUE_2": "true",
            }
            with patch.dict(os.environ, config):
                clone = self.clone_reviewed_source(root)
            self.assertTrue(
                (clone / "docs/slides/gh-aw-theme.css")
                .read_text()
                .startswith("version https://git-lfs.github.com/spec/v1")
            )

    def test_mismatched_go_is_rejected_before_patch_or_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clone = self.clone_reviewed_source(root)
            binary_dir = root / "bin"
            binary_dir.mkdir()
            calls = root / "go-calls"
            (binary_dir / "go").write_text(
                '#!/bin/sh\nprintf "%s\\n" "$*" >> "$GO_CALLS"\n'
                'printf "%s\\n" go1.26.8\n'
            )
            (binary_dir / "go").chmod(0o700)
            result = subprocess.run(
                ["bash", str(BUILD_SCRIPT), str(clone)],
                text=True,
                capture_output=True,
                check=False,
                env={
                    **os.environ,
                    "PATH": f"{binary_dir}:{os.environ['PATH']}",
                    "GO_CALLS": str(calls),
                },
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Compiler build requires Go 1.27.0", result.stderr)
            self.assertEqual(calls.read_text().splitlines(), ["env GOVERSION"])
            self.assertFalse(
                (clone / "pkg/workflow/threat_detection_prerequisites_test.go").exists()
            )

    @staticmethod
    def clone_reviewed_source(directory: Path) -> Path:
        source = Path(
            os.environ.get(
                "REPO_ASSIST_COMPILER_SOURCE", ROOT / ".repo-assist-compiler"
            )
        )
        if not (source / ".git").exists():
            raise AssertionError(
                "Build the pinned compiler first and set REPO_ASSIST_COMPILER_SOURCE"
            )
        clone = directory / "compiler-source"
        # These fixtures need compiler code, not upstream slide assets.
        # A local clone has no LFS objects, even when the runner has Git LFS.
        checkout_env = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "1"}
        subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--shared",
                "--no-hardlinks",
                "--no-checkout",
                str(source),
                str(clone),
            ],
            check=True,
            env=checkout_env,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(clone),
                "checkout",
                "--quiet",
                "--detach",
                "d534c311af32e1e3d26f2015d9b95d738633a2b5",
            ],
            check=True,
            env=checkout_env,
        )
        return clone

    def test_dirty_reviewed_source_is_rejected_before_patch_or_build(self) -> None:
        for kind in ("tracked", "untracked"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                clone = self.clone_reviewed_source(root)
                changed = (
                    clone
                    / "pkg/workflow"
                    / (
                        "threat_detection_external.go"
                        if kind == "tracked"
                        else "unreviewed.go"
                    )
                )
                with changed.open("a") as output:
                    output.write("\n// Unreviewed fixture change.\n")
                binary_dir = root / "bin"
                binary_dir.mkdir()
                called = root / "go-called"
                (binary_dir / "go").write_text(
                    '#!/bin/sh\ntouch "$GO_CALLED"\nexit 91\n'
                )
                (binary_dir / "go").chmod(0o700)
                result = subprocess.run(
                    [
                        "bash",
                        str(BUILD_SCRIPT),
                        str(clone),
                    ],
                    text=True,
                    capture_output=True,
                    check=False,
                    env={
                        **os.environ,
                        "PATH": f"{binary_dir}:{os.environ['PATH']}",
                        "GO_CALLED": str(called),
                    },
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "Compiler source must be a clean checkout before patching",
                    result.stderr,
                )
                self.assertFalse(
                    called.exists(), "Dirty source reached the Go build tool"
                )
                self.assertFalse(
                    (
                        clone / "pkg/workflow/threat_detection_prerequisites_test.go"
                    ).exists(),
                    "Dirty source was patched",
                )

    def test_generated_conditions_preserve_failure_boundaries(self) -> None:
        workflow = yaml.load(
            (ROOT / ".github/workflows/repo-assist.lock.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        detection = workflow["jobs"]["detection"]
        execution = next(
            s
            for s in detection["steps"]
            if s.get("id") == "detection_agentic_execution"
        )
        diagnostics = [
            {"name": s["name"], "if": s["if"]}
            for s in detection["steps"]
            if s.get("id") == "detection_conclusion"
            or s.get("name") == "Upload threat detection artifact"
        ]
        self.assertEqual(len(diagnostics), 2)
        fixture = [
            {
                "repo": ROOT.name,
                "job_if": detection["if"],
                "execute_if": execution["if"],
                "publication_if": workflow["jobs"]["safe_outputs"]["if"],
                "diagnostics": diagnostics,
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "conditions.json"
            path.write_text(json.dumps(fixture))
            result = subprocess.run(
                [
                    "node",
                    str(
                        ROOT / ".github/tests/expression-evaluator/check-conditions.mjs"
                    ),
                    str(path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["assertions"], 12)

    def test_changed_patch_is_rejected_before_source_access(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / ".github/scripts/build-repo-assist-compiler.sh"
            script.parent.mkdir(parents=True)
            script.write_bytes(BUILD_SCRIPT.read_bytes())
            patch = root / ".github/patches/gh-aw-detection-prerequisites.patch"
            patch.parent.mkdir(parents=True)
            patch.write_bytes(PATCH.read_bytes() + b"unreviewed change\n")
            result = subprocess.run(
                ["bash", str(script), str(root / "absent-source")],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Compiler patch digest mismatch", result.stderr)
        self.assertNotIn("not a git repository", result.stderr)

    def test_unreviewed_source_commit_is_rejected_before_building(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "commit",
                    "--quiet",
                    "--allow-empty",
                    "-m",
                    "test: unreviewed source",
                ],
                check=True,
            )
            result = subprocess.run(
                ["bash", str(BUILD_SCRIPT), str(root)],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Compiler source must be the reviewed v0.90.0 commit", result.stderr
        )

    def test_generated_version_keeps_runtime_release_checks_active(self) -> None:
        lines = (
            (ROOT / ".github/workflows/repo-assist.lock.yml").read_text().splitlines()
        )
        metadata = next(line for line in lines if line.startswith("# gh-aw-metadata: "))
        self.assertEqual(
            json.loads(metadata.removeprefix("# gh-aw-metadata: "))["compiler_version"],
            "v0.90.0",
        )
        self.assertIn(
            hashlib.sha256(PATCH.read_bytes()).hexdigest(), BUILD_SCRIPT.read_text()
        )


if __name__ == "__main__":
    unittest.main()
