"""Exercise the real installer and installed safety hook in disposable homes."""

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class HookInstallationTest(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        for name, output in (("claude", ""), ("gh", ""), ("node", "v24.0.0")):
            self.executable(self.bin / name, f"#!/bin/sh\nprintf '%s\\n' {shlex.quote(output)}\n")
        self.env = dict(os.environ, HOME=str(self.home), PATH=f"{self.bin}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin")
        self.hook = self.home / ".claude/hooks/block-dangerous.sh"

    def executable(self, path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o755)

    def install(self, source=ROOT):
        return subprocess.run(["/bin/bash", str(source / "setup.sh"), "--non-interactive"],
                              check=False, env=self.env, cwd=self.root, capture_output=True, text=True, timeout=30)

    def installed(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def trusted_python(self):
        directory = self.home / ".pyenv"
        directory.mkdir()
        (directory / "version").write_text("fixture\n")
        self.executable(directory / "versions/fixture/bin/python3",
                        f"#!/bin/sh\nexec {shlex.quote(sys.executable)} \"$@\"\n")

    def invoke(self, command=None, raw=None, env=None):
        payload = raw if raw is not None else json.dumps({"tool_input": {"command": command}})
        return subprocess.run([str(self.hook)], check=False, input=payload, env=env or self.env,
                              cwd=self.root, capture_output=True, text=True, timeout=10)

    def test_installs_exact_published_dependency_set(self):
        self.installed()
        expected = {
            "block-dangerous.sh": ("756788c05ca014e82ee67bf5c390e82e18d5d85d4ea8355fa6524d5cb4a60ad4", 0o755),
            "block-dangerous.py": ("1ac3b6da09f259e95244a2a4906ef9ab671a040d136c4700c972780afcdd288b", 0o755),
        }
        for name, (digest, mode) in expected.items():
            path = self.hook.parent / name
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            self.assertEqual(path.stat().st_mode & 0o777, mode)
        helper = self.hook.parent / "lib/python-path.sh"
        self.assertEqual(helper.read_bytes(), (ROOT / "hooks/lib/python-path.sh").read_bytes())
        self.assertEqual(hashlib.sha256(helper.read_bytes()).hexdigest(),
                         "1b908f2f484f1e4aa8730f17f8c3e290eb8047e0a6ff4e08abdc30314843e61b")
        self.assertEqual(helper.stat().st_mode & 0o777, 0o644)

    def test_malformed_payloads_fail_closed(self):
        self.installed()
        for raw in ("", "not-json", "{}", '{"tool_input":{"command":null}}',
                    '{"tool_input":{"command":""}} {}'):
            with self.subTest(raw=raw):
                result = self.invoke(raw=raw)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn('"permissionDecision":"deny"', result.stdout)
        self.assertEqual(self.invoke(command="").returncode, 0)

    def test_trusted_parser_distinguishes_commands_from_data(self):
        self.installed()
        self.trusted_python()
        for command, expected in (("rm -rf /", 2), ('echo "rm -rf /"', 0),
                                  ("find / -delete", 2), ("printf harmless", 0)):
            with self.subTest(command=command):
                self.assertEqual(self.invoke(command=command).returncode, expected)

    def test_repository_environment_cannot_execute_startup_code(self):
        self.installed()
        self.trusted_python()
        marker = self.root / "executed"
        poisoned = self.root / "poisoned"
        poisoned.mkdir()
        (poisoned / "sitecustomize.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
        subprocess.run([sys.executable, "-c", "pass"], env=dict(self.env, PYTHONPATH=str(poisoned)), check=True)
        self.assertTrue(marker.exists(), "startup-code positive control")
        marker.unlink()
        malicious = f"#!/bin/sh\ntouch {shlex.quote(str(marker))}\nprintf ALLOW\n"
        self.executable(poisoned / "python3", malicious)
        env = dict(self.env, PYTHONPATH=str(poisoned), CC_PYTHON=str(poisoned / "python3"),
                   PATH=f"{poisoned}:{self.env['PATH']}", PYENV_ROOT=str(poisoned), PYENV_VERSION="evil")
        (self.root / ".python-version").write_text("evil\n")
        for poison_jq in (False, True):
            with self.subTest(poison_jq=poison_jq):
                if poison_jq:
                    self.executable(poisoned / "jq", malicious)
                result = self.invoke(command="rm -rf /", env=env)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse(marker.exists(), "untrusted startup code ran")

    def test_missing_parser_denies_risky_input_with_trusted_python(self):
        self.installed()
        self.trusted_python()
        (self.hook.parent / "block-dangerous.py").unlink()
        self.assertEqual(self.invoke(command="rm -rf /").returncode, 2)
        self.assertEqual(self.invoke(command="printf harmless").returncode, 0)

    def test_no_trusted_python_uses_conservative_fallback(self):
        self.installed()
        self.assertEqual(self.invoke(command="rm -rf /").returncode, 2)
        self.assertEqual(self.invoke(command="find / -delete").returncode, 2)
        self.assertEqual(self.invoke(command="printf harmless").returncode, 0)

    def test_missing_manifest_helper_fails_before_success_tracking(self):
        source = self.root / "source"
        shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns(".git", "test"))
        manifest = source / "manifest.json"
        data = json.loads(manifest.read_text())
        data["files"] = [entry for entry in data["files"] if entry["dest"] != "hooks/lib/python-path.sh"]
        manifest.write_text(json.dumps(data))
        result = self.install(source)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("python-path.sh", result.stdout)
        self.assertFalse((self.home / ".claude/bd-kit.json").exists())
        self.assertNotIn("Installation complete!", result.stdout)

    def test_failure_gate_regression_rejects_success_exit_mutant(self):
        source = self.root / "mutant"
        shutil.copytree(ROOT, source, ignore=shutil.ignore_patterns(".git", "test"))
        setup = source / "setup.sh"
        original = setup.read_text()
        gate = '  error "Installation validation failed; no success tracking record was written."\n  exit 1'
        self.assertEqual(original.count(gate), 1)
        setup.write_text(original.replace(gate, gate.replace("exit 1", ":")))
        tests = source / "test"
        tests.mkdir()
        shutil.copyfile(__file__, tests / "test_hook_installation.py")
        result = subprocess.run(
            [sys.executable, str(tests / "test_hook_installation.py"),
             "HookInstallationTest.test_missing_manifest_helper_fails_before_success_tracking"],
            check=False, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("AssertionError: 0 == 0", result.stderr)
        self.assertIn("FAILED (failures=1)", result.stderr)


if __name__ == "__main__":
    unittest.main()
