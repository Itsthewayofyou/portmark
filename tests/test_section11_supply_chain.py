"""Section 11 PR C, finding #4: locked, reproducible builds and release provenance.

Most of this is enforced by CI itself: the `lockfile` job regenerates the exports and proves a
tampered hash is refused, and every job installs with --require-hashes. These tests pin the
configuration those guarantees rest on, so an edit that quietly drops one fails here first.
"""

import importlib.util
import os
import re
import shutil
import subprocess  # nosec B404 -- runs the repository's own lock script
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
DOCKERFILE = ROOT / "Dockerfile"
SHA256_PIN = re.compile(r"@sha256:[0-9a-f]{64}\b")
ACTION_PIN = re.compile(r"uses:\s*[\w.\-/]+@[0-9a-f]{40}\s")
# The only accepted install forms: a hash-pinned export, the project itself without dependency
# resolution or an unpinned build environment, and CI's deliberate tampered-hash negative control.
ALLOWED_INSTALLS = (
    re.compile(r"pip install --require-hashes --no-deps -r requirements/(\w+)\.txt$"),
    re.compile(r"pip install --no-deps --no-build-isolation (?:-e )?\.(?: && python -m pip check)?$"),
    re.compile(r"pip install --require-hashes --no-deps --ignore-installed --dry-run -r (?:tampered\.txt 2> tampered\.err; then|requirements/runtime\.txt)$"),
)


# The single deliberate exception: the non-blocking weekly canary floats the one package it exists to
# test (it builds and publishes nothing). Allowed only in that file, only as exactly this command.
CANARY_EXCEPTION = ("wasmtime-canary.yml", "pip install --upgrade wasmtime")


def load_lock_script():
    spec = importlib.util.spec_from_file_location("lock_requirements", ROOT / "scripts" / "lock_requirements.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def install_commands():
    for path in [DOCKERFILE, *sorted(WORKFLOWS.glob("*.yml"))]:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "pip install" in line and not line.lstrip().startswith("#"):
                command = line.split("pip install", 1)[1].strip().rstrip("\\").strip()
                yield path.name, number, "pip install " + command


class SupplyChainConfigurationTests(unittest.TestCase):
    def test_every_install_uses_the_hash_locked_exports(self):
        seen = 0
        for name, number, command in install_commands():
            seen += 1
            if (name, command) == CANARY_EXCEPTION:
                continue
            with self.subTest(file=name, line=number):
                self.assertTrue(any(pattern.search(command) for pattern in ALLOWED_INSTALLS), command)
                match = ALLOWED_INSTALLS[0].search(command)
                if match:
                    self.assertTrue((ROOT / "requirements" / f"{match.group(1)}.txt").is_file(), command)
        self.assertGreater(seen, 10)

    def test_base_and_service_images_are_pinned_by_digest(self):
        from_lines = [line for line in DOCKERFILE.read_text().splitlines() if line.startswith("FROM ")]
        self.assertTrue(from_lines)
        for line in from_lines:
            self.assertRegex(line, SHA256_PIN)
        images = re.findall(r"^\s+image:\s*(\S+)", (WORKFLOWS / "ci.yml").read_text(), re.MULTILINE)
        self.assertTrue(images)
        for image in images:
            self.assertRegex(image, SHA256_PIN)

    def test_every_action_is_pinned_to_a_commit(self):
        for path in sorted(WORKFLOWS.glob("*.yml")):
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if re.match(r"\s*-?\s*uses:", line):
                    with self.subTest(file=path.name, line=number):
                        self.assertRegex(line + " ", ACTION_PIN)

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "needs PyYAML (from requirements/ci.txt)")
    def test_release_is_gated_on_main_built_locked_and_attested(self):
        release = (WORKFLOWS / "release.yml").read_text()
        self.assertIn("fetch-depth: 0", release)
        self.assertIn('git merge-base --is-ancestor "$TAG_COMMIT" refs/remotes/origin/main', release)
        self.assertIn('test "$TAG_COMMIT" = "$GITHUB_SHA"', release)
        self.assertIn("python -m build --no-isolation", release)
        self.assertIn("--format cyclonedx1.5", release)
        self.assertIn("actions/attest-build-provenance@", release)
        self.assertIn("actions/attest-sbom@", release)
        self.assertRegex(release, r"attestations:\s*true")
        # The attest job holds exactly the permissions the pinned actions/attest requires -- all three,
        # or the first real tag release fails in that job (auditor round 2: artifact-metadata was
        # missing) -- and no other job holds the attestation-only ones.
        import yaml

        jobs = yaml.safe_load(release)["jobs"]
        self.assertEqual(
            jobs["attest"]["permissions"],
            {"id-token": "write", "attestations": "write", "artifact-metadata": "write"},
        )
        for name, job in jobs.items():
            if name != "attest":
                with self.subTest(job=name):
                    self.assertNotIn("attestations", job.get("permissions", {}))
                    self.assertNotIn("artifact-metadata", job.get("permissions", {}))
        self.assertIn("attest", jobs["publish"]["needs"])  # nothing unattested is published

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "needs PyYAML (from requirements/ci.txt)")
    def test_ci_runs_the_suite_inside_the_exact_image_it_built(self):
        import yaml

        jobs = yaml.safe_load((WORKFLOWS / "ci.yml").read_text())["jobs"]
        runs = [step.get("run", "") for step in jobs["container"]["steps"]]
        builds = [run for run in runs if "docker build" in run]
        self.assertEqual(builds, ['docker build -t "$IMAGE" .'])
        inside = [run for run in runs if "python -m unittest discover -s tests" in run and "docker run" in run]
        self.assertEqual(len(inside), 1, runs)
        # The checkout is read-only and its src/ hidden, so the tests can only import the image's Portmark.
        for part in ['"$GITHUB_WORKSPACE":/repo:ro', "--tmpfs /repo/src", '"$IMAGE" python -m unittest']:
            self.assertIn(part, inside[0])
        self.assertTrue(any('test "$GOT" = "$WANT"' in run for run in runs))  # the image's Python is the pinned one
        self.assertTrue(any('PORTMARK_TEST_IMAGE="$IMAGE"' in run and "DeploymentProfileTests" in run for run in runs))
        # The no-Node skip is declared by that in-image run and nowhere else in any workflow.
        declared = [
            (path.name, line)
            for path in sorted(WORKFLOWS.glob("*.yml"))
            for line in path.read_text().splitlines()
            if "PORTMARK_TEST_ENV_HAS_NO_NODE" in line and not line.lstrip().startswith("#")
        ]
        self.assertEqual(len(declared), 1, declared)
        self.assertIn("PORTMARK_TEST_ENV_HAS_NO_NODE=1", inside[0])

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "needs PyYAML (from requirements/ci.txt)")
    def test_dependabot_never_proposes_an_untested_python(self):
        import yaml

        updates = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())["updates"]
        docker = [update for update in updates if update["package-ecosystem"] == "docker"]
        self.assertEqual(len(docker), 1)
        ignored = {
            kind
            for rule in docker[0].get("ignore", [])
            if rule.get("dependency-name") == "python"
            for kind in rule.get("update-types", [])
        }
        self.assertLessEqual({"version-update:semver-major", "version-update:semver-minor"}, ignored)
        self.assertNotIn("version-update:semver-patch", ignored)  # patch releases still come

    def test_bootstrap_setuptools_matches_the_declared_build_requirement(self):
        self.assertIsNone(load_lock_script().build_system_mismatch())

    @unittest.skipUnless(
        shutil.which("git") and shutil.which("bash") and os.name != "nt" and importlib.util.find_spec("yaml"),
        "needs git, bash, and PyYAML (from requirements/ci.txt)",
    )
    def test_the_release_main_gate_script_really_refuses_an_off_main_tag(self):
        # Runs the ACTUAL `run:` text of the release step against a scratch repository whose origin has
        # a main branch, so the gate is proven to refuse, not just to be present.
        import yaml

        steps = yaml.safe_load((WORKFLOWS / "release.yml").read_text())["jobs"]["build"]["steps"]
        script = next(step["run"] for step in steps if step.get("name") == "Check the tag's commit is on main")
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            git_env = {
                "PATH": os.environ["PATH"], "HOME": scratch, "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
            }

            def git(*args, cwd=root / "work"):
                return subprocess.run(["git", *args], cwd=cwd, env=git_env, check=True, capture_output=True, text=True).stdout.strip()  # nosec B603 B607

            subprocess.run(["git", "init", "-q", "--bare", str(root / "origin.git")], env=git_env, check=True)  # nosec B603 B607
            subprocess.run(["git", "init", "-q", "-b", "main", str(root / "work")], env=git_env, check=True)  # nosec B603 B607
            git("remote", "add", "origin", str(root / "origin.git"))
            git("commit", "-q", "--allow-empty", "-m", "on main")
            on_main = git("rev-parse", "HEAD")
            git("push", "-q", "origin", "main")
            git("update-ref", "-d", "refs/remotes/origin/main")  # like a fresh runner: the gate must fetch main
            git("tag", "-a", "v1.0.0", "-m", "release", on_main)  # annotated: the gate must peel it
            git("checkout", "-q", "-b", "side")
            git("commit", "-q", "--allow-empty", "-m", "never merged")
            off_main = git("rev-parse", "HEAD")
            git("tag", "v6.6.6", off_main)

            def gate(tag, sha):
                env = {**git_env, "GITHUB_REF_NAME": tag, "GITHUB_SHA": sha}
                return subprocess.run(  # nosec B603 B607 -- bash on the workflow's own step text
                    ["bash", "-e", "-c", script], cwd=root / "work", env=env, capture_output=True, text=True
                ).returncode

            self.assertEqual(gate("v1.0.0", on_main), 0)
            self.assertNotEqual(gate("v6.6.6", off_main), 0)  # a tag on a commit that is not on main
            self.assertNotEqual(gate("v1.0.0", off_main), 0)  # the run's commit is not the tag's commit

    @unittest.skipUnless(shutil.which("uv"), "needs uv; CI's lockfile job runs this check")
    def test_uv_lock_and_the_exports_are_current(self):
        result = subprocess.run(  # nosec B603 -- this interpreter, the repository's own script
            [sys.executable, str(ROOT / "scripts" / "lock_requirements.py"), "--check"],
            capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
