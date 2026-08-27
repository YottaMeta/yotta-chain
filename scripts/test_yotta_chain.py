#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""yotta-chain (yuan lian) - unit tests.

Run:  python3 scripts/test_yotta_chain.py
"""
import argparse
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yotta_chain as yc


def write_files(base, files):
    for rel, content in files.items():
        p = Path(base) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


def scan_dir(path, level="info", gate="info"):
    args = argparse.Namespace(path=str(path), format="text", level=level, gate=gate, output=None)
    findings = []
    sbom = []
    root = {}
    eco = yc._collect(str(path), findings, sbom, root)
    return eco, findings


def rules_of(findings):
    return {f.rule for f in findings}


def has(findings, rule):
    return any(f.rule == rule for f in findings)


class TestSemver(unittest.TestCase):
    def test_caret(self):
        self.assertTrue(yc.semver_satisfies("1.2.3", "^1.2.0"))
        self.assertTrue(yc.semver_satisfies("1.9.9", "^1.2.0"))
        self.assertFalse(yc.semver_satisfies("2.0.0", "^1.2.0"))
        self.assertTrue(yc.semver_satisfies("0.2.5", "^0.2.3"))
        self.assertFalse(yc.semver_satisfies("0.3.0", "^0.2.3"))

    def test_tilde(self):
        self.assertTrue(yc.semver_satisfies("1.2.9", "~1.2.0"))
        self.assertFalse(yc.semver_satisfies("1.3.0", "~1.2.0"))
        self.assertTrue(yc.semver_satisfies("1.2.0", "~1.2"))

    def test_comparators(self):
        self.assertTrue(yc.semver_satisfies("1.5.0", ">=1.2.0 <2.0.0"))
        self.assertFalse(yc.semver_satisfies("2.0.0", ">=1.2.0 <2.0.0"))
        self.assertTrue(yc.semver_satisfies("1.2.3", "<=1.2.3"))
        self.assertFalse(yc.semver_satisfies("1.2.4", "<=1.2.3"))

    def test_xrange(self):
        self.assertTrue(yc.semver_satisfies("1.2.9", "1.2.x"))
        self.assertFalse(yc.semver_satisfies("1.3.0", "1.2.x"))
        self.assertTrue(yc.semver_satisfies("1.9.9", "1.x"))
        self.assertTrue(yc.semver_satisfies("1.2.3", "*"))

    def test_exact(self):
        self.assertTrue(yc.semver_satisfies("1.2.3", "1.2.3"))
        self.assertFalse(yc.semver_satisfies("1.2.4", "1.2.3"))

    def test_hyphen(self):
        self.assertTrue(yc.semver_satisfies("1.9.0", "1.2.3 - 2.0.0"))
        self.assertTrue(yc.semver_satisfies("2.0.0", "1.2.3 - 2.0.0"))
        self.assertFalse(yc.semver_satisfies("2.1.0", "1.2.3 - 2.0.0"))

    def test_or(self):
        self.assertTrue(yc.semver_satisfies("1.5.0", "^1.0.0 || ^2.0.0"))
        self.assertTrue(yc.semver_satisfies("2.5.0", "^1.0.0 || ^2.0.0"))
        self.assertFalse(yc.semver_satisfies("3.0.0", "^1.0.0 || ^2.0.0"))

    def test_prerelease_rule(self):
        self.assertFalse(yc.semver_satisfies("1.5.0-beta.1", "^1.0.0"))
        self.assertTrue(yc.semver_satisfies("1.5.0", "^1.0.0"))
        self.assertTrue(yc.semver_satisfies("1.5.0-beta.1", "^1.5.0-beta.0"))


class TestPep440(unittest.TestCase):
    def test_basic(self):
        self.assertTrue(yc.pep440_satisfies("2.31.0", ">=2.28"))
        self.assertFalse(yc.pep440_satisfies("2.27.0", ">=2.28"))
        self.assertTrue(yc.pep440_satisfies("2.31.0", "==2.31.0"))
        self.assertFalse(yc.pep440_satisfies("2.31.1", "==2.31.0"))
        self.assertTrue(yc.pep440_satisfies("2.31.0", ">=2.28,<3.0"))
        self.assertFalse(yc.pep440_satisfies("3.1.0", ">=2.28,<3.0"))

    def test_compatible(self):
        self.assertTrue(yc.pep440_satisfies("1.2.9", "~=1.2"))
        self.assertFalse(yc.pep440_satisfies("1.3.0", "~=1.2"))
        self.assertTrue(yc.pep440_satisfies("1.4.5", "~=1.4.5"))
        self.assertFalse(yc.pep440_satisfies("1.5.0", "~=1.4.5"))

    def test_wildcard(self):
        self.assertTrue(yc.pep440_satisfies("2.31.4", "==2.31.*"))
        self.assertFalse(yc.pep440_satisfies("2.32.0", "==2.31.*"))

    def test_pre_release_order(self):
        self.assertTrue(yc.pep440_satisfies("1.0.0b1", "<1.0.0"))
        self.assertFalse(yc.pep440_satisfies("1.0.0", "<1.0.0"))
        self.assertTrue(yc.pep440_satisfies("1.0.0", ">=1.0.0"))


class TestToml(unittest.TestCase):
    def test_tables_and_values(self):
        doc = '''
[project]
name = "demo"
version = "0.1.1"
dependencies = [
    "requests>=2.28",
    'flask<3.0',
]
[tool.poetry.dependencies]
python = "^3.8"
requests = { version = ">=2.28", extras = ["socks"] }
'''
        d = yc.parse_toml(doc)
        self.assertEqual(d["project"]["name"], "demo")
        self.assertEqual(d["project"]["dependencies"], ["requests>=2.28", "flask<3.0"])
        self.assertEqual(d["tool"]["poetry"]["dependencies"]["python"], "^3.8")
        self.assertEqual(d["tool"]["poetry"]["dependencies"]["requests"]["version"], ">=2.28")

    def test_array_of_tables_with_nested(self):
        doc = '''
[[package]]
name = "requests"
version = "2.31.0"
optional = false

[package.dependencies]
urllib3 = ">=1.21.1,<3"

[[package]]
name = "urllib3"
version = "2.0.4"

[[tool.poetry.source]]
name = "private"
url = "https://pypi.example.com/simple"
secondary = true
'''
        d = yc.parse_toml(doc)
        self.assertEqual(len(d["package"]), 2)
        self.assertEqual(d["package"][0]["name"], "requests")
        self.assertEqual(d["package"][0]["dependencies"]["urllib3"], ">=1.21.1,<3")
        self.assertEqual(d["package"][1]["name"], "urllib3")
        self.assertEqual(d["tool"]["poetry"]["source"][0]["url"], "https://pypi.example.com/simple")
        self.assertTrue(d["tool"]["poetry"]["source"][0]["secondary"])

    def test_triple_quoted_and_comments(self):
        doc = '''
[project]
description = """A long
description here."""
version = "1.0.0"  # inline comment
'''
        d = yc.parse_toml(doc)
        self.assertEqual(d["project"]["description"], "A long\ndescription here.")
        self.assertEqual(d["project"]["version"], "1.0.0")

    def test_dotted_key_and_inline_table(self):
        doc = 'a.b.c = 1\narr = [ {x = 1}, {x = 2} ]\n'
        d = yc.parse_toml(doc)
        self.assertEqual(d["a"]["b"]["c"], 1)
        self.assertEqual(d["arr"][0]["x"], 1)
        self.assertEqual(d["arr"][1]["x"], 2)


class TestRequirements(unittest.TestCase):
    def test_basic_pins(self):
        out = yc.parse_requirements("requests==2.31.0\nflask>=2.0\nfoo[extra]>=1.0; python_version < '3.9'\n")
        self.assertEqual(out["packages"]["requests"]["spec"], "==2.31.0")
        self.assertEqual(out["packages"]["flask"]["spec"], ">=2.0")
        self.assertEqual(out["packages"]["foo"]["spec"], ">=1.0")

    def test_index_flags(self):
        out = yc.parse_requirements(
            "--index-url https://pypi.example.com/simple\n"
            "--extra-index-url https://pypi.org/simple\n"
            "requests==2.31.0\n")
        self.assertEqual(out["index"], "https://pypi.example.com/simple")
        self.assertEqual(out["extra"], ["https://pypi.org/simple"])

    def test_hash_strip(self):
        out = yc.parse_requirements("requests==2.31.0 --hash=sha256:abc\n")
        self.assertEqual(out["packages"]["requests"]["spec"], "==2.31.0")
        self.assertTrue(out["packages"]["requests"]["has_hash"])


class TestTyposquat(unittest.TestCase):
    def test_hit(self):
        self.assertIsNotNone(yc.find_typosquat("lodassh", yc.POPULAR_NPM))
        self.assertIsNotNone(yc.find_typosquat("requets", yc.POPULAR_PYPI))

    def test_clean(self):
        self.assertIsNone(yc.find_typosquat("lodash", yc.POPULAR_NPM))
        self.assertIsNone(yc.find_typosquat("my-company-tool", yc.POPULAR_NPM))


NPM_LOCK_V3 = {
    "name": "demo",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "requires": True,
    "packages": {
        "": {"name": "demo", "version": "1.0.0",
             "dependencies": {"lodash": "^4.17.21", "express": "^4.18.0"}},
        "node_modules/lodash": {"version": "4.17.21",
                               "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                               "integrity": "sha512-aaa"},
        "node_modules/express": {"version": "4.18.2",
                                "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
                                "integrity": "sha512-bbb",
                                "dependencies": {"accepts": "^1.3.8"}},
        "node_modules/accepts": {"version": "1.3.8",
                                "resolved": "https://registry.npmjs.org/accepts/-/accepts-1.3.8.tgz",
                                "integrity": "sha512-ccc"},
    },
}


class TestNpmScan(unittest.TestCase):
    def test_clean_project(self):
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {
                "package.json": json.dumps({
                    "name": "demo", "version": "1.0.0",
                    "dependencies": {"lodash": "^4.17.21", "express": "^4.18.0"}}),
                "package-lock.json": json.dumps(NPM_LOCK_V3),
            })
            eco, findings = scan_dir(td)
            self.assertEqual(eco, ["npm"])
            self.assertEqual(findings, [])

    def test_missing_lockfile(self):
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {"package.json": json.dumps(
                {"name": "demo", "dependencies": {"lodash": "^4.17.21"}})})
            eco, findings = scan_dir(td)
            self.assertTrue(has(findings, "missing_lockfile"))

    def test_missing_entry(self):
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {
                "package.json": json.dumps(
                    {"name": "demo", "dependencies": {"ghostpkg": "^1.0.0"}}),
                "package-lock.json": json.dumps(NPM_LOCK_V3),
            })
            _, findings = scan_dir(td)
            self.assertTrue(has(findings, "lockfile_missing_entry"))

    def test_range_unsatisfied(self):
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {
                "package.json": json.dumps(
                    {"name": "demo", "dependencies": {"lodash": "^5.0.0"}}),
                "package-lock.json": json.dumps(NPM_LOCK_V3),
            })
            _, findings = scan_dir(td)
            self.assertTrue(has(findings, "lockfile_range_unsatisfied"))

    def test_dangling_ref(self):
        lock = json.loads(json.dumps(NPM_LOCK_V3))
        lock["packages"]["node_modules/express"]["dependencies"]["ghost"] = "^1.0.0"
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {
                "package.json": json.dumps(
                    {"name": "demo", "dependencies": {"express": "^4.18.0"}}),
                "package-lock.json": json.dumps(lock),
            })
            _, findings = scan_dir(td)
            self.assertTrue(has(findings, "lockfile_dangling_ref"))

    def test_missing_integrity(self):
        lock = json.loads(json.dumps(NPM_LOCK_V3))
        del lock["packages"]["node_modules/accepts"]["integrity"]
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {
                "package.json": json.dumps(
                    {"name": "demo", "dependencies": {"express": "^4.18.0"}}),
                "package-lock.json": json.dumps(lock),
            })
            _, findings = scan_dir(td)
            self.assertTrue(has(findings, "lockfile_integrity_missing"))

    def test_scope_registry_confusion(self):
        lock = json.loads(json.dumps(NPM_LOCK_V3))
        lock["packages"]["node_modules/@corp/secret"] = {
            "version": "1.0.0",
            "resolved": "https://registry.npmjs.org/@corp/secret/-/secret-1.0.0.tgz",
            "integrity": "sha512-ddd",
        }
        lock["packages"][""]["dependencies"]["@corp/secret"] = "^1.0.0"
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {
                "package.json": json.dumps(
                    {"name": "demo", "dependencies": {"@corp/secret": "^1.0.0"}}),
                "package-lock.json": json.dumps(lock),
                ".npmrc": "@corp:registry=https://npm.corp.example.com/\n",
            })
            _, findings = scan_dir(td)
            self.assertTrue(has(findings, "confusion_scope_registry"))

    def test_suspicious_resolved_url(self):
        lock = json.loads(json.dumps(NPM_LOCK_V3))
        lock["packages"]["node_modules/lodash"]["resolved"] = "http://registry.example.com/lodash.tgz"
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {
                "package.json": json.dumps(
                    {"name": "demo", "dependencies": {"lodash": "^4.17.21"}}),
                "package-lock.json": json.dumps(lock),
            })
            _, findings = scan_dir(td)
            self.assertTrue(has(findings, "confusion_suspicious_registry"))

    def test_mixed_registry(self):
        lock = json.loads(json.dumps(NPM_LOCK_V3))
        lock["packages"]["node_modules/express/node_modules/lodash"] = {
            "version": "4.17.21",
            "resolved": "https://mirror.corp.example.com/lodash.tgz",
            "integrity": "sha512-eee",
        }
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {
                "package.json": json.dumps(
                    {"name": "demo", "dependencies": {"lodash": "^4.17.21", "express": "^4.18.0"}}),
                "package-lock.json": json.dumps(lock),
            })
            _, findings = scan_dir(td)
            self.assertTrue(has(findings, "confusion_mixed_registry"))

    def test_unpinned_and_typosquat(self):
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {
                "package.json": json.dumps(
                    {"name": "demo", "dependencies": {"lodassh": "*", "express": "latest"}}),
                "package-lock.json": json.dumps(NPM_LOCK_V3),
            })
            _, findings = scan_dir(td)
            self.assertTrue(has(findings, "unpinned"))
            self.assertTrue(has(findings, "typosquat"))


class TestPythonScan(unittest.TestCase):
    def test_requirements_unpinned_and_typosquat(self):
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {"requirements.txt": "requests\nrequets==1.0.0\n"})
            eco, findings = scan_dir(td)
            self.assertIn("python", eco)
            self.assertTrue(has(findings, "unpinned"))
            self.assertTrue(has(findings, "typosquat"))

    def test_requirements_index_confusion(self):
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {"requirements.txt":
                "--index-url https://pypi.example.com/simple\n"
                "--extra-index-url https://pypi.org/simple\nrequests==2.31.0\n"})
            _, findings = scan_dir(td)
            self.assertTrue(has(findings, "confusion_extra_index"))

    def test_pyproject_missing_poetry_lock(self):
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {"pyproject.toml":
                '[tool.poetry.dependencies]\npython = "^3.8"\nrequests = ">=2.28"\n'})
            _, findings = scan_dir(td)
            self.assertTrue(has(findings, "missing_lockfile"))

    def test_poetry_lock_consistent(self):
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {
                "pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.8"\nrequests = ">=2.28"\n',
                "poetry.lock": '''
[[package]]
name = "requests"
version = "2.31.0"
files = [
    {file = "requests-2.31.0.tar.gz", hash = "sha256:aaa"},
]
[package.dependencies]
urllib3 = ">=1.21.1,<3"

[[package]]
name = "urllib3"
version = "2.0.4"
files = [
    {file = "urllib3-2.0.4.tar.gz", hash = "sha256:bbb"},
]
''',
            })
            eco, findings = scan_dir(td)
            self.assertIn("python", eco)
            self.assertFalse(has(findings, "lockfile_missing_entry"))
            self.assertFalse(has(findings, "lockfile_dangling_ref"))

    def test_poetry_lock_missing_entry_and_dangling(self):
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {
                "pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.8"\nflask = ">=2.0"\n',
                "poetry.lock": '''
[[package]]
name = "requests"
version = "2.31.0"
[package.dependencies]
ghost = "*"
''',
            })
            _, findings = scan_dir(td)
            self.assertTrue(has(findings, "lockfile_missing_entry"))
            self.assertTrue(has(findings, "lockfile_dangling_ref"))

    def test_pipfile_lock_consistent_and_missing(self):
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {
                "Pipfile": "[[source]]\nname = \"pypi\"\nurl = \"https://pypi.org/simple\"\n[packages]\nrequests = \">=2.28\"\n",
                "Pipfile.lock": json.dumps({
                    "_meta": {"hash": {"sha256": "x"}, "pipfile-spec": 6},
                    "default": {"requests": {"version": "==2.31.0", "hashes": ["sha256:abc"]}},
                    "develop": {},
                }),
            })
            _, findings = scan_dir(td)
            self.assertFalse(has(findings, "lockfile_missing_entry"))
            self.assertFalse(has(findings, "lockfile_integrity_missing"))

    def test_pipfile_missing_lock(self):
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {"Pipfile": "[packages]\nrequests = \">=2.28\"\n"})
            _, findings = scan_dir(td)
            self.assertTrue(has(findings, "missing_lockfile"))

    def test_pipfile_mixed_sources(self):
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {"Pipfile":
                '[[source]]\nname = "private"\nurl = "https://pypi.example.com/simple"\n'
                '[[source]]\nname = "pypi"\nurl = "https://pypi.org/simple"\n'
                '[packages]\nrequests = ">=2.28"\n'})
            _, findings = scan_dir(td)
            self.assertTrue(has(findings, "confusion_extra_index"))


class TestMavenScan(unittest.TestCase):
    def test_unpinned_snapshot_suspicious_repo(self):
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {"pom.xml": """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.demo</groupId><artifactId>app</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency><groupId>org.foo</groupId><artifactId>floating</artifactId></dependency>
    <dependency><groupId>org.foo</groupId><artifactId>snap</artifactId><version>2.0.0-SNAPSHOT</version></dependency>
    <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>32.1.0-jre</version></dependency>
  </dependencies>
  <repositories>
    <repository><id>insecure</id><url>http://repo.example.com/maven2</url></repository>
  </repositories>
</project>"""})
            eco, findings = scan_dir(td)
            self.assertIn("maven", eco)
            self.assertTrue(has(findings, "unpinned"))
            self.assertTrue(has(findings, "snapshot"))
            self.assertTrue(has(findings, "confusion_suspicious_registry"))


class TestSbom(unittest.TestCase):
    def _pkgs(self):
        return [
            {"ecosystem": "npm", "name": "@corp/secret", "version": "1.0.0",
             "resolved": "https://registry.npmjs.org/@corp/secret.tgz", "integrity": "sha512-abc",
             "scope": "required", "direct": True, "deps": []},
            {"ecosystem": "npm", "name": "lodash", "version": "4.17.21",
             "resolved": "https://registry.npmjs.org/lodash.tgz", "integrity": "sha512-def",
             "scope": "required", "direct": True, "deps": []},
            {"ecosystem": "python", "name": "requests", "version": "2.31.0",
             "resolved": "", "integrity": "sha256:xxx",
             "scope": "optional", "direct": False, "deps": []},
        ]

    def test_cyclonedx_structure(self):
        bom = yc.build_sbom(self._pkgs(), include_dev=True,
                            root_component={"ecosystem": "npm", "name": "demo", "version": "1.0.0"})
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.5")
        self.assertEqual(bom["metadata"]["component"]["name"], "demo")
        names = [c["name"] for c in bom["components"]]
        self.assertIn("@corp/secret", names)
        self.assertIn("requests", names)
        scoped = [c for c in bom["components"] if c["name"] == "@corp/secret"][0]
        self.assertTrue(scoped["purl"].startswith("pkg:npm/%40corp/secret@1.0.0"))
        root_dep = [d for d in bom["dependencies"] if d["ref"].startswith("pkg:npm/demo@")][0]
        self.assertEqual(len(root_dep["dependsOn"]), 2)

    def test_exclude_dev(self):
        bom = yc.build_sbom(self._pkgs(), include_dev=False)
        names = {c["name"] for c in bom["components"]}
        self.assertNotIn("requests", names)


class TestCli(unittest.TestCase):
    def _run(self, td, cmd="scan"):
        if cmd == "scan":
            args = argparse.Namespace(path=td, format="json", level="info", gate="info", output=None)
            return yc.cmd_scan(args)
        args = argparse.Namespace(path=td, format="cyclonedx", exclude_dev=False, output=None)
        return yc.cmd_sbom(args)

    def test_scan_clean_exit0(self):
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {
                "package.json": json.dumps({"name": "demo", "dependencies": {"lodash": "^4.17.21"}}),
                "package-lock.json": json.dumps(NPM_LOCK_V3),
            })
            self.assertEqual(self._run(td), 0)

    def test_scan_findings_exit1(self):
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {"requirements.txt": "requests\n"})
            self.assertEqual(self._run(td), 1)

    def test_scan_no_project_exit4(self):
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {"notes.txt": "nothing here"})
            self.assertEqual(self._run(td), 4)

    def test_sbom_exit0_and_json(self):
        import io
        from contextlib import redirect_stdout
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {
                "package.json": json.dumps({"name": "demo", "dependencies": {"lodash": "^4.17.21"}}),
                "package-lock.json": json.dumps(NPM_LOCK_V3),
            })
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = self._run(td, cmd="sbom")
            self.assertEqual(code, 0)
            data = json.loads(buf.getvalue())
            self.assertEqual(data["bomFormat"], "CycloneDX")

    def test_version(self):
        self.assertEqual(yc.VERSION, "0.1.1")


class TestNpmLockV1(unittest.TestCase):
    def test_v1_parse_and_clean(self):
        lock_v1 = {
            "name": "demo",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {"version": "4.17.21",
                           "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                           "integrity": "sha512-aaa"},
                "@corp/secret": {"version": "1.0.0",
                                 "resolved": "https://registry.npmjs.org/@corp/secret.tgz",
                                 "integrity": "sha512-bbb",
                                 "requires": {"lodash": "^4.0.0"}},
            },
        }
        parsed = yc.parse_package_lock(json.dumps(lock_v1))
        self.assertEqual(parsed["lockfileVersion"], 1)
        self.assertIn("lodash", parsed["packages"])
        self.assertIn("@corp/secret", parsed["packages"])
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {
                "package.json": json.dumps({
                    "name": "demo", "version": "1.0.0",
                    "dependencies": {"lodash": "^4.17.21", "@corp/secret": "^1.0.0"}}),
                "package-lock.json": json.dumps(lock_v1),
            })
            _, findings = scan_dir(td)
            self.assertEqual(findings, [])

    def test_v1_dangling_requires(self):
        lock_v1 = {
            "name": "demo", "version": "1.0.0", "lockfileVersion": 1,
            "dependencies": {
                "pkg-a": {"version": "1.0.0",
                          "resolved": "https://registry.npmjs.org/pkg-a.tgz",
                          "requires": {"ghost": "^1.0.0"}},
            },
        }
        with tempfile.TemporaryDirectory() as td:
            write_files(td, {
                "package.json": json.dumps({"name": "demo", "dependencies": {"pkg-a": "^1.0.0"}}),
                "package-lock.json": json.dumps(lock_v1),
            })
            _, findings = scan_dir(td)
            self.assertTrue(has(findings, "lockfile_dangling_ref"))


class TestPep440Edge(unittest.TestCase):
    def test_not_equal(self):
        self.assertFalse(yc.pep440_satisfies("2.31.0", "!=2.31.0"))
        self.assertTrue(yc.pep440_satisfies("2.30.0", "!=2.31.0"))

    def test_dev_order(self):
        self.assertTrue(yc.pep440_satisfies("1.0.0.dev1", "<1.0.0"))
        self.assertTrue(yc.pep440_satisfies("1.0.0rc1", "<1.0.0"))
        self.assertFalse(yc.pep440_satisfies("1.0.0", "<1.0.0"))

    def test_post(self):
        self.assertTrue(yc.pep440_satisfies("1.0.0.post1", ">=1.0.0"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
