import io
import http.client
import json
import os
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security_review.service import (  # noqa: E402
    Config,
    GitLabClient,
    ReviewError,
    ReviewState,
    ReviewTarget,
    api_project,
    build_context_bundle,
    custom_models_endpoint,
    env_bool,
    effective_runtime_settings,
    is_context_candidate,
    list_llm_models,
    normalize_gitlab_group_path,
    normalized_archive_path,
    run_custom_llm,
    run_gemini,
    run_openai,
    parse_mr_url,
    scan_once,
    test_claude_api_key as verify_claude_api_key,
)
from security_review.web import (  # noqa: E402
    Credentials,
    MemoryVault,
    WebStore,
    application_page,
    collect_security_findings,
    completed_review_entries,
    decrypt_credentials,
    encrypt_credentials,
    paginate_repositories,
    parse_security_findings,
    password_record,
    report_section,
    render_diff_html,
    handler_factory,
    validated_credentials,
    verify_password,
)


def config_for_test(root: Path, **overrides):
    values = {
        "gitlab_url": "https://gitlab.example.com",
        "gitlab_token": "test-token",
        "llm_api_key": "test-anthropic-key",
        "report_dir": root / "reports",
        "state_db": root / "state.sqlite3",
        "skill_path": root / "SKILL.md",
        "poll_interval_seconds": 300,
        "max_reviews_per_cycle": 5,
        "review_existing_mrs": False,
        "max_diff_files": 200,
        "max_diff_bytes": 300_000,
        "max_archive_bytes": 10_000_000,
        "max_archive_members": 100,
        "max_context_files": 5,
        "max_context_file_bytes": 100_000,
        "max_context_bytes": 300_000,
        "max_context_scan_bytes": 1_000_000,
        "llm_model": "opus",
        "claude_max_budget_usd": "5.00",
        "claude_max_turns": "3",
    }
    values.update(overrides)
    return Config(**values)


def archive_with(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for path, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(f"project-abc123/{path}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


class ConfigurationTests(unittest.TestCase):
    def test_required_secrets_are_loaded(self):
        with patch.dict(
            os.environ,
            {"GITLAB_REVIEW_TOKEN": "gitlab-secret", "ANTHROPIC_API_KEY": "api-secret"},
            clear=True,
        ):
            config = Config.from_env()
        self.assertEqual(config.gitlab_url, "https://gitlab.com")
        self.assertEqual(config.llm_model, "opus")

    def test_group_path_is_loaded_and_validated(self):
        with patch.dict(
            os.environ,
            {
                "GITLAB_REVIEW_TOKEN": "gitlab-secret",
                "ANTHROPIC_API_KEY": "api-secret",
                "GITLAB_GROUP_PATH": "/company/platform/",
            },
            clear=True,
        ):
            config = Config.from_env()
        self.assertEqual(config.gitlab_group_path, "company/platform")
        self.assertEqual(normalize_gitlab_group_path(" maas "), "maas")
        with self.assertRaisesRegex(ReviewError, "Do not enter a URL"):
            normalize_gitlab_group_path("https://gitlab.example.com/maas")

    def test_placeholder_secret_is_rejected(self):
        with patch.dict(
            os.environ,
            {"GITLAB_REVIEW_TOKEN": "replace-me", "ANTHROPIC_API_KEY": "api-secret"},
            clear=True,
        ):
            with self.assertRaises(ReviewError):
                Config.from_env()

    def test_boolean_parsing(self):
        with patch.dict(os.environ, {"TEST_FLAG": "yes"}, clear=True):
            self.assertTrue(env_bool("TEST_FLAG", False))

    def test_zero_reviews_per_cycle_means_unlimited(self):
        settings = effective_runtime_settings({"MAX_REVIEWS_PER_CYCLE": "0"})
        self.assertEqual(settings["MAX_REVIEWS_PER_CYCLE"], "0")

    def test_managed_config_allows_gitlab_discovery_without_claude(self):
        config = Config.from_credentials(
            "https://gitlab.example.com", "gitlab-secret", ""
        )
        self.assertEqual(config.llm_api_key, "")

    def test_provider_defaults_are_selected(self):
        openai = Config.from_credentials(
            "https://gitlab.example.com",
            "gitlab-secret",
            "openai-secret",
            llm_provider="openai",
        )
        gemini = Config.from_credentials(
            "https://gitlab.example.com",
            "gitlab-secret",
            "gemini-secret",
            llm_provider="gemini",
        )
        self.assertEqual(openai.llm_model, "gpt-6-astra")
        self.assertEqual(gemini.llm_model, "gemini-3.8-flash")

    def test_anthropic_key_test_uses_claude_code_with_a_bounded_request(self):
        completed = subprocess.CompletedProcess(
            args=["claude"], returncode=0, stdout='{"result":"OK"}', stderr=""
        )
        with patch("security_review.service.subprocess.run", return_value=completed) as run:
            verify_claude_api_key("anthropic-test-key", "opus")
        command = run.call_args.args[0]
        self.assertIn("--bare", command)
        self.assertIn("--max-budget-usd", command)
        self.assertEqual(run.call_args.kwargs["env"]["ANTHROPIC_API_KEY"], "anthropic-test-key")

    def test_anthropic_key_test_rejects_an_empty_key_without_a_request(self):
        with patch("security_review.service.subprocess.run") as run:
            with self.assertRaises(ReviewError):
                verify_claude_api_key("")
        run.assert_not_called()

    def test_openai_uses_responses_api_without_storage(self):
        config = config_for_test(
            Path("/tmp"),
            llm_provider="openai",
            llm_model="gpt-test",
        )
        response = {
            "output": [{"content": [{"type": "output_text", "text": "# Report"}]}],
            "usage": {"input_tokens": 10, "output_tokens": 3},
        }
        with patch("security_review.service.post_json", return_value=response) as post:
            report, metadata = run_openai("review this", config)
        self.assertEqual(report, "# Report")
        self.assertEqual(metadata["usage"]["input_tokens"], 10)
        self.assertEqual(post.call_args.args[0], "https://api.openai.com/v1/responses")
        self.assertFalse(post.call_args.args[2]["store"])

    def test_gemini_uses_generate_content_api(self):
        config = config_for_test(
            Path("/tmp"),
            llm_provider="gemini",
            llm_model="gemini-test",
        )
        response = {
            "candidates": [{"content": {"parts": [{"text": "# Gemini report"}]}}]
        }
        with patch("security_review.service.post_json", return_value=response) as post:
            report, _ = run_gemini("review this", config)
        self.assertEqual(report, "# Gemini report")
        self.assertIn("gemini-test:generateContent", post.call_args.args[0])
        self.assertEqual(post.call_args.args[1]["x-goog-api-key"], "test-anthropic-key")

    def test_custom_provider_uses_exact_openai_compatible_endpoint(self):
        config = config_for_test(
            Path("/tmp"),
            llm_provider="custom",
            llm_api_url="https://llm.example.com/v1/chat/completions",
            llm_model="company-model",
        )
        response = {"choices": [{"message": {"content": "# Custom report"}}]}
        with patch("security_review.service.post_json", return_value=response) as post:
            report, _ = run_custom_llm("review this", config)
        self.assertEqual(report, "# Custom report")
        self.assertEqual(
            post.call_args.args[0], "https://llm.example.com/v1/chat/completions"
        )
        self.assertEqual(post.call_args.args[2]["model"], "company-model")

    def test_anthropic_models_are_fetched_with_api_headers(self):
        response = {"data": [{"id": "claude-opus"}, {"id": "claude-sonnet"}]}
        with patch(
            "security_review.service.get_provider_json", return_value=response
        ) as request:
            models = list_llm_models("anthropic", "anthropic-test-key")
        self.assertEqual(models, ["claude-opus", "claude-sonnet"])
        self.assertEqual(
            request.call_args.args[0],
            "https://api.anthropic.com/v1/models?limit=1000",
        )
        self.assertEqual(request.call_args.args[1]["x-api-key"], "anthropic-test-key")

    def test_gemini_model_fetch_keeps_generate_content_models(self):
        response = {
            "models": [
                {
                    "name": "models/gemini-generate",
                    "supportedGenerationMethods": ["generateContent"],
                },
                {
                    "name": "models/gemini-embed",
                    "supportedGenerationMethods": ["embedContent"],
                },
            ]
        }
        with patch("security_review.service.get_provider_json", return_value=response):
            models = list_llm_models("gemini", "gemini-test-key")
        self.assertEqual(models, ["gemini-generate"])

    def test_custom_model_endpoint_is_derived_from_completion_url(self):
        self.assertEqual(
            custom_models_endpoint(
                "https://llm.example.com/v1/chat/completions"
            ),
            "https://llm.example.com/v1/models",
        )
        response = {"data": [{"id": "company-model"}]}
        with patch(
            "security_review.service.get_provider_json", return_value=response
        ) as request:
            models = list_llm_models(
                "custom",
                "custom-test-key",
                "https://llm.example.com/v1/chat/completions",
            )
        self.assertEqual(models, ["company-model"])
        self.assertEqual(request.call_args.args[0], "https://llm.example.com/v1/models")

    def test_model_fetch_requires_an_api_key(self):
        with self.assertRaises(ReviewError):
            list_llm_models("openai", "")

    def test_gitlab_project_discovery_403_explains_required_permission(self):
        denied = urllib.error.HTTPError(
            "https://gitlab.example.com/api/v4/projects",
            403,
            "Forbidden",
            {},
            None,
        )
        with patch("security_review.service.urllib.request.urlopen", side_effect=denied):
            with self.assertRaisesRegex(ReviewError, "User boundary.*Project: Read"):
                GitLabClient(
                    "https://gitlab.example.com", "gitlab-test-token"
                ).list_projects()

    def test_group_project_discovery_uses_group_endpoint_and_subgroups(self):
        class Response(io.BytesIO):
            headers = {"X-Next-Page": ""}

        with patch(
            "security_review.service.urllib.request.urlopen",
            return_value=Response(b"[]"),
        ) as request:
            projects = GitLabClient(
                "https://gitlab.example.com",
                "gitlab-test-token",
                "company/platform",
            ).list_projects()
        self.assertEqual(projects, [])
        url = request.call_args.args[0].full_url
        parsed = urllib.parse.urlparse(url)
        self.assertEqual(
            parsed.path,
            "/api/v4/groups/company%2Fplatform/projects",
        )
        query = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(query["include_subgroups"], ["true"])
        self.assertEqual(query["with_shared"], ["false"])

    def test_gitlab_401_explains_invalid_or_expired_token(self):
        denied = urllib.error.HTTPError(
            "https://gitlab.example.com/api/v4/projects",
            401,
            "Unauthorized",
            {},
            None,
        )
        with patch("security_review.service.urllib.request.urlopen", side_effect=denied):
            with self.assertRaisesRegex(ReviewError, "active, not expired or revoked"):
                GitLabClient(
                    "https://gitlab.example.com", "gitlab-test-token"
                ).list_projects()


class PathTests(unittest.TestCase):
    def test_project_path_is_encoded(self):
        self.assertEqual(api_project("company/apps/api"), "company%2Fapps%2Fapi")

    def test_archive_prefix_is_removed(self):
        self.assertEqual(normalized_archive_path("repo-sha/src/app.py"), "src/app.py")

    def test_traversal_member_is_rejected(self):
        self.assertIsNone(normalized_archive_path("repo-sha/../secret"))

    def test_sensitive_files_are_not_context_candidates(self):
        self.assertFalse(is_context_candidate("config/private.key"))
        self.assertFalse(is_context_candidate(".env"))
        self.assertTrue(is_context_candidate(".env.example"))

    def test_mr_url_is_parsed(self):
        project, iid = parse_mr_url(
            "https://gitlab.example.com/company/apps/api/-/merge_requests/27"
        )
        self.assertEqual(project, "company/apps/api")
        self.assertEqual(iid, 27)


class ContextTests(unittest.TestCase):
    def test_changed_and_related_files_are_selected(self):
        data = archive_with(
            {
                "src/controller.py": (
                    "from service import lookup_user\n"
                    "def route(request): return lookup_user(request.args['name'])\n"
                ),
                "src/service.py": (
                    "def lookup_user(name):\n"
                    "    return database.execute('select ' + name)\n"
                ),
                "docs/readme.md": "unrelated documentation",
            }
        )
        diffs = [
            {
                "new_path": "src/controller.py",
                "old_path": "src/controller.py",
                "diff": "+def route(request): return lookup_user(request.args['name'])",
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            bundle = build_context_bundle(data, diffs, config_for_test(Path(directory)))
        self.assertIn("src/controller.py", bundle.files)
        self.assertIn("src/service.py", bundle.files)
        self.assertNotIn("docs/readme.md", bundle.files)

    def test_oversized_changed_file_is_reported(self):
        data = archive_with({"src/large.py": "x" * 1000})
        diffs = [{"new_path": "src/large.py", "diff": "+change"}]
        with tempfile.TemporaryDirectory() as directory:
            config = config_for_test(Path(directory), max_context_file_bytes=100)
            bundle = build_context_bundle(data, diffs, config)
        self.assertEqual(bundle.files, ())
        self.assertTrue(any("omitted" in note for note in bundle.notes))


class StateTests(unittest.TestCase):
    def test_review_revision_is_recorded_once(self):
        target = ReviewTarget(1, "company/app", 3, "abc123", "https://example/mr/3")
        with tempfile.TemporaryDirectory() as directory:
            state = ReviewState(Path(directory) / "state.sqlite3")
            self.assertFalse(state.has(target))
            state.record(
                target,
                "completed",
                report_content="# Security review\n",
                diff_content="## Changed file: app.py\n\n```diff\n+secure = True\n```",
                metadata_json='{"status":"completed"}',
            )
            self.assertTrue(state.has(target))
            stored = state.connection.execute(
                "SELECT report_content, diff_content, metadata_json FROM reviews"
            ).fetchone()
            self.assertEqual(stored[0], "# Security review\n")
            self.assertIn("+secure = True", stored[1])
            state.close()

    def test_new_head_sha_is_a_new_review(self):
        first = ReviewTarget(1, "company/app", 3, "abc123", "https://example/mr/3")
        second = ReviewTarget(1, "company/app", 3, "def456", "https://example/mr/3")
        with tempfile.TemporaryDirectory() as directory:
            state = ReviewState(Path(directory) / "state.sqlite3")
            state.record(first, "completed")
            self.assertFalse(state.has(second))
            state.close()


class CycleLimitTests(unittest.TestCase):
    class FakeState:
        def initialized(self):
            return True

        def has(self, target):
            return False

    def test_zero_limit_processes_every_pending_revision(self):
        targets = [
            ReviewTarget(1, "company/app", iid, f"sha{iid}", "") for iid in range(1, 8)
        ]
        with tempfile.TemporaryDirectory() as directory:
            config = config_for_test(Path(directory), max_reviews_per_cycle=0)
            with (
                patch("security_review.service.discover_targets", return_value=targets),
                patch("security_review.service.review_target", return_value="completed") as review,
            ):
                result = scan_once(object(), self.FakeState(), config)
        self.assertEqual(review.call_count, 7)
        self.assertEqual(result["deferred"], 0)

    def test_positive_limit_defers_remainder(self):
        targets = [
            ReviewTarget(1, "company/app", iid, f"sha{iid}", "") for iid in range(1, 8)
        ]
        with tempfile.TemporaryDirectory() as directory:
            config = config_for_test(Path(directory), max_reviews_per_cycle=5)
            with (
                patch("security_review.service.discover_targets", return_value=targets),
                patch("security_review.service.review_target", return_value="completed") as review,
            ):
                result = scan_once(object(), self.FakeState(), config)
        self.assertEqual(review.call_count, 5)
        self.assertEqual(result["deferred"], 2)

    def test_gitlab_only_scan_queues_mrs_for_later_review(self):
        targets = [
            ReviewTarget(1, "company/app", iid, f"sha{iid}", "")
            for iid in range(1, 4)
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReviewState(root / "state.sqlite3")
            discovery_config = config_for_test(root, llm_api_key="")
            with (
                patch("security_review.service.discover_targets", return_value=targets),
                patch("security_review.service.review_target") as review,
            ):
                discovered = scan_once(object(), state, discovery_config)
            self.assertEqual(review.call_count, 0)
            self.assertEqual(discovered["queued"], 3)
            self.assertEqual(discovered["pending"], 3)
            self.assertTrue(state.initialized())

            def complete(_client, review_state, _config, target):
                review_state.record(target, "completed")
                return "completed"

            review_config = config_for_test(root, max_reviews_per_cycle=0)
            with (
                patch("security_review.service.discover_targets", return_value=targets),
                patch("security_review.service.review_target", side_effect=complete) as review,
            ):
                reviewed = scan_once(object(), state, review_config)
            self.assertEqual(review.call_count, 3)
            self.assertEqual(reviewed["completed"], 3)
            self.assertTrue(all(state.has(target) for target in targets))
            state.close()


class DiscoveryInventoryTests(unittest.TestCase):
    class FakeGitLabClient:
        def list_projects(self):
            return [
                {
                    "id": 1,
                    "path_with_namespace": "company/first",
                    "web_url": "https://gitlab.example.com/company/first",
                },
                {
                    "id": 2,
                    "path_with_namespace": "company/second",
                    "web_url": "https://gitlab.example.com/company/second",
                },
            ]

        def list_open_merge_requests(self, project_path):
            if project_path == "company/first":
                return [
                    {
                        "iid": 1,
                        "sha": "before-deployment",
                        "web_url": "https://gitlab.example.com/company/first/-/merge_requests/1",
                        "created_at": "2026-09-14T09:00:00Z",
                    },
                    {
                        "iid": 2,
                        "sha": "after-deployment",
                        "web_url": "https://gitlab.example.com/company/first/-/merge_requests/2",
                        "created_at": "2026-09-15T11:00:00Z",
                    },
                ]
            return []

    def test_visible_projects_are_saved_and_predeployment_mrs_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "state.sqlite3"
            state = ReviewState(database)
            state.set_metadata("deployment_started_at", "2026-09-15T10:00:00+00:00")
            result = scan_once(
                self.FakeGitLabClient(),
                state,
                config_for_test(root, llm_api_key=""),
            )
            self.assertEqual(result["discovered"], 1)
            self.assertEqual(result["queued"], 1)
            stored_shas = [
                row[0] for row in state.connection.execute("SELECT head_sha FROM reviews")
            ]
            self.assertEqual(stored_shas, ["after-deployment"])
            projects = WebStore(database).visible_projects()
            self.assertEqual(len(projects), 2)
            statuses = {
                row["project_path"]: row["last_check_status"] for row in projects
            }
            self.assertEqual(statuses["company/first"], "up")
            self.assertEqual(statuses["company/second"], "up")
            state.close()

    def test_findings_are_parsed_counted_and_sorted_by_severity(self):
        reports = [
            {
                "project_id": 1,
                "project_path": "company/app",
                "project_web_url": "https://gitlab.example.com/company/app",
                "mr_iid": 7,
                "report_content": (
                    "# Security review\n\n## Findings\n\n"
                    "### [LOW] Verbose error\nFile: app.py:1\nMinor exposure.\n\n"
                    "### [CRITICAL] Command injection\nFile: shell.py:8\nUser input reaches a shell.\n"
                ),
            },
            {
                "project_id": 2,
                "project_path": "company/api",
                "project_web_url": "javascript:alert(1)",
                "mr_iid": 9,
                "report_content": (
                    "# Security review\n\n## Findings\n\n"
                    "### [HIGH] Authorization bypass\nFile: auth.py:3\nCheck is missing.\n"
                ),
            },
        ]
        findings, counts = collect_security_findings(reports)
        self.assertEqual(
            [finding["severity"] for finding in findings],
            ["CRITICAL", "HIGH", "LOW"],
        )
        self.assertEqual(counts, {1: 2, 2: 1})
        self.assertEqual(
            findings[0]["mr_url"],
            "https://gitlab.example.com/company/app/-/merge_requests/7",
        )
        self.assertEqual(findings[1]["mr_url"], "")
        self.assertIn("User input reaches a shell.", findings[0]["details"])
        self.assertEqual(
            parse_security_findings(
                "# Security review\n\n## Findings\nNo high-confidence security findings."
            ),
            [],
        )

    def test_completed_entries_include_findings_and_safe_reviews(self):
        reviews = [
            {
                "project_id": 1,
                "project_path": "company/risky",
                "project_web_url": "https://gitlab.example.com/company/risky",
                "mr_iid": 7,
                "head_sha": "risk-sha",
                "reviewed_at": "2026-09-15T12:00:00+00:00",
                "diff_content": "+dangerous_call(user_input)",
                "report_content": (
                    "# Security review\n\n## Summary\nA changed route passes user input to a shell.\n\n"
                    "## Findings\n### [HIGH] Command injection\nFile: app.py:9\nUser input reaches the shell.\n\n"
                    "## Overall severity rationale\nThe path enables remote command execution."
                ),
            },
            {
                "project_id": 2,
                "project_path": "company/safe",
                "project_web_url": "https://gitlab.example.com/company/safe",
                "mr_iid": 8,
                "head_sha": "safe-sha",
                "reviewed_at": "2026-09-15T13:00:00+00:00",
                "diff_content": "+query(parameterized_sql, user_id)",
                "report_content": (
                    "# Security review\n\n## Summary\nThe query remains parameterized.\n\n"
                    "## Findings\nNo high-confidence security findings.\n\n"
                    "## Overall severity rationale\nUser input remains data rather than executable SQL."
                ),
            },
        ]

        entries = completed_review_entries(reviews)

        self.assertEqual([entry["severity"] for entry in entries], ["HIGH", "SAFE"])
        self.assertEqual(entries[0]["title"], "Command injection")
        self.assertIn("remote command execution", entries[0]["severity_explanation"])
        self.assertEqual(entries[1]["title"], "No evidence-backed findings")
        self.assertIn("parameterized", entries[1]["summary"])
        self.assertIn("executable SQL", entries[1]["severity_explanation"])
        self.assertEqual(
            report_section(reviews[0]["report_content"], "Summary"),
            "A changed route passes user input to a shell.",
        )
        self.assertNotIn(
            "Overall severity rationale",
            parse_security_findings(reviews[0]["report_content"])[0]["details"],
        )

    def test_diff_html_uses_light_syntax_classes_and_escapes_code(self):
        rendered = render_diff_html(
            "## Changed file: app.py\n@@ -1 +1 @@\n-old <value>\n+new & safe\n context"
        )

        self.assertIn("class='diff-line diff-meta'", rendered)
        self.assertIn("class='diff-line diff-hunk'", rendered)
        self.assertIn("class='diff-line diff-delete'", rendered)
        self.assertIn("class='diff-line diff-add'", rendered)
        self.assertIn("class='diff-line diff-context'", rendered)
        self.assertIn("&lt;value&gt;", rendered)
        self.assertIn("new &amp; safe", rendered)
        self.assertNotIn("<value>", rendered)

    def test_repository_activity_uses_mr_dates_and_project_health(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite3"
            state = ReviewState(database)
            state.record_visible_projects(self.FakeGitLabClient().list_projects())
            state.record_project_check(1, "up")
            state.record_project_check(2, "down", "Access failed")
            state.queue(
                ReviewTarget(
                    1,
                    "company/first",
                    7,
                    "first-sha",
                    "",
                    "2026-09-15T08:30:00Z",
                )
            )
            state.queue(
                ReviewTarget(
                    1,
                    "company/first",
                    7,
                    "second-sha",
                    "",
                    "2026-09-15T08:30:00Z",
                )
            )
            rows, start, end = WebStore(database).repository_activity(
                "week", "2026-09-15", "2026-09-15"
            )
            by_project = {row["project_path"]: row for row in rows}
            self.assertEqual(start.isoformat(), "2026-09-15T00:00:00+00:00")
            self.assertEqual(end.isoformat(), "2026-09-16T00:00:00+00:00")
            self.assertEqual(by_project["company/first"]["mr_count"], 1)
            self.assertEqual(
                by_project["company/first"]["latest_mr_at"],
                "2026-09-15T08:30:00Z",
            )
            self.assertEqual(by_project["company/first"]["last_check_status"], "up")
            self.assertEqual(by_project["company/second"]["mr_count"], 0)
            self.assertEqual(by_project["company/second"]["last_check_status"], "down")
            self.assertEqual(
                len(WebStore(database).repository_mrs(1, start, end)), 1
            )
            with self.assertRaises(ReviewError):
                WebStore(database).repository_activity(
                    "week", "2026-09-16", "2026-09-15"
                )
            state.close()

    def test_mr_activity_filters_distinct_mrs_by_period(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite3"
            state = ReviewState(database)
            targets = [
                ReviewTarget(1, "company/app", iid, f"sha{iid}", "")
                for iid in range(1, 4)
            ]
            for target in targets:
                state.queue(target)
            now = datetime.now(timezone.utc)
            timestamps = [
                now - timedelta(hours=2),
                now - timedelta(days=2),
                now - timedelta(days=10),
            ]
            for target, discovered_at in zip(targets, timestamps):
                state.connection.execute(
                    "UPDATE reviews SET discovered_at = ? WHERE mr_iid = ?",
                    (discovered_at.isoformat(), target.mr_iid),
                )
            state.connection.commit()
            store = WebStore(database)
            self.assertEqual(store.mr_activity("day")[0], 1)
            self.assertEqual(store.mr_activity("week")[0], 2)
            self.assertEqual(store.mr_activity("month")[0], 3)
            state.close()

    def test_repository_pagination_uses_ten_rows_and_clamps_page_number(self):
        repositories = list(range(23))
        first, first_page, page_count = paginate_repositories(repositories, "1")
        second, second_page, _ = paginate_repositories(repositories, "2")
        last, last_page, _ = paginate_repositories(repositories, "99")
        invalid, invalid_page, _ = paginate_repositories(repositories, "invalid")

        self.assertEqual(first, list(range(10)))
        self.assertEqual(second, list(range(10, 20)))
        self.assertEqual(last, list(range(20, 23)))
        self.assertEqual((first_page, second_page, last_page), (1, 2, 3))
        self.assertEqual(page_count, 3)
        self.assertEqual(invalid, first)
        self.assertEqual(invalid_page, 1)
        self.assertEqual(paginate_repositories([], "1"), ([], 1, 1))


class WebAuthenticationTests(unittest.TestCase):
    def test_restart_invalidates_session_and_requires_fresh_login(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = WebStore(root / "state.sqlite3")
            user_id = store.create_first_user(
                "security-admin",
                "a secure test password",
                Credentials("https://gitlab.example.com", "test-token", "test-key"),
            )
            session_token, _ = store.create_session(user_id)
            self.assertEqual(store.delete_all_sessions(), 1)
            handler = handler_factory(store, root / "reports", False, MemoryVault())
            handler.log_message = lambda *_args: None
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            connection = http.client.HTTPConnection(
                "127.0.0.1", server.server_port, timeout=5
            )
            try:
                connection.request(
                    "GET", "/", headers={"Cookie": f"reviewer_session={session_token}"}
                )
                response = connection.getresponse()
                response.read()
                self.assertEqual(response.status, 303)
                self.assertEqual(response.getheader("Location"), "/login?reason=restart")
                self.assertIn("Max-Age=0", response.getheader("Set-Cookie", ""))

                connection.request("GET", "/login?reason=restart")
                response = connection.getresponse()
                login_page = response.read().decode("utf-8")
            finally:
                connection.close()
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=5)

            self.assertIsNone(store.session(session_token))
            self.assertIn("The service was restarted", login_page)
            self.assertNotIn("Unlock service", login_page)

    def test_authenticated_dashboard_and_repository_routes_are_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = WebStore(root / "state.sqlite3")
            user_id = store.create_first_user(
                "security-admin", "a secure test password"
            )
            session_token, _ = store.create_session(user_id)
            vault = MemoryVault()
            vault.set(Credentials("https://gitlab.example.com", "test-token", ""))
            state = ReviewState(root / "state.sqlite3")
            state.record_visible_projects(
                [
                    {
                        "id": 1,
                        "path_with_namespace": "company/app",
                        "web_url": "https://gitlab.example.com/company/app",
                    }
                ]
            )
            state.record(
                ReviewTarget(
                    1,
                    "company/app",
                    7,
                    "high-sha",
                    "https://gitlab.example.com/company/app/-/merge_requests/7",
                ),
                "high_severity",
                report_content=(
                    "# Security review\n\n## Summary\nUntrusted input reaches a shell.\n\n"
                    "## Findings\n### [HIGH] Command injection\n"
                    "File: app.py:8\nAn attacker can execute commands.\n\n"
                    "## Overall severity rationale\nRemote command execution can compromise the service."
                ),
                diff_content="@@ -7,0 +8 @@\n+run_shell(user_input)",
            )
            state.record(
                ReviewTarget(
                    1,
                    "company/app",
                    8,
                    "medium-sha",
                    "https://gitlab.example.com/company/app/-/merge_requests/8",
                ),
                "completed",
                report_content=(
                    "# Security review\n\n## Summary\nA verbose error is returned.\n\n"
                    "## Findings\n### [MEDIUM] Information disclosure\n"
                    "File: api.py:12\nInternal details may be exposed.\n\n"
                    "## Overall severity rationale\nThe data is useful but not directly exploitable."
                ),
                diff_content="@@ -11,0 +12 @@\n+return internal_error",
            )
            state.record(
                ReviewTarget(
                    1,
                    "company/app",
                    9,
                    "safe-sha",
                    "https://gitlab.example.com/company/app/-/merge_requests/9",
                ),
                "completed",
                report_content=(
                    "# Security review\n\n## Summary\nInput remains parameterized.\n\n"
                    "## Findings\nNo high-confidence security findings.\n\n"
                    "## Overall severity rationale\nThe query uses bound parameters, so input cannot alter SQL structure."
                ),
                diff_content="@@ -5,0 +6 @@\n+cursor.execute(query, (user_input,))",
            )
            state.queue(
                ReviewTarget(
                    1,
                    "company/app",
                    10,
                    "pending-sha",
                    "https://gitlab.example.com/company/app/-/merge_requests/10",
                )
            )
            state.close()
            handler = handler_factory(store, root / "reports", False, vault)
            handler.log_message = lambda *_args: None
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                headers = {"Cookie": f"reviewer_session={session_token}"}
                with urllib.request.urlopen(
                    urllib.request.Request(base_url + "/", headers=headers)
                ) as response:
                    dashboard = response.read().decode("utf-8")
                with urllib.request.urlopen(
                    urllib.request.Request(base_url + "/repositories", headers=headers)
                ) as response:
                    repositories = response.read().decode("utf-8")
                with urllib.request.urlopen(
                    urllib.request.Request(base_url + "/completed", headers=headers)
                ) as response:
                    completed = response.read().decode("utf-8")
                with urllib.request.urlopen(
                    urllib.request.Request(
                        base_url + "/repository?project_id=1&period=week",
                        headers=headers,
                    )
                ) as response:
                    repository_mrs = response.read().decode("utf-8")
                with urllib.request.urlopen(
                    urllib.request.Request(
                        base_url
                        + "/mr-diff?project_id=1&mr_iid=7&sha=high-sha",
                        headers=headers,
                    )
                ) as response:
                    stored_diff = json.loads(response.read().decode("utf-8"))
                with (
                    patch.object(
                        GitLabClient,
                        "get_merge_request",
                        return_value={"sha": "pending-sha"},
                    ),
                    patch.object(
                        GitLabClient,
                        "get_merge_request_diffs",
                        return_value=[
                            {
                                "new_path": "pending.py",
                                "diff": "@@ -0,0 +1 @@\n+pending_change = True",
                            }
                        ],
                    ),
                ):
                    with urllib.request.urlopen(
                        urllib.request.Request(
                            base_url
                            + "/mr-diff?project_id=1&mr_iid=10&sha=pending-sha",
                            headers=headers,
                        )
                    ) as response:
                        fetched_diff = json.loads(response.read().decode("utf-8"))
            finally:
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=5)

            self.assertIn("<h1>Review dashboard</h1>", dashboard)
            self.assertIn("<h2>Review status</h2>", dashboard)
            self.assertIn("<h2>High-severity findings</h2>", dashboard)
            self.assertIn("Command injection", dashboard)
            self.assertNotIn("Information disclosure", dashboard)
            self.assertNotIn("No evidence-backed findings", dashboard)
            self.assertNotIn("<h2>Repositories and MRs</h2>", dashboard)
            self.assertNotIn("Open MR revisions are queued", dashboard)
            self.assertNotIn("<h2>GitLab connection</h2>", dashboard)
            self.assertIn("class='connection-dot down'", dashboard)
            self.assertIn("GitLab connection not yet verified", dashboard)
            self.assertIn("href='/' aria-current='page'", dashboard)
            self.assertIn("<h1>Repositories</h1>", repositories)
            self.assertIn("<h2>Repositories and MRs</h2>", repositories)
            self.assertNotIn("<h2>Review status</h2>", repositories)
            self.assertNotIn("<h2>GitLab connection</h2>", repositories)
            self.assertIn(
                "href='/repositories' aria-current='page'", repositories
            )
            self.assertIn("<h1>Completed MRs</h1>", completed)
            self.assertIn("<h2>Completed review results</h2>", completed)
            self.assertIn("Command injection", completed)
            self.assertIn("Information disclosure", completed)
            self.assertIn("No evidence-backed findings", completed)
            self.assertIn("Reviewed code diff", completed)
            self.assertIn("run_shell(user_input)", completed)
            self.assertIn("Input remains parameterized.", completed)
            self.assertIn("The query uses bound parameters", completed)
            self.assertIn("class='expandable-row'", completed)
            self.assertIn("href='/completed' aria-current='page'", completed)
            expected_columns = (
                "<th>Severity</th><th>Finding title</th><th>MR</th>"
                "<th>Vulnerability details</th>"
            )
            self.assertIn(expected_columns, dashboard)
            self.assertIn(expected_columns, completed)
            self.assertIn("<h2>Merge requests</h2>", repository_mrs)
            self.assertIn("name='project_id' value='1'", repository_mrs)
            self.assertIn("/repository?project_id=1&amp;period=day", repository_mrs)
            self.assertIn("name='start_date'", repository_mrs)
            self.assertIn("name='end_date'", repository_mrs)
            self.assertIn("class='expandable-row'", repository_mrs)
            self.assertIn("data-open-label='View diff'", repository_mrs)
            self.assertIn("run_shell(user_input)", repository_mrs)
            self.assertIn("data-lazy-diff", repository_mrs)
            self.assertEqual(stored_diff["source"], "stored")
            self.assertIn("run_shell(user_input)", stored_diff["diff"])
            self.assertEqual(fetched_diff["source"], "gitlab")
            self.assertIn("pending_change = True", fetched_diff["diff"])
            cached_pending = store.mr_revision(1, 10, "pending-sha")
            self.assertIsNotNone(cached_pending)
            self.assertIn("pending_change = True", cached_pending["diff_content"])

    def test_application_shell_has_safe_navigation_and_active_page(self):
        rendered = application_page(
            "Repositories",
            "Repositories <all>",
            "Repository coverage",
            "<section>Trusted application content</section>",
            "<admin>",
            "'csrf-token",
            "repositories",
            "Reviews active",
            "completed",
            "",
            ("GitLab connected", "up"),
        )

        self.assertIn("href='/'", rendered)
        self.assertIn("href='/completed'", rendered)
        self.assertIn("href='/repositories' aria-current='page'", rendered)
        self.assertIn("href='/settings'", rendered)
        self.assertEqual(rendered.count("aria-current='page'"), 1)
        self.assertIn("Repositories &lt;all&gt;", rendered)
        self.assertIn("&lt;admin&gt;", rendered)
        self.assertNotIn("<admin>", rendered)
        self.assertIn("value='&#x27;csrf-token'", rendered)
        self.assertIn("Reviews active", rendered)
        self.assertIn("class='connection-dot up'", rendered)
        self.assertIn("GitLab connected", rendered)

    def test_password_hash_round_trip(self):
        salt, digest, iterations = password_record("a sufficiently long password")
        self.assertTrue(
            verify_password("a sufficiently long password", salt, digest, iterations)
        )
        self.assertFalse(verify_password("wrong password", salt, digest, iterations))

    def test_users_and_settings_are_stored_in_sqlite(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WebStore(Path(directory) / "state.sqlite3")
            credentials = Credentials(
                "https://gitlab.example.com", "gitlab-test-token", "anthropic-test-key"
            )
            user_id = store.create_first_user(
                "security-admin",
                "a secure test password",
                credentials,
                {"MAX_REVIEWS_PER_CYCLE": "0"},
            )
            self.assertEqual(store.user_count(), 1)
            user = store.authenticate("security-admin", "a secure test password")
            self.assertIsNotNone(user)
            self.assertEqual(
                store.unlock_credentials("a secure test password"), credentials
            )
            token, _ = store.create_session(user_id)
            self.assertIsNotNone(store.session(token))
            self.assertEqual(store.settings()["MAX_REVIEWS_PER_CYCLE"], "0")
            store.save_settings({"MAX_REVIEWS_PER_CYCLE": "5"})
            self.assertEqual(store.settings()["MAX_REVIEWS_PER_CYCLE"], "5")

    def test_credentials_require_the_correct_password(self):
        credentials = Credentials(
            "https://gitlab.example.com", "gitlab-test-token", "anthropic-test-key"
        )
        salt, nonce, ciphertext = encrypt_credentials(credentials, "correct password")
        self.assertEqual(
            decrypt_credentials(salt, nonce, ciphertext, "correct password"), credentials
        )
        with self.assertRaises(ReviewError):
            decrypt_credentials(salt, nonce, ciphertext, "wrong password")

    def test_unlocked_encryption_key_can_rotate_credentials_without_password(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WebStore(Path(directory) / "state.sqlite3")
            original = Credentials(
                "https://gitlab.example.com", "old-gitlab-token", "old-llm-key"
            )
            store.create_first_user(
                "security-admin", "a secure test password", original
            )
            _, salt, encryption_key = store.unlock_credentials_with_key(
                "a secure test password"
            )
            replacement = Credentials(
                "https://gitlab.example.com", "new-gitlab-token", "new-llm-key"
            )
            store.save_encrypted_credentials(replacement, salt, encryption_key)
            self.assertEqual(
                store.unlock_credentials("a secure test password"), replacement
            )

    def test_gitlab_credentials_can_be_saved_without_anthropic_key(self):
        credentials = validated_credentials(
            "https://gitlab.example.com",
            "gitlab-test-token",
            "",
            gitlab_group_path="maas",
        )
        salt, nonce, ciphertext = encrypt_credentials(credentials, "correct password")
        restored = decrypt_credentials(salt, nonce, ciphertext, "correct password")
        self.assertEqual(restored, credentials)
        self.assertEqual(restored.gitlab_group_path, "maas")

    def test_non_anthropic_provider_configuration_is_encrypted(self):
        credentials = validated_credentials(
            "https://gitlab.example.com",
            "gitlab-test-token",
            "openai-test-key",
            "openai",
            "",
            "gpt-company",
        )
        salt, nonce, ciphertext = encrypt_credentials(credentials, "correct password")
        restored = decrypt_credentials(salt, nonce, ciphertext, "correct password")
        self.assertEqual(restored, credentials)
        self.assertEqual(restored.llm_provider, "openai")
        self.assertNotIn("openai-test-key", ciphertext)

    def test_custom_provider_requires_an_https_endpoint_when_key_is_present(self):
        with self.assertRaises(ReviewError):
            validated_credentials(
                "https://gitlab.example.com",
                "gitlab-test-token",
                "custom-test-key",
                "custom",
                "http://localhost:9000/v1/chat/completions",
                "company-model",
            )

    def test_scan_status_is_shared_with_web_console(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite3"
            store = WebStore(database)
            state = ReviewState(database)
            state.set_metadata("last_gitlab_check_status", "success")
            self.assertEqual(
                store.scan_status()["last_gitlab_check_status"], "success"
            )
            state.close()

    def test_each_fresh_data_folder_gets_its_own_deployment_time(self):
        with tempfile.TemporaryDirectory() as directory:
            first_database = Path(directory) / "first.sqlite3"
            second_database = Path(directory) / "second.sqlite3"
            with patch("security_review.web.now_iso", return_value="2026-09-15T10:00:00+00:00"):
                first = WebStore(first_database)
            with patch("security_review.web.now_iso", return_value="2026-09-16T10:00:00+00:00"):
                second = WebStore(second_database)
            self.assertEqual(
                first.scan_status()["deployment_started_at"],
                "2026-09-15T10:00:00+00:00",
            )
            self.assertEqual(
                second.scan_status()["deployment_started_at"],
                "2026-09-16T10:00:00+00:00",
            )
            with patch("security_review.web.now_iso", return_value="2026-09-17T10:00:00+00:00"):
                WebStore(first_database)
            self.assertEqual(
                first.scan_status()["deployment_started_at"],
                "2026-09-15T10:00:00+00:00",
            )

    def test_review_data_reset_preserves_admin_credentials_and_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite3"
            store = WebStore(database)
            credentials = Credentials(
                "https://gitlab.example.com", "gitlab-test-token", "llm-test-key"
            )
            user_id = store.create_first_user(
                "security-admin",
                "a secure test password",
                credentials,
                {"MAX_REVIEWS_PER_CYCLE": "5"},
            )
            session_token, _ = store.create_session(user_id)
            state = ReviewState(database)
            state.record_visible_projects(
                [
                    {
                        "id": 1,
                        "path_with_namespace": "company/app",
                        "web_url": "https://gitlab.example.com/company/app",
                    }
                ]
            )
            state.queue(
                ReviewTarget(
                    1,
                    "company/app",
                    7,
                    "test-sha",
                    "https://gitlab.example.com/company/app/-/merge_requests/7",
                    "2026-09-15T11:00:00Z",
                )
            )
            state.set_metadata("last_gitlab_check_status", "success")
            state.close()

            reset_at = "2026-09-15T12:00:00+00:00"
            with patch("security_review.web.now_iso", return_value=reset_at):
                self.assertEqual(store.reset_review_data(), (1, 1, reset_at))

            self.assertEqual(store.user_count(), 1)
            self.assertIsNotNone(
                store.authenticate("security-admin", "a secure test password")
            )
            self.assertEqual(
                store.unlock_credentials("a secure test password"), credentials
            )
            self.assertEqual(store.settings()["MAX_REVIEWS_PER_CYCLE"], "5")
            self.assertIsNotNone(store.session(session_token))
            self.assertEqual(store.visible_projects(), [])
            self.assertEqual(store.dashboard(), ({}, []))
            status = store.scan_status()
            self.assertEqual(status["deployment_started_at"], reset_at)
            self.assertNotIn("last_gitlab_check_status", status)
            with store.connect() as connection:
                initialized = connection.execute(
                    "SELECT value FROM metadata WHERE key = 'initialized'"
                ).fetchone()
            self.assertEqual(str(initialized["value"]), reset_at)


if __name__ == "__main__":
    unittest.main()
