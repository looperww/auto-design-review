import io
import os
import sqlite3
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from security_review.service import (  # noqa: E402
    Config,
    ReviewError,
    ReviewState,
    ReviewTarget,
    api_project,
    build_context_bundle,
    env_bool,
    effective_runtime_settings,
    is_context_candidate,
    normalized_archive_path,
    parse_mr_url,
    scan_once,
)
from security_review.web import (  # noqa: E402
    Credentials,
    WebStore,
    decrypt_credentials,
    encrypt_credentials,
    password_record,
    verify_password,
)


def config_for_test(root: Path, **overrides):
    values = {
        "gitlab_url": "https://gitlab.example.com",
        "gitlab_token": "test-token",
        "anthropic_api_key": "test-anthropic-key",
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
        "claude_model": "opus",
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
        self.assertEqual(config.claude_model, "opus")

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
                metadata_json='{"status":"completed"}',
            )
            self.assertTrue(state.has(target))
            stored = state.connection.execute(
                "SELECT report_content, metadata_json FROM reviews"
            ).fetchone()
            self.assertEqual(stored[0], "# Security review\n")

    def test_new_head_sha_is_a_new_review(self):
        first = ReviewTarget(1, "company/app", 3, "abc123", "https://example/mr/3")
        second = ReviewTarget(1, "company/app", 3, "def456", "https://example/mr/3")
        with tempfile.TemporaryDirectory() as directory:
            state = ReviewState(Path(directory) / "state.sqlite3")
            state.record(first, "completed")
            self.assertFalse(state.has(second))


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


class WebAuthenticationTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
