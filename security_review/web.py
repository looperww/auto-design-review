from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import urllib.parse
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from .service import (
    COMPARISON_PROFILES,
    COMPARISON_PROFILE_LABELS,
    GitLabClient,
    LLM_DEFAULT_MODELS,
    LLM_PROVIDER_LABELS,
    LLM_PROVIDERS,
    RUNTIME_SETTINGS,
    Config,
    ReviewError,
    effective_runtime_settings,
    initial_mr_discovery_started_at,
    list_llm_models,
    normalize_gitlab_group_path,
    normalize_runtime_setting,
    render_diffs,
    test_llm_connection,
)


PASSWORD_ITERATIONS = 600_000
SESSION_LIFETIME_SECONDS = 12 * 60 * 60
LOGIN_WINDOW_SECONDS = 15 * 60
MAX_LOGIN_ATTEMPTS = 10
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
FINDING_HEADING_PATTERN = re.compile(
    r"(?m)^### \[(CRITICAL|HIGH|MEDIUM|LOW)\] ([^\r\n]+?)\s*$"
)
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
REPOSITORIES_PER_PAGE = 50
REPOSITORY_PAGE_SIZES = (10, 25, 50, 100)
COMPLETED_ROWS_PER_PAGE = 20
COMPLETED_SEVERITIES = {"all", "critical", "high", "medium", "low", "safe"}
MANUAL_REVIEW_STATUSES = {"open", "in_progress", "done"}
MANUAL_REVIEW_FILTERS = {"all", *MANUAL_REVIEW_STATUSES}
MANUAL_REVIEW_RESOLUTIONS = {"false_positive", "finding"}
MANUAL_FINDING_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
MR_MANUAL_REVIEW_KEY = "mr"
SEVERITY_EXPLANATIONS = {
    "CRITICAL": "Critical indicates a credible path to broad compromise of sensitive systems, users, or company data.",
    "HIGH": "High indicates a credible path to meaningful unauthorized access, sensitive-data exposure, or code execution.",
    "MEDIUM": "Medium indicates a material but limited risk, or a risk that requires important preconditions.",
    "LOW": "Low indicates a defensible security weakness with limited plausible impact.",
    "SAFE": (
        "Safe means this review established no evidence-backed vulnerability in the changed code and supplied context. "
        "No credible attacker-controlled path to a sensitive sink was identified; this is not a guarantee that the repository is vulnerability-free."
    ),
}
VAULT_ASSOCIATED_DATA = b"gitlab-security-review-vault-v1"
APP_JAVASCRIPT = b"""(() => {
  const diffLineClass = (line) => {
    if (line.startsWith('+') && !line.startsWith('+++')) return 'diff-add';
    if (line.startsWith('-') && !line.startsWith('---')) return 'diff-delete';
    if (line.startsWith('@@')) return 'diff-hunk';
    if (line.startsWith('## Changed file:') || line.startsWith('diff --git') ||
        line.startsWith('index ') || line.startsWith('---') ||
        line.startsWith('+++') || line.startsWith('```')) return 'diff-meta';
    return 'diff-context';
  };
  const renderDiff = (target, content) => {
    const code = document.createElement('code');
    for (const line of content.split('\\n')) {
      const span = document.createElement('span');
      span.className = `diff-line ${diffLineClass(line)}`;
      span.textContent = line || '\u00a0';
      code.appendChild(span);
    }
    target.replaceChildren(code);
  };
  for (const form of document.querySelectorAll('.auto-submit-selector')) {
    for (const select of form.querySelectorAll('select')) {
      select.addEventListener('change', () => form.requestSubmit());
    }
  }
  for (const row of document.querySelectorAll('.expandable-row')) {
    const details = document.getElementById(row.dataset.detailsId || '');
    const button = row.querySelector('.row-toggle');
    if (!details) continue;
    const openLabel = row.dataset.openLabel || 'View review';
    const closeLabel = row.dataset.closeLabel || 'Hide review';
    const lazyDiff = details.querySelector('[data-lazy-diff]');
    const lazyCommits = details.querySelector('[data-lazy-commits]');
    const loadDiff = async () => {
      if (!lazyDiff || lazyDiff.dataset.loaded === 'true') return;
      lazyDiff.dataset.loaded = 'true';
      lazyDiff.textContent = 'Loading the MR diff from GitLab...';
      try {
        const response = await fetch(row.dataset.diffUrl || '', {
          headers: {'Accept': 'application/json'},
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || 'Could not load the MR diff.');
        renderDiff(
          lazyDiff,
          payload.diff || 'GitLab returned an empty diff for this MR revision.'
        );
      } catch (error) {
        lazyDiff.dataset.loaded = 'false';
        lazyDiff.textContent = error instanceof Error ? error.message : 'Could not load the MR diff.';
      }
    };
    const loadCommits = async () => {
      if (!lazyCommits || lazyCommits.dataset.loaded === 'true') return;
      lazyCommits.dataset.loaded = 'true';
      lazyCommits.textContent = 'Loading commit details from GitLab...';
      try {
        const response = await fetch(lazyCommits.dataset.commitsUrl || '', {
          headers: {'Accept': 'application/json'},
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || 'Could not load commit details.');
        const commits = Array.isArray(payload.commits) ? payload.commits : [];
        if (!commits.length) {
          lazyCommits.textContent = 'GitLab returned no commit details for this MR.';
          return;
        }
        const list = document.createElement('div');
        list.className = 'commit-summary-list';
        for (const commit of commits) {
          const item = document.createElement('div');
          item.className = 'commit-summary-item';
          const message = document.createElement('span');
          message.className = 'commit-message';
          message.textContent = commit.message || commit.title || 'Untitled commit';
          const author = document.createElement('span');
          author.className = 'commit-author';
          author.textContent = `by ${commit.author_name || 'Unknown author'}`;
          item.append(message, author);
          list.appendChild(item);
        }
        lazyCommits.replaceChildren(list);
      } catch (error) {
        lazyCommits.dataset.loaded = 'false';
        lazyCommits.textContent = error instanceof Error ? error.message : 'Could not load commit details.';
      }
    };
    const setExpanded = (expanded) => {
      details.hidden = !expanded;
      row.setAttribute('aria-expanded', String(expanded));
      if (button) button.textContent = expanded ? closeLabel : openLabel;
      if (expanded) {
        loadCommits();
        loadDiff();
      }
    };
    const toggle = () => setExpanded(details.hidden);
    row.addEventListener('click', (event) => {
      if (event.target.closest('a, button')) return;
      toggle();
    });
    row.addEventListener('keydown', (event) => {
      if (event.target !== row || !['Enter', ' '].includes(event.key)) return;
      event.preventDefault();
      toggle();
    });
    if (button) button.addEventListener('click', toggle);
  }
  const reviewDialog = document.getElementById('manual-review-dialog');
  const reviewForm = document.getElementById('manual-review-form');
  if (reviewDialog && reviewForm) {
    const statusInput = reviewForm.elements.namedItem('workflow_status');
    const severityInput = reviewForm.elements.namedItem('severity');
    const commentsInput = reviewForm.elements.namedItem('comments');
    const resolutionFields = document.getElementById('manual-resolution-fields');
    const severityField = document.getElementById('manual-severity-field');
    const selectedResolution = () =>
      reviewForm.querySelector('input[name="resolution"]:checked')?.value || '';
    const updateReviewFields = () => {
      const done = statusInput.value === 'done';
      resolutionFields.hidden = !done;
      const confirmed = done && selectedResolution() === 'finding';
      severityField.hidden = !confirmed;
      severityInput.required = confirmed;
      commentsInput.required = done;
      for (const input of reviewForm.querySelectorAll('input[name="resolution"]')) {
        input.required = done;
      }
    };
    statusInput.addEventListener('change', updateReviewFields);
    for (const input of reviewForm.querySelectorAll('input[name="resolution"]')) {
      input.addEventListener('change', updateReviewFields);
    }
    for (const button of document.querySelectorAll('.manual-review-button')) {
      button.addEventListener('click', () => {
        for (const name of ['project_id', 'mr_iid', 'head_sha', 'item_key', 'return_to']) {
          reviewForm.elements.namedItem(name).value = button.dataset[name.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase())] || '';
        }
        statusInput.value = button.dataset.workflowStatus || 'open';
        severityInput.value = button.dataset.severity || '';
        commentsInput.value = button.dataset.comments || '';
        const resolution = button.dataset.resolution || '';
        for (const input of reviewForm.querySelectorAll('input[name="resolution"]')) {
          input.checked = input.value === resolution;
        }
        updateReviewFields();
        reviewDialog.showModal();
      });
    }
    for (const button of reviewDialog.querySelectorAll('.dialog-close, .dialog-cancel')) {
      button.addEventListener('click', () => reviewDialog.close());
    }
    reviewDialog.addEventListener('click', (event) => {
      if (event.target === reviewDialog) reviewDialog.close();
    });
  }
  const credentialForm = document.getElementById('credential_form');
  for (const fetchButton of document.querySelectorAll('.fetch-models')) {
    const modelInput = document.getElementById(fetchButton.dataset.modelField || '');
    const modelPicker = document.getElementById(fetchButton.dataset.picker || '');
    const modelStatus = document.getElementById(fetchButton.dataset.status || '');
    if (!credentialForm || !modelInput || !modelPicker || !modelStatus) continue;
    modelPicker.addEventListener('change', () => {
      if (modelPicker.value) modelInput.value = modelPicker.value;
    });
    fetchButton.addEventListener('click', async () => {
      fetchButton.disabled = true;
      modelPicker.hidden = true;
      modelStatus.textContent = 'Fetching available models...';
      try {
        const formData = new FormData(credentialForm);
        const requestData = new URLSearchParams();
        requestData.set('csrf', String(formData.get('csrf') || ''));
        requestData.set('model_provider', fetchButton.dataset.provider || '');
        const keyField = fetchButton.dataset.keyField || '';
        if (keyField) requestData.set(keyField, String(formData.get(keyField) || ''));
        const response = await fetch('/credentials/models', {
          method: 'POST',
          headers: {'Accept': 'application/json'},
          body: requestData,
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || 'Could not fetch models.');
        modelPicker.replaceChildren(new Option('Select a fetched model...', ''));
        for (const model of payload.models) {
          modelPicker.add(new Option(model, model));
        }
        if (payload.models.includes(modelInput.value)) modelPicker.value = modelInput.value;
        modelPicker.hidden = false;
        modelStatus.textContent = `${payload.models.length} model(s) available. Select one from the list.`;
      } catch (error) {
        modelStatus.textContent = error instanceof Error ? error.message : 'Could not fetch models.';
      } finally {
        fetchButton.disabled = false;
      }
    });
  }
})();
"""


def parse_security_findings(report: str) -> list[dict[str, str]]:
    matches = list(FINDING_HEADING_PATTERN.finditer(report))
    findings: list[dict[str, str]] = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(report)
        next_section = re.search(r"(?m)^##\s+", report[match.end() : end])
        if next_section is not None:
            end = match.end() + next_section.start()
        details = report[match.end() : end].strip()
        severity = match.group(1)
        title = match.group(2).strip()
        item_key = hashlib.sha256(
            f"{index}\0{severity}\0{title}\0{details}".encode("utf-8")
        ).hexdigest()
        findings.append(
            {
                "severity": severity,
                "title": title,
                "details": details or "No additional details were provided.",
                "item_key": item_key,
            }
        )
    return findings


def report_section(report: str, heading: str) -> str:
    match = re.search(
        rf"(?ms)^##\s+{re.escape(heading)}\s*$\n?(.*?)(?=^##\s+|\Z)", report
    )
    return match.group(1).strip() if match else ""


def render_diff_html(diff_content: str) -> str:
    rendered_lines = []
    for line in diff_content.split("\n"):
        if line.startswith("+") and not line.startswith("+++"):
            line_class = "diff-add"
        elif line.startswith("-") and not line.startswith("---"):
            line_class = "diff-delete"
        elif line.startswith("@@"):
            line_class = "diff-hunk"
        elif line.startswith(
            ("## Changed file:", "diff --git", "index ", "---", "+++", "```")
        ):
            line_class = "diff-meta"
        else:
            line_class = "diff-context"
        rendered_lines.append(
            f"<span class='diff-line {line_class}'>{html.escape(line) or '&nbsp;'}</span>"
        )
    return "<pre class='diff-view'><code>" + "".join(rendered_lines) + "</code></pre>"


def normalize_gitlab_commits(
    commits: Iterable[Mapping[str, Any]], gitlab_url: str
) -> list[dict[str, str]]:
    base = urllib.parse.urlparse(gitlab_url)
    normalized: list[dict[str, str]] = []
    for commit in commits:
        commit_id = str(commit.get("id") or "").strip()
        if not re.fullmatch(r"[0-9a-fA-F]{7,64}", commit_id):
            continue
        short_id = str(commit.get("short_id") or commit_id[:12]).strip()[:16]
        if not re.fullmatch(r"[0-9a-fA-F]{7,16}", short_id):
            short_id = commit_id[:12]
        raw_url = str(commit.get("web_url") or "").strip()
        parsed_url = urllib.parse.urlparse(raw_url)
        web_url = (
            raw_url
            if parsed_url.scheme == "https"
            and parsed_url.netloc
            and parsed_url.netloc == base.netloc
            else ""
        )
        normalized.append(
            {
                "id": commit_id,
                "short_id": short_id,
                "title": str(commit.get("title") or "Untitled commit").strip()[:1000],
                "message": str(
                    commit.get("message") or commit.get("title") or "Untitled commit"
                ).strip()[:4000],
                "author_name": str(
                    commit.get("author_name") or commit.get("committer_name") or ""
                ).strip()[:300],
                "committed_date": str(
                    commit.get("committed_date") or commit.get("created_at") or ""
                ).strip()[:100],
                "web_url": web_url,
            }
        )
    return normalized


def collect_security_findings(
    reports: Iterable[Mapping[str, Any]],
    manual_reviews: Mapping[tuple[int, int, str, str], Mapping[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], dict[int, int]]:
    decisions = manual_reviews or {}
    findings: list[dict[str, Any]] = []
    counts: dict[int, int] = {}
    for report in reports:
        review_profile = str(report.get("review_profile", ""))
        project_id = int(report["project_id"])
        project_path = str(report["project_path"])
        mr_iid = int(report["mr_iid"])
        project_url = str(report["project_web_url"] or "")
        parsed_url = urllib.parse.urlparse(project_url)
        mr_url = (
            project_url.rstrip("/") + f"/-/merge_requests/{mr_iid}"
            if parsed_url.scheme == "https" and parsed_url.netloc
            else ""
        )
        parsed_findings = parse_security_findings(str(report["report_content"]))
        for finding in parsed_findings:
            try:
                head_sha = str(report["head_sha"] or "")
            except (KeyError, IndexError):
                head_sha = ""
            raw_item_key = str(finding["item_key"])
            item_key = (
                hashlib.sha256(
                    f"{review_profile}\0{raw_item_key}".encode("utf-8")
                ).hexdigest()
                if review_profile
                else raw_item_key
            )
            mr_item_key = (
                hashlib.sha256(
                    f"{review_profile}\0{MR_MANUAL_REVIEW_KEY}".encode("utf-8")
                ).hexdigest()
                if review_profile
                else MR_MANUAL_REVIEW_KEY
            )
            decision = decisions.get(
                (project_id, mr_iid, head_sha, item_key)
            ) or decisions.get(
                (project_id, mr_iid, head_sha, mr_item_key)
            ) or decisions.get(
                (project_id, mr_iid, head_sha, raw_item_key)
            ) or decisions.get(
                (project_id, mr_iid, head_sha, MR_MANUAL_REVIEW_KEY)
            )
            workflow_status = str(decision["workflow_status"]) if decision else "open"
            resolution = str(decision["resolution"] or "") if decision else ""
            if workflow_status == "done" and resolution == "false_positive":
                continue
            severity = str(finding["severity"])
            if workflow_status == "done" and resolution == "finding":
                manual_severity = str(decision["severity"] or "") if decision else ""
                if manual_severity in MANUAL_FINDING_SEVERITIES:
                    severity = manual_severity
            counts[project_id] = counts.get(project_id, 0) + 1
            findings.append(
                {
                    **finding,
                    "item_key": item_key,
                    "review_profile": review_profile,
                    "severity": severity,
                    "project_id": project_id,
                    "project_path": project_path,
                    "mr_iid": mr_iid,
                    "mr_url": mr_url,
                    "head_sha": head_sha,
                    "manual_status": workflow_status,
                    "manual_resolution": resolution,
                    "manual_severity": str(decision["severity"] or "") if decision else "",
                    "manual_comments": str(decision["comments"] or "") if decision else "",
                }
            )
    findings.sort(
        key=lambda finding: (
            SEVERITY_ORDER[str(finding["severity"])],
            str(finding["project_path"]).casefold(),
            int(finding["mr_iid"]),
            str(finding["title"]).casefold(),
        )
    )
    return findings, counts


def completed_review_entries(
    reviews: Iterable[Mapping[str, Any]],
    manual_reviews: Mapping[tuple[int, int, str, str], Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    decisions = manual_reviews or {}
    entries: list[dict[str, Any]] = []
    for review in reviews:
        review_profile = str(review.get("review_profile", ""))
        report = str(review["report_content"] or "")
        summary = report_section(report, "Summary") or "Security review completed."
        overall_rationale = report_section(report, "Overall severity rationale")
        findings = parse_security_findings(report)
        project_url = str(review["project_web_url"] or "")
        parsed_url = urllib.parse.urlparse(project_url)
        mr_iid = int(review["mr_iid"])
        mr_url = (
            project_url.rstrip("/") + f"/-/merge_requests/{mr_iid}"
            if parsed_url.scheme == "https" and parsed_url.netloc
            else ""
        )
        base = {
            "project_id": int(review["project_id"]),
            "project_path": str(review["project_path"]),
            "mr_iid": mr_iid,
            "mr_url": mr_url,
            "project_web_url": project_url,
            "head_sha": str(review["head_sha"]),
            "summary": summary,
            "diff_content": str(review["diff_content"] or ""),
            "reviewed_at": str(review["reviewed_at"]),
            "review_profile": review_profile,
            "llm_model": str(review.get("llm_model", "")),
        }
        mr_item_key = (
            hashlib.sha256(
                f"{review_profile}\0{MR_MANUAL_REVIEW_KEY}".encode("utf-8")
            ).hexdigest()
            if review_profile
            else MR_MANUAL_REVIEW_KEY
        )
        if not findings:
            decision = decisions.get(
                (
                    int(review["project_id"]),
                    mr_iid,
                    str(review["head_sha"]),
                    mr_item_key,
                )
            ) or decisions.get(
                (
                    int(review["project_id"]),
                    mr_iid,
                    str(review["head_sha"]),
                    MR_MANUAL_REVIEW_KEY,
                )
            )
            workflow_status = str(decision["workflow_status"]) if decision else "open"
            resolution = str(decision["resolution"] or "") if decision else ""
            manual_severity = str(decision["severity"] or "") if decision else ""
            severity = (
                manual_severity
                if workflow_status == "done"
                and resolution == "finding"
                and manual_severity in MANUAL_FINDING_SEVERITIES
                else "SAFE"
            )
            entries.append(
                {
                    **base,
                    "severity": severity,
                    "title": "No evidence-backed findings",
                    "finding_details": (
                        "The review found no high-confidence security finding in the supplied change and bounded repository context."
                    ),
                    "severity_explanation": (
                        SEVERITY_EXPLANATIONS[severity]
                        if severity != "SAFE"
                        else overall_rationale or SEVERITY_EXPLANATIONS["SAFE"]
                    ),
                    "item_key": mr_item_key,
                    "manual_status": workflow_status,
                    "manual_resolution": resolution,
                    "manual_severity": str(decision["severity"] or "") if decision else "",
                    "manual_comments": str(decision["comments"] or "") if decision else "",
                }
            )
            continue
        for finding in findings:
            raw_item_key = str(finding["item_key"])
            item_key = (
                hashlib.sha256(
                    f"{review_profile}\0{raw_item_key}".encode("utf-8")
                ).hexdigest()
                if review_profile
                else raw_item_key
            )
            decision = decisions.get(
                (
                    int(review["project_id"]),
                    mr_iid,
                    str(review["head_sha"]),
                    item_key,
                )
            ) or decisions.get(
                (
                    int(review["project_id"]),
                    mr_iid,
                    str(review["head_sha"]),
                    mr_item_key,
                )
            ) or decisions.get(
                (
                    int(review["project_id"]),
                    mr_iid,
                    str(review["head_sha"]),
                    raw_item_key,
                )
            ) or decisions.get(
                (
                    int(review["project_id"]),
                    mr_iid,
                    str(review["head_sha"]),
                    MR_MANUAL_REVIEW_KEY,
                )
            )
            workflow_status = str(decision["workflow_status"]) if decision else "open"
            resolution = str(decision["resolution"] or "") if decision else ""
            severity = str(finding["severity"])
            if workflow_status == "done" and resolution == "false_positive":
                severity = "SAFE"
            elif workflow_status == "done" and resolution == "finding":
                manual_severity = str(decision["severity"] or "") if decision else ""
                if manual_severity in MANUAL_FINDING_SEVERITIES:
                    severity = manual_severity
            explanation = SEVERITY_EXPLANATIONS[severity]
            if overall_rationale and not (
                workflow_status == "done" and resolution == "false_positive"
            ):
                explanation += "\n\nOverall review rationale:\n" + overall_rationale
            entries.append(
                {
                    **base,
                    "severity": severity,
                    "title": str(finding["title"]),
                    "finding_details": str(finding["details"]),
                    "severity_explanation": explanation,
                    "item_key": item_key,
                    "manual_status": workflow_status,
                    "manual_resolution": resolution,
                    "manual_severity": str(decision["severity"] or "") if decision else "",
                    "manual_comments": str(decision["comments"] or "") if decision else "",
                }
            )
    return entries


def manual_review_status_for_mr(
    project_id: int,
    mr_iid: int,
    head_sha: str,
    report_content: str,
    manual_reviews: Mapping[tuple[int, int, str, str], Mapping[str, Any]],
) -> str:
    mr_decision = manual_reviews.get(
        (project_id, mr_iid, head_sha, MR_MANUAL_REVIEW_KEY)
    )
    if mr_decision is not None:
        return str(mr_decision["workflow_status"])
    findings = parse_security_findings(report_content)
    if not findings:
        return "open"
    statuses = []
    for finding in findings:
        decision = manual_reviews.get(
            (project_id, mr_iid, head_sha, str(finding["item_key"]))
        )
        statuses.append(str(decision["workflow_status"]) if decision else "open")
    if any(status == "in_progress" for status in statuses):
        return "in_progress"
    if statuses and all(status == "done" for status in statuses):
        return "done"
    return "open"


def manual_review_button(
    *,
    project_id: int,
    mr_iid: int,
    head_sha: str,
    item_key: str,
    workflow_status: str,
    resolution: str = "",
    severity: str = "",
    comments: str = "",
    return_to: str,
) -> str:
    label = {
        "open": "Open",
        "in_progress": "In Progress",
        "done": "Done",
    }.get(workflow_status, "Open")
    return (
        "<button class='manual-review-button secondary' type='button' "
        f"data-project-id='{project_id}' data-mr-iid='{mr_iid}' "
        f"data-head-sha='{html.escape(head_sha)}' "
        f"data-item-key='{html.escape(item_key)}' "
        f"data-workflow-status='{html.escape(workflow_status)}' "
        f"data-resolution='{html.escape(resolution)}' "
        f"data-severity='{html.escape(severity)}' "
        f"data-comments='{html.escape(comments)}' "
        f"data-return-to='{html.escape(return_to)}'>"
        f"<span class='review-state review-state-{html.escape(workflow_status)}'>"
        f"{html.escape(label)}</span></button>"
    )


def manual_review_dialog(csrf_token: str) -> str:
    return f"""
    <dialog class='manual-review-dialog' id='manual-review-dialog'>
      <form method='post' action='/manual-review' id='manual-review-form'>
        <input type='hidden' name='csrf' value='{html.escape(csrf_token)}'>
        <input type='hidden' name='project_id'>
        <input type='hidden' name='mr_iid'>
        <input type='hidden' name='head_sha'>
        <input type='hidden' name='item_key'>
        <input type='hidden' name='return_to'>
        <div class='dialog-heading'><div><p class='eyebrow'>Human verification</p><h2>Update manual-review status</h2></div>
        <button class='dialog-close secondary' type='button' aria-label='Close'>Close</button></div>
        <div class='field'><label for='manual_workflow_status'>Status</label>
          <select id='manual_workflow_status' name='workflow_status'>
            <option value='open'>Open</option><option value='in_progress'>In Progress</option><option value='done'>Done</option>
          </select>
        </div>
        <div id='manual-resolution-fields' hidden>
          <fieldset><legend>Resolution</legend>
            <label><input type='radio' name='resolution' value='false_positive'> False positive</label>
            <label><input type='radio' name='resolution' value='finding'> Confirmed finding</label>
          </fieldset>
          <div class='field' id='manual-severity-field' hidden><label for='manual_severity'>Finding severity</label>
            <select id='manual_severity' name='severity'>
              <option value=''>Choose severity</option><option value='CRITICAL'>Critical</option><option value='HIGH'>High</option><option value='MEDIUM'>Medium</option><option value='LOW'>Low</option>
            </select>
          </div>
          <div class='field'><label for='manual_comments'>Comments</label>
            <textarea id='manual_comments' name='comments' maxlength='4000' rows='5' placeholder='Record the verification evidence and decision.'></textarea>
            <small>Comments are required when closing a review.</small>
          </div>
        </div>
        <div class='actions'><button type='submit'>Save review status</button><button class='dialog-cancel secondary' type='button'>Cancel</button></div>
      </form>
    </dialog>"""


def inline_commit_summary(
    project_id: int,
    mr_iid: int,
    head_sha: str,
) -> str:
    query = urllib.parse.urlencode(
        {"project_id": project_id, "mr_iid": mr_iid, "sha": head_sha}
    )
    return (
        "<div class='inline-commit-summary' data-lazy-commits "
        f"data-commits-url='/mr-commits?{html.escape(query)}' "
        "data-loaded='false'>Commit messages and authors load when this row is expanded.</div>"
    )


def normalize_repository_page_size(requested_page_size: str) -> int:
    try:
        page_size = int(requested_page_size)
    except ValueError:
        return REPOSITORIES_PER_PAGE
    return page_size if page_size in REPOSITORY_PAGE_SIZES else REPOSITORIES_PER_PAGE


def paginate_repositories(
    repositories: list[Any], requested_page: str, page_size: int = REPOSITORIES_PER_PAGE
) -> tuple[list[Any], int, int]:
    if page_size not in REPOSITORY_PAGE_SIZES:
        page_size = REPOSITORIES_PER_PAGE
    try:
        page_number = int(requested_page)
    except ValueError:
        page_number = 1
    total_pages = max(
        1,
        (len(repositories) + page_size - 1)
        // page_size,
    )
    page_number = min(max(page_number, 1), total_pages)
    start = (page_number - 1) * page_size
    return (
        repositories[start : start + page_size],
        page_number,
        total_pages,
    )


@dataclass(frozen=True)
class Credentials:
    gitlab_url: str
    gitlab_token: str
    llm_api_key: str
    llm_provider: str = "anthropic"
    llm_api_url: str = ""
    llm_model: str = ""
    gitlab_group_path: str = ""
    openai_api_key: str = ""
    openai_model: str = ""
    copilot_api_key: str = ""
    copilot_anthropic_model: str = "claude-sonnet-5"
    copilot_openai_model: str = "gpt-5.4"

    def comparison_ready(self) -> bool:
        return bool(
            self.llm_api_key.strip()
            and self.openai_api_key.strip()
            and self.copilot_api_key.strip()
        )

    def review_ready(self) -> bool:
        """Whether the direct Anthropic reviewer can run by itself."""
        return bool(self.llm_api_key.strip())


def credential_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS, dklen=32
    )


def credential_payload(credentials: Credentials) -> bytes:
    return json.dumps(
        {
            "gitlab_url": credentials.gitlab_url,
            "gitlab_token": credentials.gitlab_token,
            "llm_api_key": credentials.llm_api_key,
            "llm_provider": credentials.llm_provider,
            "llm_api_url": credentials.llm_api_url,
            "llm_model": credentials.llm_model,
            "gitlab_group_path": credentials.gitlab_group_path,
            "anthropic_api_key": credentials.llm_api_key,
            "anthropic_model": credentials.llm_model,
            "openai_api_key": credentials.openai_api_key,
            "openai_model": credentials.openai_model,
            "copilot_api_key": credentials.copilot_api_key,
            "copilot_anthropic_model": credentials.copilot_anthropic_model,
            "copilot_openai_model": credentials.copilot_openai_model,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def encrypt_credentials_with_key(
    credentials: Credentials, salt: bytes, key: bytes
) -> tuple[str, str, str]:
    if len(salt) != 16 or len(key) != 32:
        raise ReviewError("The in-memory credential encryption context is invalid.")
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(
        nonce, credential_payload(credentials), VAULT_ASSOCIATED_DATA
    )
    return salt.hex(), nonce.hex(), ciphertext.hex()


def encrypt_credentials(credentials: Credentials, password: str) -> tuple[str, str, str]:
    salt = secrets.token_bytes(16)
    return encrypt_credentials_with_key(credentials, salt, credential_key(password, salt))


def decrypt_credentials_with_key(
    nonce_hex: str, ciphertext_hex: str, key: bytes
) -> Credentials:
    try:
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, VAULT_ASSOCIATED_DATA)
        payload = json.loads(plaintext)
        legacy_provider = str(payload.get("llm_provider", "anthropic"))
        legacy_key = str(
            payload.get("llm_api_key", payload.get("anthropic_api_key", ""))
        )
        legacy_model = str(payload.get("llm_model", ""))
        anthropic_key = str(payload.get("anthropic_api_key", ""))
        anthropic_model = str(payload.get("anthropic_model", ""))
        openai_key = str(payload.get("openai_api_key", ""))
        openai_model = str(payload.get("openai_model", ""))
        if not anthropic_key and legacy_provider == "anthropic":
            anthropic_key = legacy_key
            anthropic_model = anthropic_model or legacy_model
        if not openai_key and legacy_provider == "openai":
            openai_key = legacy_key
            openai_model = openai_model or legacy_model
        credentials = Credentials(
            gitlab_url=str(payload["gitlab_url"]),
            gitlab_token=str(payload["gitlab_token"]),
            llm_api_key=anthropic_key,
            llm_provider="anthropic",
            llm_api_url=str(payload.get("llm_api_url", "")),
            llm_model=anthropic_model,
            gitlab_group_path=normalize_gitlab_group_path(
                str(payload.get("gitlab_group_path", ""))
            ),
            openai_api_key=openai_key,
            openai_model=openai_model,
            copilot_api_key=str(payload.get("copilot_api_key", "")),
            copilot_anthropic_model=str(
                payload.get("copilot_anthropic_model", "claude-sonnet-5")
            ),
            copilot_openai_model=str(
                payload.get("copilot_openai_model", "gpt-5.4")
            ),
        )
    except (ValueError, KeyError, TypeError, json.JSONDecodeError, InvalidTag) as exc:
        raise ReviewError("The credential vault could not be unlocked.") from exc
    if not credentials.gitlab_url.strip() or not credentials.gitlab_token.strip():
        raise ReviewError("The credential vault does not contain GitLab access.")
    if credentials.llm_provider not in LLM_PROVIDERS:
        raise ReviewError("The credential vault contains an unsupported LLM provider.")
    return credentials


def decrypt_credentials(
    salt_hex: str, nonce_hex: str, ciphertext_hex: str, password: str
) -> Credentials:
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError as exc:
        raise ReviewError("The credential vault could not be unlocked.") from exc
    return decrypt_credentials_with_key(
        nonce_hex, ciphertext_hex, credential_key(password, salt)
    )


def review_row_for_profile(
    row: Mapping[str, Any], profile: str
) -> dict[str, Any] | None:
    """Project one stored MR revision into a single comparison profile."""
    try:
        comparison = json.loads(str(row["comparison_json"] or "{}"))
    except (KeyError, TypeError, json.JSONDecodeError):
        comparison = {}
    if isinstance(comparison, dict) and isinstance(comparison.get(profile), dict):
        result = comparison[profile]
        projected = dict(row)
        projected.update(
            {
                "status": str(result.get("status", "failed")),
                "report_content": str(result.get("report_content", "")),
                "metadata_json": json.dumps(result.get("metadata", {}), sort_keys=True),
                "review_profile": profile,
                "llm_provider": str(result.get("provider", "")),
                "llm_model": str(result.get("model", "")),
            }
        )
        return projected
    try:
        metadata = json.loads(str(row["metadata_json"] or "{}"))
    except (KeyError, TypeError, json.JSONDecodeError):
        metadata = {}
    legacy_provider = str(metadata.get("llm_provider", "anthropic"))
    legacy_profile = legacy_provider if legacy_provider in {"anthropic", "openai"} else ""
    if legacy_profile != profile or not str(row["report_content"] or ""):
        return None
    projected = dict(row)
    projected.update(
        {
            "review_profile": profile,
            "llm_provider": legacy_provider,
            "llm_model": str(metadata.get("llm_model", "")),
        }
    )
    return projected


def profile_usage_summary(
    reports: Iterable[Mapping[str, Any]], profile: str
) -> dict[str, Any]:
    """Summarize comparable operational metrics without inventing provider prices."""
    review_count = 0
    durations: list[float] = []
    input_tokens = 0
    output_tokens = 0
    reported_usd = 0.0
    has_reported_usd = False
    premium_requests = 0.0
    has_premium_requests = False
    for report in reports:
        try:
            metadata = json.loads(str(report.get("metadata_json", "{}") or "{}"))
        except (TypeError, json.JSONDecodeError):
            metadata = {}
        if not isinstance(metadata, dict):
            metadata = {}
        review_count += 1
        elapsed = metadata.get("elapsed_ms") or metadata.get("llm_duration_ms")
        if isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool):
            durations.append(float(elapsed))
        cost = metadata.get("llm_cost_usd")
        if isinstance(cost, (int, float)) and not isinstance(cost, bool):
            reported_usd += float(cost)
            has_reported_usd = True
        usage = metadata.get("llm_usage")
        if not isinstance(usage, dict):
            continue
        raw_input = usage.get("input_tokens", usage.get("lastCallInputTokens"))
        raw_output = usage.get("output_tokens", usage.get("lastCallOutputTokens"))
        if isinstance(raw_input, int) and not isinstance(raw_input, bool):
            input_tokens += raw_input
        if isinstance(raw_output, int) and not isinstance(raw_output, bool):
            output_tokens += raw_output
        raw_premium = usage.get("totalPremiumRequestCost")
        if isinstance(raw_premium, (int, float)) and not isinstance(raw_premium, bool):
            premium_requests += float(raw_premium)
            has_premium_requests = True
    average_ms = sum(durations) / len(durations) if durations else None
    if profile.startswith("copilot_"):
        cost_display = (
            f"{premium_requests:,.2f} premium requests"
            if has_premium_requests
            else "Not reported"
        )
    else:
        cost_display = f"${reported_usd:,.4f}" if has_reported_usd else "Provider billing"
    return {
        "reviews": review_count,
        "average_ms": average_ms,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cost_display": cost_display,
    }


class MemoryVault:
    def __init__(self):
        self.condition = threading.Condition()
        self.credentials: Credentials | None = None
        self.kdf_salt: bytes | None = None
        self.encryption_key: bytes | None = None
        self.version = 0

    def prepare(self, password: str, salt: bytes | None = None) -> None:
        selected_salt = salt or secrets.token_bytes(16)
        key = credential_key(password, selected_salt)
        with self.condition:
            self.kdf_salt = selected_salt
            self.encryption_key = key

    def set(
        self,
        credentials: Credentials,
        *,
        salt: bytes | None = None,
        encryption_key: bytes | None = None,
    ) -> None:
        with self.condition:
            if salt is not None:
                self.kdf_salt = salt
            if encryption_key is not None:
                self.encryption_key = encryption_key
            self.credentials = credentials
            self.version += 1
            self.condition.notify_all()

    def snapshot(self) -> tuple[Credentials | None, int]:
        with self.condition:
            return self.credentials, self.version

    def encryption_context(self) -> tuple[bytes, bytes]:
        with self.condition:
            if self.kdf_salt is None or self.encryption_key is None:
                raise ReviewError(
                    "The credential vault is locked. Sign in again to unlock it."
                )
            return self.kdf_salt, self.encryption_key

    def ready_for_updates(self) -> bool:
        with self.condition:
            return self.kdf_salt is not None and self.encryption_key is not None

    def wait_for_credentials(self) -> tuple[Credentials, int]:
        with self.condition:
            while self.credentials is None:
                self.condition.wait(timeout=30)
            return self.credentials, self.version

    def wait_for_change(self, version: int, timeout: int) -> None:
        with self.condition:
            if self.version == version:
                self.condition.wait(timeout=timeout)

    def notify_change(self) -> None:
        with self.condition:
            self.version += 1
            self.condition.notify_all()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def password_record(password: str) -> tuple[str, str, int]:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return salt.hex(), digest.hex(), PASSWORD_ITERATIONS


def verify_password(password: str, salt_hex: str, digest_hex: str, iterations: int) -> bool:
    if iterations < 100_000 or iterations > 2_000_000:
        return False
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def validated_credentials(
    gitlab_url: str,
    gitlab_token: str,
    llm_api_key: str,
    llm_provider: str = "anthropic",
    llm_api_url: str = "",
    llm_model: str = "",
    gitlab_group_path: str = "",
    *,
    openai_api_key: str = "",
    openai_model: str = "",
    copilot_api_key: str = "",
    copilot_anthropic_model: str = "claude-sonnet-5",
    copilot_openai_model: str = "gpt-5.4",
) -> Credentials:
    url = gitlab_url.strip().rstrip("/")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ReviewError("GitLab URL must be a valid HTTPS address.")
    gitlab_token = gitlab_token.strip()
    llm_api_key = llm_api_key.strip()
    llm_provider = llm_provider.strip().lower()
    llm_api_url = llm_api_url.strip()
    llm_model = llm_model.strip() or LLM_DEFAULT_MODELS.get(llm_provider, "")
    if not 8 <= len(gitlab_token) <= 4096:
        raise ReviewError("GitLab token is missing or has an invalid length.")
    if llm_provider not in LLM_PROVIDERS:
        raise ReviewError("Select a supported LLM provider.")
    if llm_provider == "openai" and llm_api_key and not openai_api_key:
        openai_api_key, openai_model, llm_api_key = (
            llm_api_key,
            openai_model or llm_model,
            "",
        )
        llm_model = LLM_DEFAULT_MODELS["anthropic"]
    if llm_api_key and not 8 <= len(llm_api_key) <= 4096:
        raise ReviewError("LLM API key has an invalid length.")
    if llm_model and len(llm_model) > 256:
        raise ReviewError("LLM model name is too long.")
    if llm_api_key and not llm_model:
        raise ReviewError("Enter a model name for the selected LLM provider.")
    if llm_provider == "custom" and llm_api_key and not llm_api_url:
        raise ReviewError("Enter a custom LLM API URL when an API key is configured.")
    if llm_provider == "custom" and llm_api_url:
        parsed_llm = urllib.parse.urlparse(llm_api_url)
        if (
            parsed_llm.scheme != "https"
            or not parsed_llm.netloc
            or parsed_llm.username
            or parsed_llm.password
            or parsed_llm.fragment
        ):
            raise ReviewError("Custom LLM API URL must be a valid HTTPS address without a fragment.")
    elif llm_provider != "custom":
        llm_api_url = ""
    if len(llm_api_url) > 2048:
        raise ReviewError("Custom LLM API URL is too long.")
    openai_api_key = openai_api_key.strip()
    copilot_api_key = copilot_api_key.strip()
    openai_model = openai_model.strip() or LLM_DEFAULT_MODELS["openai"]
    copilot_anthropic_model = copilot_anthropic_model.strip() or "claude-sonnet-5"
    copilot_openai_model = copilot_openai_model.strip() or "gpt-5.4"
    for label, secret in (
        ("OpenAI API key", openai_api_key),
        ("GitHub Copilot token", copilot_api_key),
    ):
        if secret and not 8 <= len(secret) <= 4096:
            raise ReviewError(f"{label} has an invalid length.")
    for model in (openai_model, copilot_anthropic_model, copilot_openai_model):
        if len(model) > 256:
            raise ReviewError("LLM model name is too long.")
    return Credentials(
        gitlab_url=url,
        gitlab_token=gitlab_token,
        llm_api_key=llm_api_key,
        llm_provider="anthropic",
        llm_api_url=llm_api_url,
        llm_model=llm_model,
        gitlab_group_path=normalize_gitlab_group_path(gitlab_group_path),
        openai_api_key=openai_api_key,
        openai_model=openai_model,
        copilot_api_key=copilot_api_key,
        copilot_anthropic_model=copilot_anthropic_model,
        copilot_openai_model=copilot_openai_model,
    )


class WebStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.operation_lock = threading.RLock()
        self.initialize()

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_salt TEXT NOT NULL,
                    password_digest TEXT NOT NULL,
                    password_iterations INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS web_sessions (
                    token_digest TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    csrf_token TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS login_attempts (
                    remote_address TEXT NOT NULL,
                    attempted_at INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS login_attempts_address_time "
                "ON login_attempts(remote_address, attempted_at)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS credential_vault (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    kdf_salt TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    ciphertext TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS reviews (
                    project_id INTEGER NOT NULL,
                    mr_iid INTEGER NOT NULL,
                    head_sha TEXT NOT NULL,
                    project_path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    report_path TEXT,
                    report_content TEXT,
                diff_content TEXT,
                metadata_json TEXT,
                comparison_json TEXT NOT NULL DEFAULT '{}',
                discovered_at TEXT NOT NULL,
                    mr_created_at TEXT NOT NULL,
                    reviewed_at TEXT NOT NULL,
                    PRIMARY KEY (project_id, mr_iid, head_sha)
                )
                """
            )
            review_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(reviews)")
            }
            if "report_content" not in review_columns:
                connection.execute("ALTER TABLE reviews ADD COLUMN report_content TEXT")
            if "diff_content" not in review_columns:
                connection.execute("ALTER TABLE reviews ADD COLUMN diff_content TEXT")
            if "metadata_json" not in review_columns:
                connection.execute("ALTER TABLE reviews ADD COLUMN metadata_json TEXT")
            if "comparison_json" not in review_columns:
                connection.execute(
                    "ALTER TABLE reviews ADD COLUMN comparison_json TEXT NOT NULL DEFAULT '{}'"
                )
            if "discovered_at" not in review_columns:
                connection.execute("ALTER TABLE reviews ADD COLUMN discovered_at TEXT")
                connection.execute(
                    "UPDATE reviews SET discovered_at = reviewed_at WHERE discovered_at IS NULL"
                )
            if "mr_created_at" not in review_columns:
                connection.execute(
                    "ALTER TABLE reviews ADD COLUMN "
                    "mr_created_at TEXT NOT NULL DEFAULT ''"
                )
                connection.execute(
                    "UPDATE reviews SET mr_created_at = discovered_at "
                    "WHERE mr_created_at = ''"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS manual_reviews (
                    project_id INTEGER NOT NULL,
                    mr_iid INTEGER NOT NULL,
                    head_sha TEXT NOT NULL,
                    item_key TEXT NOT NULL,
                    workflow_status TEXT NOT NULL DEFAULT 'open',
                    resolution TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT '',
                    comments TEXT NOT NULL DEFAULT '',
                    updated_by TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (project_id, mr_iid, head_sha, item_key),
                    FOREIGN KEY (project_id, mr_iid, head_sha)
                        REFERENCES reviews(project_id, mr_iid, head_sha)
                        ON DELETE CASCADE
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS manual_reviews_status "
                "ON manual_reviews(workflow_status)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            if connection.execute(
                "SELECT 1 FROM metadata WHERE key = 'deployment_started_at'"
            ).fetchone() is None:
                connection.execute(
                    "INSERT INTO metadata (key, value) VALUES ('deployment_started_at', ?)",
                    (initial_mr_discovery_started_at(),),
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS visible_projects (
                    project_id INTEGER PRIMARY KEY,
                    project_path TEXT NOT NULL,
                    web_url TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    is_visible INTEGER NOT NULL DEFAULT 1,
                    last_check_status TEXT NOT NULL DEFAULT 'unknown',
                    last_check_error TEXT NOT NULL DEFAULT ''
                )
                """
            )
            visible_project_columns = {
                str(row[1])
                for row in connection.execute("PRAGMA table_info(visible_projects)")
            }
            if "last_check_status" not in visible_project_columns:
                connection.execute(
                    "ALTER TABLE visible_projects ADD COLUMN "
                    "last_check_status TEXT NOT NULL DEFAULT 'unknown'"
                )
            if "last_check_error" not in visible_project_columns:
                connection.execute(
                    "ALTER TABLE visible_projects ADD COLUMN "
                    "last_check_error TEXT NOT NULL DEFAULT ''"
                )

    def user_count(self) -> int:
        with self.connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def create_first_user(
        self,
        username: str,
        password: str,
        credentials: Credentials | None = None,
        runtime_settings: dict[str, str] | None = None,
    ) -> int:
        salt, digest, iterations = password_record(password)
        encrypted = encrypt_credentials(credentials, password) if credentials else None
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM users LIMIT 1").fetchone():
                raise ReviewError("The administrator account has already been created.")
            cursor = connection.execute(
                """
                INSERT INTO users
                    (username, password_salt, password_digest, password_iterations, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, salt, digest, iterations, now_iso()),
            )
            if encrypted:
                vault_salt, nonce, ciphertext = encrypted
                connection.execute(
                    """
                    INSERT INTO credential_vault
                        (id, kdf_salt, nonce, ciphertext, updated_at)
                    VALUES (1, ?, ?, ?, ?)
                    """,
                    (vault_salt, nonce, ciphertext, now_iso()),
                )
            for key, value in (runtime_settings or {}).items():
                connection.execute(
                    "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
                    (key, value, now_iso()),
                )
            return int(cursor.lastrowid)

    def authenticate(self, username: str, password: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
            ).fetchone()
        if row is None:
            password_record(password)
            return None
        if not verify_password(
            password,
            str(row["password_salt"]),
            str(row["password_digest"]),
            int(row["password_iterations"]),
        ):
            return None
        return row

    def credentials_configured(self) -> bool:
        with self.connect() as connection:
            return connection.execute(
                "SELECT 1 FROM credential_vault WHERE id = 1"
            ).fetchone() is not None

    def save_encrypted_credentials(
        self, credentials: Credentials, salt: bytes, encryption_key: bytes
    ) -> None:
        salt_hex, nonce, ciphertext = encrypt_credentials_with_key(
            credentials, salt, encryption_key
        )
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO credential_vault
                    (id, kdf_salt, nonce, ciphertext, updated_at)
                VALUES (1, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET kdf_salt = excluded.kdf_salt,
                                              nonce = excluded.nonce,
                                              ciphertext = excluded.ciphertext,
                                              updated_at = excluded.updated_at
                """,
                (salt_hex, nonce, ciphertext, now_iso()),
            )

    def save_credentials(self, credentials: Credentials, password: str) -> None:
        salt = secrets.token_bytes(16)
        self.save_encrypted_credentials(
            credentials, salt, credential_key(password, salt)
        )

    def unlock_credentials(self, password: str) -> Credentials:
        credentials, _, _ = self.unlock_credentials_with_key(password)
        return credentials

    def unlock_credentials_with_key(
        self, password: str
    ) -> tuple[Credentials, bytes, bytes]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT kdf_salt, nonce, ciphertext FROM credential_vault WHERE id = 1"
            ).fetchone()
        if row is None:
            raise ReviewError("GitLab credentials have not been configured.")
        try:
            salt = bytes.fromhex(str(row["kdf_salt"]))
        except ValueError as exc:
            raise ReviewError("The credential vault could not be unlocked.") from exc
        key = credential_key(password, salt)
        credentials = decrypt_credentials_with_key(
            str(row["nonce"]), str(row["ciphertext"]), key
        )
        return credentials, salt, key

    def login_blocked(self, remote_address: str) -> bool:
        cutoff = int(time.time()) - LOGIN_WINDOW_SECONDS
        with self.connect() as connection:
            connection.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (cutoff,))
            count = connection.execute(
                "SELECT COUNT(*) FROM login_attempts "
                "WHERE remote_address = ? AND attempted_at >= ?",
                (remote_address, cutoff),
            ).fetchone()[0]
        return int(count) >= MAX_LOGIN_ATTEMPTS

    def record_failed_login(self, remote_address: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "INSERT INTO login_attempts (remote_address, attempted_at) VALUES (?, ?)",
                (remote_address, int(time.time())),
            )

    def clear_failed_logins(self, remote_address: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "DELETE FROM login_attempts WHERE remote_address = ?", (remote_address,)
            )

    def create_session(self, user_id: int) -> tuple[str, str]:
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        with self.connect() as connection:
            connection.execute("DELETE FROM web_sessions WHERE expires_at < ?", (int(time.time()),))
            connection.execute(
                """
                INSERT INTO web_sessions
                    (token_digest, user_id, csrf_token, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    token_digest(token),
                    user_id,
                    csrf,
                    int(time.time()) + SESSION_LIFETIME_SECONDS,
                    now_iso(),
                ),
            )
        return token, csrf

    def session(self, token: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(
                """
                SELECT users.id, users.username, web_sessions.csrf_token
                FROM web_sessions
                JOIN users ON users.id = web_sessions.user_id
                WHERE web_sessions.token_digest = ? AND web_sessions.expires_at >= ?
                """,
                (token_digest(token), int(time.time())),
            ).fetchone()

    def delete_session(self, token: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "DELETE FROM web_sessions WHERE token_digest = ?", (token_digest(token),)
            )

    def delete_all_sessions(self) -> int:
        with self.connect() as connection:
            cursor = connection.execute("DELETE FROM web_sessions")
            return max(cursor.rowcount, 0)

    def settings(self) -> dict[str, str]:
        with self.connect() as connection:
            rows = connection.execute("SELECT key, value FROM settings").fetchall()
        return {str(row["key"]): str(row["value"]) for row in rows}

    def settings_configured(self) -> bool:
        saved = self.settings()
        return all(setting.key in saved for setting in RUNTIME_SETTINGS)

    def save_settings(self, values: dict[str, str]) -> None:
        with self.connect() as connection:
            for key, value in values.items():
                connection.execute(
                    """
                    INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                                   updated_at = excluded.updated_at
                    """,
                    (key, value, now_iso()),
                )

    def reset_review_data(self) -> tuple[int, int, str]:
        with self.operation_lock:
            reset_at = now_iso()
            with self.connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                repository_count = int(
                    connection.execute("SELECT COUNT(*) FROM visible_projects").fetchone()[0]
                )
                review_count = int(
                    connection.execute("SELECT COUNT(*) FROM reviews").fetchone()[0]
                )
                connection.execute("DELETE FROM reviews")
                connection.execute("DELETE FROM visible_projects")
                connection.execute(
                    "DELETE FROM metadata WHERE key LIKE 'last_gitlab_check_%'"
                )
                connection.execute(
                    "INSERT OR REPLACE INTO metadata (key, value) VALUES "
                    "('deployment_started_at', ?)",
                    (reset_at,),
                )
                connection.execute(
                    "INSERT OR REPLACE INTO metadata (key, value) VALUES "
                    "('initialized', ?)",
                    (reset_at,),
                )
        return repository_count, review_count, reset_at

    def manual_review_map(
        self,
    ) -> dict[tuple[int, int, str, str], sqlite3.Row]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT project_id, mr_iid, head_sha, item_key, workflow_status,
                       resolution, severity, comments, updated_by, updated_at
                FROM manual_reviews
                """
            ).fetchall()
        return {
            (
                int(row["project_id"]),
                int(row["mr_iid"]),
                str(row["head_sha"]),
                str(row["item_key"]),
            ): row
            for row in rows
        }

    def save_manual_review(
        self,
        project_id: int,
        mr_iid: int,
        head_sha: str,
        item_key: str,
        workflow_status: str,
        resolution: str,
        severity: str,
        comments: str,
        updated_by: str,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO manual_reviews
                    (project_id, mr_iid, head_sha, item_key, workflow_status,
                     resolution, severity, comments, updated_by, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, mr_iid, head_sha, item_key) DO UPDATE SET
                    workflow_status = excluded.workflow_status,
                    resolution = excluded.resolution,
                    severity = excluded.severity,
                    comments = excluded.comments,
                    updated_by = excluded.updated_by,
                    updated_at = excluded.updated_at
                """,
                (
                    project_id,
                    mr_iid,
                    head_sha,
                    item_key,
                    workflow_status,
                    resolution,
                    severity,
                    comments,
                    updated_by,
                    now_iso(),
                ),
            )

    def dashboard(self) -> tuple[dict[str, int], list[sqlite3.Row]]:
        with self.connect() as connection:
            counts = {
                str(row["status"]): int(row["count"])
                for row in connection.execute(
                    "SELECT status, COUNT(*) AS count FROM reviews GROUP BY status"
                ).fetchall()
            }
            recent = connection.execute(
                """
                SELECT project_id, project_path, mr_iid, head_sha, status,
                       report_path, report_content, reviewed_at
                FROM reviews ORDER BY reviewed_at DESC LIMIT 25
                """
            ).fetchall()
        return counts, recent

    def scan_status(self) -> dict[str, str]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT key, value FROM metadata "
                "WHERE key LIKE 'last_gitlab_check_%' OR key = 'deployment_started_at'"
            ).fetchall()
        return {str(row["key"]): str(row["value"]) for row in rows}

    def visible_projects(self) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return connection.execute(
                """
                SELECT project_id, project_path, web_url, first_seen_at, last_seen_at,
                       last_check_status, last_check_error
                FROM visible_projects WHERE is_visible = 1
                ORDER BY project_path COLLATE NOCASE
                """
            ).fetchall()

    def repository_activity(
        self, period: str, start_date: str = "", end_date: str = ""
    ) -> tuple[list[sqlite3.Row], datetime, datetime]:
        now = datetime.now(timezone.utc)
        if bool(start_date) != bool(end_date):
            raise ReviewError("Choose both a start date and an end date.")
        if start_date and end_date:
            try:
                start = datetime.strptime(start_date, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                )
                final_day = datetime.strptime(end_date, "%Y-%m-%d").replace(
                    tzinfo=timezone.utc
                )
            except ValueError as exc:
                raise ReviewError("Choose a valid start and end date.") from exc
            if final_day < start:
                raise ReviewError("The end date cannot be earlier than the start date.")
            end = final_day + timedelta(days=1)
        else:
            durations = {
                "day": timedelta(days=1),
                "week": timedelta(days=7),
                "month": timedelta(days=30),
            }
            start = now - durations.get(period, durations["week"])
            end = now
        with self.connect() as connection:
            rows = connection.execute(
                """
                WITH first_discovery AS (
                    SELECT project_id, mr_iid,
                           MIN(COALESCE(NULLIF(mr_created_at, ''), discovered_at)) AS mr_at
                    FROM reviews
                    GROUP BY project_id, mr_iid
                ), activity AS (
                    SELECT project_id, COUNT(*) AS mr_count,
                           MAX(mr_at) AS latest_mr_at
                    FROM first_discovery
                    WHERE mr_at >= ? AND mr_at < ?
                    GROUP BY project_id
                )
                SELECT projects.project_id, projects.project_path, projects.web_url,
                       projects.last_seen_at, projects.last_check_status,
                       projects.last_check_error,
                       COALESCE(activity.mr_count, 0) AS mr_count,
                       activity.latest_mr_at
                FROM visible_projects AS projects
                LEFT JOIN activity ON activity.project_id = projects.project_id
                WHERE projects.is_visible = 1
                ORDER BY
                    CASE WHEN activity.latest_mr_at IS NULL THEN 1 ELSE 0 END,
                    activity.latest_mr_at DESC,
                    projects.project_path COLLATE NOCASE
                """,
                (start.isoformat(), end.isoformat()),
            ).fetchall()
        return rows, start, end

    def repository_mrs(
        self, project_id: int, start: datetime, end: datetime
    ) -> list[sqlite3.Row]:
        with self.connect() as connection:
            return connection.execute(
                """
                WITH ranked AS (
                    SELECT project_id, project_path, mr_iid, head_sha, status,
                           report_path, report_content, diff_content,
                           mr_created_at, reviewed_at,
                           ROW_NUMBER() OVER (
                               PARTITION BY project_id, mr_iid
                               ORDER BY reviewed_at DESC
                           ) AS revision_rank
                    FROM reviews
                    WHERE project_id = ?
                      AND COALESCE(NULLIF(mr_created_at, ''), discovered_at) >= ?
                      AND COALESCE(NULLIF(mr_created_at, ''), discovered_at) < ?
                )
                SELECT project_id, project_path, mr_iid, head_sha, status,
                       report_path, report_content, diff_content,
                       mr_created_at, reviewed_at
                FROM ranked
                WHERE revision_rank = 1
                ORDER BY mr_created_at DESC, mr_iid DESC
                """,
                (project_id, start.isoformat(), end.isoformat()),
            ).fetchall()

    def mr_revision(
        self, project_id: int, mr_iid: int, head_sha: str
    ) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(
                """
                SELECT project_id, project_path, mr_iid, head_sha, status,
                       diff_content
                FROM reviews
                WHERE project_id = ? AND mr_iid = ? AND head_sha = ?
                """,
                (project_id, mr_iid, head_sha),
            ).fetchone()

    def cache_mr_diff(
        self, project_id: int, mr_iid: int, head_sha: str, diff_content: str
    ) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE reviews SET diff_content = ?
                WHERE project_id = ? AND mr_iid = ? AND head_sha = ?
                """,
                (diff_content, project_id, mr_iid, head_sha),
            )
            return cursor.rowcount == 1

    def latest_review_reports(
        self, start: datetime, end: datetime, review_profile: str = "anthropic"
    ) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                WITH ranked AS (
                    SELECT reviews.project_id, reviews.project_path,
                           reviews.mr_iid, reviews.head_sha, reviews.status,
                           reviews.report_content, reviews.reviewed_at,
                           reviews.diff_content, reviews.metadata_json,
                           reviews.comparison_json,
                           projects.web_url AS project_web_url,
                           ROW_NUMBER() OVER (
                               PARTITION BY reviews.project_id, reviews.mr_iid
                               ORDER BY reviews.reviewed_at DESC
                           ) AS revision_rank
                    FROM reviews
                    LEFT JOIN visible_projects AS projects
                      ON projects.project_id = reviews.project_id
                    WHERE COALESCE(NULLIF(reviews.mr_created_at, ''), reviews.discovered_at) >= ?
                      AND COALESCE(NULLIF(reviews.mr_created_at, ''), reviews.discovered_at) < ?
                      AND (
                          (reviews.report_content IS NOT NULL AND reviews.report_content != '')
                          OR reviews.comparison_json != '{}'
                      )
                )
                SELECT project_id, project_path, mr_iid, head_sha, status,
                       report_content, diff_content, metadata_json, comparison_json,
                       reviewed_at, project_web_url
                FROM ranked
                WHERE revision_rank = 1
                """,
                (start.isoformat(), end.isoformat()),
            ).fetchall()
        return [
            projected
            for row in rows
            if (projected := review_row_for_profile(row, review_profile)) is not None
        ]

    def completed_reviews(self, review_profile: str = "anthropic") -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                WITH ranked AS (
                    SELECT reviews.project_id, reviews.project_path,
                           reviews.mr_iid, reviews.head_sha, reviews.status,
                           reviews.report_content, reviews.diff_content,
                           reviews.metadata_json, reviews.reviewed_at,
                           reviews.comparison_json,
                           projects.web_url AS project_web_url,
                           ROW_NUMBER() OVER (
                               PARTITION BY reviews.project_id, reviews.mr_iid
                               ORDER BY reviews.reviewed_at DESC
                           ) AS revision_rank
                    FROM reviews
                    LEFT JOIN visible_projects AS projects
                      ON projects.project_id = reviews.project_id
                    WHERE reviews.status IN ('completed', 'high_severity', 'failed')
                      AND (
                          (reviews.report_content IS NOT NULL AND reviews.report_content != '')
                          OR reviews.comparison_json != '{}'
                      )
                )
                SELECT project_id, project_path, mr_iid, head_sha, status,
                       report_content, diff_content, metadata_json, comparison_json, reviewed_at,
                       project_web_url
                FROM ranked
                WHERE revision_rank = 1
                ORDER BY reviewed_at DESC, project_path COLLATE NOCASE, mr_iid DESC
                """
            ).fetchall()
        projected = [
            result
            for row in rows
            if (result := review_row_for_profile(row, review_profile)) is not None
        ]
        return [
            row
            for row in projected
            if str(row["status"]) in {"completed", "high_severity"}
        ]

    def mr_activity(self, period: str) -> tuple[int, list[sqlite3.Row]]:
        durations = {
            "day": timedelta(days=1),
            "week": timedelta(days=7),
            "month": timedelta(days=30),
        }
        cutoff = (datetime.now(timezone.utc) - durations.get(period, durations["week"])).isoformat()
        with self.connect() as connection:
            count = connection.execute(
                """
                SELECT COUNT(*) FROM (
                    SELECT project_id, mr_iid FROM reviews
                    WHERE discovered_at >= ?
                    GROUP BY project_id, mr_iid
                )
                """,
                (cutoff,),
            ).fetchone()[0]
            recent = connection.execute(
                """
                SELECT project_id, project_path, mr_iid, head_sha, status,
                       report_path, report_content, discovered_at, reviewed_at
                FROM reviews WHERE discovered_at >= ?
                ORDER BY discovered_at DESC LIMIT 100
                """,
                (cutoff,),
            ).fetchall()
        return int(count), recent

    def report(self, project_id: int, mr_iid: int, head_sha: str) -> sqlite3.Row | None:
        with self.connect() as connection:
            return connection.execute(
                """
                SELECT project_path, mr_iid, head_sha, status, report_path, reviewed_at
                       , report_content, metadata_json, comparison_json
                FROM reviews WHERE project_id = ? AND mr_iid = ? AND head_sha = ?
                """,
                (project_id, mr_iid, head_sha),
            ).fetchone()


STYLE = """
:root{color-scheme:light;--ink:#172033;--muted:#667085;--line:#e3e8ef;--blue:#2563eb;--blue-dark:#1746a2;--blue-soft:#edf4ff;--bg:#f5f7fb;--card:#fff;--sidebar:#111827;--sidebar-muted:#a8b3c5;--red:#b42318;--red-soft:#fff1f0;--green:#16803c;--green-soft:#ebf8ef;--amber:#9a6700;--amber-soft:#fff7df;--shadow:0 12px 32px rgba(17,24,39,.06)}
*{box-sizing:border-box}html{min-height:100%}body{margin:0;min-height:100vh;background:var(--bg);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.45}a{color:var(--blue);text-underline-offset:2px}.public-main{max-width:1120px;margin:0 auto;padding:38px 24px 72px}.app-shell{display:grid;grid-template-columns:252px minmax(0,1fr);min-height:100vh}.sidebar{position:sticky;top:0;height:100vh;background:var(--sidebar);color:#fff;padding:24px 16px 18px;display:flex;flex-direction:column}.brand{display:flex;align-items:center;gap:12px;color:#fff;text-decoration:none;padding:0 10px 24px;border-bottom:1px solid rgba(255,255,255,.1)}.brand-mark{display:grid;place-items:center;width:38px;height:38px;border-radius:10px;background:linear-gradient(145deg,#3b82f6,#1d4ed8);font-size:13px;font-weight:850;letter-spacing:.04em;box-shadow:0 8px 18px rgba(37,99,235,.3)}.brand strong{display:block;font-size:15px}.brand small{display:block;color:var(--sidebar-muted);font-size:11px;margin-top:1px}.side-nav{display:grid;gap:6px;padding:22px 0}.side-nav a{display:flex;align-items:center;gap:12px;padding:11px 12px;border-radius:9px;color:var(--sidebar-muted);font-weight:650;text-decoration:none}.side-nav a:hover{background:rgba(255,255,255,.07);color:#fff}.side-nav a[aria-current=page]{background:#243c66;color:#fff;box-shadow:inset 3px 0 #60a5fa}.nav-icon{display:grid;place-items:center;width:24px;height:24px;border-radius:7px;background:rgba(255,255,255,.08);font-size:11px;font-weight:800}.sidebar-footer{margin-top:auto;border-top:1px solid rgba(255,255,255,.1);padding:18px 10px 0}.service-state{display:flex;align-items:flex-start;gap:9px;color:var(--sidebar-muted);font-size:12px;line-height:1.35;margin-bottom:17px}.service-dot{width:9px;height:9px;margin-top:3px;border-radius:50%;background:#60a5fa;box-shadow:0 0 0 3px rgba(96,165,250,.14);flex:0 0 auto}.service-dot.completed{background:#4ade80;box-shadow:0 0 0 3px rgba(74,222,128,.14)}.service-dot.failed{background:#f87171;box-shadow:0 0 0 3px rgba(248,113,113,.14)}.user-row{display:flex;align-items:center;gap:10px;margin-bottom:12px}.user-avatar{display:grid;place-items:center;width:32px;height:32px;border-radius:50%;background:#334155;color:#fff;font-size:12px;font-weight:800}.user-row span{font-size:13px;overflow:hidden;text-overflow:ellipsis}.signout{width:100%;background:transparent;border:1px solid rgba(255,255,255,.16);color:#d9e1ec;padding:9px 12px}.signout:hover{background:rgba(255,255,255,.07)}.app-main{min-width:0;padding:34px clamp(24px,4vw,56px) 72px}.content{width:100%;max-width:1440px;margin:0 auto}.page-header{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;margin-bottom:28px}.eyebrow{color:var(--blue);font-size:12px;font-weight:800;letter-spacing:.09em;text-transform:uppercase;margin:0 0 7px}.page-header h1{font-size:32px;line-height:1.15;margin:0;letter-spacing:-.025em}.page-header .sub{max-width:720px}.connection-status{display:flex;align-items:center;gap:9px;color:var(--muted);font-size:14px;margin:9px 0 0}.connection-dot{width:9px;height:9px;border-radius:50%;background:var(--red);box-shadow:0 0 0 3px rgba(180,35,24,.1);flex:0 0 auto}.connection-dot.up{background:var(--green);box-shadow:0 0 0 3px rgba(22,128,60,.12)}.header-actions{display:flex;align-items:center;gap:10px;flex-wrap:wrap}h1{font-size:31px;margin:0}h2{font-size:20px;margin:0 0 8px;letter-spacing:-.01em}.section-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:20px}.sub{color:var(--muted);margin:6px 0 0}.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:24px;box-shadow:var(--shadow);margin-bottom:22px}.danger-zone{border-color:#f2b8b3}.auth{max-width:480px;margin:8vh auto}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px}.metric{position:relative;padding:19px 20px;border:1px solid var(--line);border-radius:12px;background:linear-gradient(180deg,#fff,#fbfcfe);color:var(--muted);font-size:13px;font-weight:650}.metric strong{display:block;color:var(--ink);font-size:29px;line-height:1.2;margin-top:7px;letter-spacing:-.03em}.metric.critical{border-color:#f2b8b3;background:linear-gradient(180deg,#fff,var(--red-soft))}.metric.success{border-color:#b9dfc4;background:linear-gradient(180deg,#fff,var(--green-soft))}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}.field label,.date-filter label{display:block;font-weight:700;margin-bottom:7px}.field small{display:block;color:var(--muted);line-height:1.35;margin-top:6px}.field input,.field select,.date-filter input{width:100%;padding:11px 12px;border:1px solid #aebdce;border-radius:9px;background:#fff;font:inherit}.field input:focus,.field select:focus,.date-filter input:focus,button:focus-visible,a:focus-visible,summary:focus-visible{outline:3px solid #bed4ff;outline-offset:2px;border-color:var(--blue)}[hidden]{display:none!important}button,.button{display:inline-flex;align-items:center;justify-content:center;border:0;border-radius:9px;background:var(--blue);color:#fff;font-weight:700;padding:10px 15px;cursor:pointer;text-decoration:none;font:inherit}.button:hover,button:hover{filter:brightness(.97)}.secondary{background:var(--blue-soft);color:var(--blue-dark)}.danger{background:var(--red)}.actions{display:flex;gap:10px;align-items:center;margin-top:22px;flex-wrap:wrap}.inline-control{display:flex;gap:8px;align-items:center}.inline-control input{min-width:0;flex:1}.inline-control button{white-space:nowrap}.model-picker{margin-top:8px}.model-status{min-height:18px}.filter-bar{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin-bottom:20px;padding:16px;background:#f8fafc;border:1px solid var(--line);border-radius:12px}.filter-bar .actions{margin-top:0}.date-filter{display:grid;grid-template-columns:minmax(150px,1fr) minmax(150px,1fr) auto;gap:8px;align-items:end}.pagination{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-top:18px}.pagination .actions{margin-top:0}.page-selector{display:flex;align-items:center;gap:8px}.page-selector label{font-weight:700}.page-selector select{padding:10px;border:1px solid #aebdce;border-radius:9px;background:#fff;font:inherit}.notice,.error{padding:13px 15px;border-radius:10px;margin-bottom:18px;border:1px solid transparent}.notice{background:var(--green-soft);border-color:#c9e8d2;color:#116329}.error{background:var(--red-soft);border-color:#f5c7c3;color:var(--red)}table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:13px 11px;border-bottom:1px solid var(--line);vertical-align:top}tbody tr:hover{background:#f8faff}tbody tr:last-child td{border-bottom:0}th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.065em;white-space:nowrap}.status{font-weight:750}.high_severity,.failed,.down{color:var(--red)}.completed,.up{color:var(--green)}.pending,.unknown{color:var(--blue)}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#111827;color:#e5e7eb;padding:20px;border-radius:12px;line-height:1.5}.severity{display:inline-block;padding:4px 8px;border-radius:999px;font-size:11px;font-weight:850;letter-spacing:.035em}.severity-critical,.severity-high{background:var(--red-soft);color:var(--red)}.severity-medium{background:var(--amber-soft);color:var(--amber)}.severity-low{background:var(--blue-soft);color:#31506f}details summary{cursor:pointer;color:var(--blue);font-weight:700}.finding-details{margin:10px 0 0;min-width:320px;max-width:620px;background:#f5f8fc;color:var(--ink);border:1px solid var(--line);padding:14px;font-size:13px}.empty-state{text-align:center;color:var(--muted);padding:34px!important}.table-wrap{overflow:auto}.muted-link{color:var(--muted)}
.severity-safe{background:var(--green-soft);color:var(--green)}.severity-filter{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:20px}.severity-filter .button{padding:8px 12px}.expandable-row{cursor:pointer}.expandable-row:focus{outline:3px solid #bed4ff;outline-offset:-3px}.row-toggle,.manual-review-button{padding:7px 10px;font-size:13px;white-space:nowrap}.review-state{font-weight:800}.review-state-open{color:var(--blue-dark)}.review-state-in_progress{color:var(--amber)}.review-state-done{color:var(--green)}.expanded-review td{padding:0 11px 18px;background:#f8fafc}.review-details{border:1px solid var(--line);border-radius:12px;background:#fff;padding:20px}.review-detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}.review-section{border:1px solid var(--line);border-radius:10px;padding:16px}.review-section+.review-section{margin-top:16px}.review-section h3{font-size:14px;margin:0 0 8px}.review-copy{white-space:pre-wrap;margin:0;color:var(--ink)}.diff-view{max-height:520px;overflow:auto;margin:8px 0 0;padding:8px 0;background:#fff;color:#344054;border:1px solid #d0d5dd;border-radius:10px;font-size:12px;line-height:1.55;white-space:pre}.diff-view code{display:block;min-width:max-content}.diff-line{display:block;padding:0 14px;min-height:1.55em}.diff-context{color:#344054}.diff-add{color:#067647;background:#ecfdf3}.diff-delete{color:#b42318;background:#fff1f0}.diff-hunk{color:#175cd3;background:#eff8ff}.diff-meta{color:#6941c6;background:#f9f5ff;font-weight:650}.historical-note{color:var(--muted);font-style:italic}.review-meta{display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;margin-top:14px}.inline-commit-summary{margin:0 0 12px;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:#f8fafc;color:var(--muted)}.commit-summary-list{display:grid;gap:8px}.commit-summary-item{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap}.commit-message{font-weight:750;color:var(--ink);white-space:pre-wrap}.commit-author{font-size:13px;color:var(--muted)}.manual-review-dialog{width:min(620px,calc(100vw - 32px));border:0;border-radius:16px;padding:24px;box-shadow:0 24px 80px rgba(17,24,39,.28)}.manual-review-dialog::backdrop{background:rgba(15,23,42,.55)}.dialog-heading{display:flex;justify-content:space-between;align-items:flex-start;gap:18px;margin-bottom:20px}.dialog-heading h2{margin:0}.manual-review-dialog fieldset{display:flex;gap:18px;border:1px solid var(--line);border-radius:10px;margin:18px 0;padding:14px}.manual-review-dialog legend{font-weight:750;padding:0 6px}.manual-review-dialog textarea{width:100%;padding:11px 12px;border:1px solid #aebdce;border-radius:9px;font:inherit;resize:vertical}.manual-decision{margin-top:12px;padding:12px;border-radius:9px;background:#f8fafc;border:1px solid var(--line)}
.grid+.table-wrap{margin-top:22px}
.table-controls{display:flex;justify-content:flex-end;margin:22px 0 10px}
.model-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 18px;border-bottom:1px solid var(--line)}.model-tab{display:inline-flex;padding:10px 14px;color:var(--muted);font-weight:750;text-decoration:none;border-bottom:3px solid transparent;margin-bottom:-1px}.model-tab:hover{color:var(--blue)}.model-tab[aria-selected=true]{color:var(--blue-dark);border-bottom-color:var(--blue)}.comparison-summary{display:grid;grid-template-columns:minmax(180px,1.5fr) repeat(5,minmax(110px,1fr));gap:10px;margin:0 0 18px}.comparison-model,.comparison-stat{padding:12px 14px;border:1px solid var(--line);border-radius:10px;background:#f8fafc;min-width:0}.comparison-model span,.comparison-stat span{display:block;color:var(--muted);font-size:11px;font-weight:750;text-transform:uppercase;letter-spacing:.04em}.comparison-model strong,.comparison-stat strong{display:block;margin-top:5px;overflow-wrap:anywhere}.comparison-stat strong{font-size:16px}
@media(max-width:900px){.app-shell{grid-template-columns:1fr}.sidebar{position:relative;height:auto;padding:14px 18px}.brand{padding:0 4px 14px}.side-nav{display:flex;overflow:auto;padding:12px 0 0}.side-nav a{white-space:nowrap}.sidebar-footer{display:flex;align-items:center;gap:14px;margin:12px 0 0;padding:12px 4px 0}.service-state{margin:0;margin-right:auto}.user-row{margin:0}.signout{width:auto}.app-main{padding:26px 20px 56px}.page-header{margin-bottom:22px}}
@media(max-width:1100px){.comparison-summary{grid-template-columns:repeat(3,minmax(140px,1fr))}}@media(max-width:680px){.grid,.form-grid,.review-detail-grid,.comparison-summary{grid-template-columns:1fr}.inline-control{align-items:stretch;flex-direction:column}.filter-bar,.pagination,.page-header,.section-heading{align-items:stretch;flex-direction:column}.date-filter{grid-template-columns:1fr}.page-header h1{font-size:28px}.app-main{padding:22px 14px 48px}.card{padding:18px}.sidebar-footer{align-items:stretch;flex-wrap:wrap}.service-state{width:100%}.table-wrap{overflow:auto}}
"""


def document(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)} · Design Review</title><style>{STYLE}</style>"
        f"</head><body>{body}</body></html>"
    )


def page(title: str, body: str) -> str:
    return document(title, f"<main class='public-main'>{body}</main>")


def application_page(
    title: str,
    heading: str,
    subtitle: str,
    body: str,
    username: str,
    csrf_token: str,
    active_page: str,
    reviewer_label: str,
    reviewer_class: str,
    header_actions: str = "",
    header_status: tuple[str, str] | None = None,
) -> str:
    navigation_items = []
    for key, href, icon, label in (
        ("dashboard", "/", "D", "Dashboard"),
        ("completed", "/completed", "C", "Completed MRs"),
        ("repositories", "/repositories", "R", "Repositories"),
        ("settings", "/settings", "S", "Settings"),
    ):
        current = " aria-current='page'" if key == active_page else ""
        navigation_items.append(
            f"<a href='{href}'{current}>"
            f"<span class='nav-icon' aria-hidden='true'>{icon}</span>{label}</a>"
        )
    navigation = "".join(navigation_items)
    safe_username = html.escape(username)
    safe_initial = html.escape((username[:1] or "A").upper())
    subtitle_content = (
        f"<p class='connection-status'><span class='connection-dot {html.escape(header_status[1])}'></span>{html.escape(header_status[0])}</p>"
        if header_status is not None
        else f"<p class='sub'>{html.escape(subtitle)}</p>"
    )
    shell = f"""
    <div class='app-shell'>
      <aside class='sidebar'>
        <a class='brand' href='/' aria-label='Design Review home'>
          <span class='brand-mark'>DR</span><span><strong>Design Review</strong><small>Automated MR assurance</small></span>
        </a>
        <nav class='side-nav' aria-label='Primary navigation'>{navigation}</nav>
        <div class='sidebar-footer'>
          <div class='service-state'><span class='service-dot {html.escape(reviewer_class)}'></span><span>{html.escape(reviewer_label)}</span></div>
          <div class='user-row'><span class='user-avatar'>{safe_initial}</span><span title='{safe_username}'>{safe_username}</span></div>
          <form method='post' action='/logout'><input type='hidden' name='csrf' value='{html.escape(csrf_token)}'><button class='signout' type='submit'>Sign out</button></form>
        </div>
      </aside>
      <main class='app-main'><div class='content'>
        <header class='page-header'><div><p class='eyebrow'>Design Review</p><h1>{html.escape(heading)}</h1>{subtitle_content}</div><div class='header-actions'>{header_actions}</div></header>
        {body}
      </div></main>
    </div>"""
    return document(title, shell)


def form_field(key: str, value: str) -> str:
    setting = next(item for item in RUNTIME_SETTINGS if item.key == key)
    if setting.kind == "choice":
        options = "".join(
            f"<option value='{html.escape(choice)}'"
            f"{' selected' if choice == value else ''}>{html.escape(choice.title())}</option>"
            for choice in setting.choices
        )
        control = f"<select id='{key}' name='{key}'>{options}</select>"
    else:
        step = "1" if setting.kind == "integer" else "0.01"
        control = (
            f"<input id='{key}' name='{key}' type='number' value='{html.escape(value)}' "
            f"min='{setting.minimum}' max='{setting.maximum}' step='{step}' required>"
        )
    return (
        f"<div class='field'><label for='{key}'>{html.escape(setting.label)}</label>"
        f"{control}<small>{html.escape(setting.help_text)}</small></div>"
    )


def cookie_value(raw_header: str | None, name: str) -> str:
    jar = cookies.SimpleCookie()
    if raw_header:
        try:
            jar.load(raw_header)
        except cookies.CookieError:
            return ""
    morsel = jar.get(name)
    return morsel.value if morsel else ""


def handler_factory(
    store: WebStore,
    report_dir: Path,
    secure_cookies: bool,
    vault: MemoryVault,
):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SecurityReviewUI/1"
        sys_version = ""

        def security_headers(self) -> None:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; form-action 'self'; "
                "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'",
            )
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")

        def send_page(
            self,
            status: int,
            content: str,
            extra_headers: list[tuple[str, str]] | None = None,
        ) -> None:
            encoded = content.encode("utf-8")
            self.send_response(status)
            self.security_headers()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            for key, value in extra_headers or []:
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(encoded)

        def send_javascript(self) -> None:
            self.send_response(200)
            self.security_headers()
            self.send_header("Content-Type", "text/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(APP_JAVASCRIPT)))
            self.end_headers()
            self.wfile.write(APP_JAVASCRIPT)

        def send_json(self, status: int, payload: dict[str, Any]) -> None:
            encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.security_headers()
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def redirect(
            self, location: str, extra_headers: list[tuple[str, str]] | None = None
        ) -> None:
            self.send_response(303)
            self.security_headers()
            self.send_header("Location", location)
            for key, value in extra_headers or []:
                self.send_header(key, value)
            self.end_headers()

        def make_cookie(self, name: str, value: str, max_age: int) -> str:
            parts = [
                f"{name}={value}",
                "Path=/",
                f"Max-Age={max_age}",
                "HttpOnly",
                "SameSite=Strict",
            ]
            if secure_cookies:
                parts.append("Secure")
            return "; ".join(parts)

        def form(self) -> dict[str, str]:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as exc:
                raise ReviewError("Invalid request length.") from exc
            if length < 1 or length > 65_536:
                raise ReviewError("Invalid form size.")
            body = self.rfile.read(length).decode("utf-8", errors="strict")
            parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
            return {key: values[-1] for key, values in parsed.items()}

        def session(self) -> tuple[str, sqlite3.Row] | None:
            token = cookie_value(self.headers.get("Cookie"), "reviewer_session")
            if not token:
                return None
            row = store.session(token)
            return (token, row) if row is not None else None

        def require_session(self) -> tuple[str, sqlite3.Row] | None:
            cookie_token = cookie_value(
                self.headers.get("Cookie"), "reviewer_session"
            )
            session = self.session()
            if session is None:
                headers = (
                    [("Set-Cookie", self.make_cookie("reviewer_session", "", 0))]
                    if cookie_token
                    else []
                )
                self.redirect(
                    "/login?reason=restart" if cookie_token else "/login", headers
                )
                return None
            token, _ = session
            active_credentials, _ = vault.snapshot()
            if store.credentials_configured() and active_credentials is None:
                store.delete_session(token)
                headers = [
                    ("Set-Cookie", self.make_cookie("reviewer_session", "", 0))
                ]
                self.redirect("/login?reason=restart", headers)
                return None
            return session

        def preauth_token(self) -> tuple[str, list[tuple[str, str]]]:
            token = cookie_value(self.headers.get("Cookie"), "reviewer_csrf")
            if token:
                return token, []
            token = secrets.token_urlsafe(32)
            return token, [("Set-Cookie", self.make_cookie("reviewer_csrf", token, 3600))]

        def valid_csrf(self, submitted: str, expected: str) -> bool:
            return bool(submitted and expected and hmac.compare_digest(submitted, expected))

        def do_GET(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/healthz":
                payload = b'{"status":"ok"}\n'
                self.send_response(200)
                self.security_headers()
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if parsed.path == "/app.js":
                self.send_javascript()
            elif parsed.path == "/setup":
                self.show_setup()
            elif parsed.path == "/login":
                self.show_login(urllib.parse.parse_qs(parsed.query))
            elif parsed.path == "/settings":
                self.show_settings(urllib.parse.parse_qs(parsed.query))
            elif parsed.path == "/repositories":
                self.show_repositories(urllib.parse.parse_qs(parsed.query))
            elif parsed.path == "/completed":
                self.show_completed(urllib.parse.parse_qs(parsed.query))
            elif parsed.path == "/report":
                self.show_report(urllib.parse.parse_qs(parsed.query))
            elif parsed.path == "/mr-diff":
                self.show_mr_diff(urllib.parse.parse_qs(parsed.query))
            elif parsed.path == "/mr-commits":
                self.show_mr_commits(urllib.parse.parse_qs(parsed.query))
            elif parsed.path == "/repository":
                self.show_repository(urllib.parse.parse_qs(parsed.query))
            elif parsed.path == "/":
                self.show_dashboard(urllib.parse.parse_qs(parsed.query))
            else:
                self.send_page(404, page("Not found", "<div class='card'><h1>Not found</h1></div>"))

        def do_POST(self) -> None:  # noqa: N802
            parsed = urllib.parse.urlparse(self.path)
            try:
                form = self.form()
                if parsed.path == "/setup":
                    self.create_admin(form)
                elif parsed.path == "/login":
                    self.login(form)
                elif parsed.path == "/logout":
                    self.logout(form)
                elif parsed.path == "/credentials":
                    self.update_credentials(form)
                elif parsed.path == "/credentials/test-gitlab":
                    self.test_gitlab_credentials(form)
                elif parsed.path == "/credentials/test-llm":
                    self.test_llm_credentials(form)
                elif parsed.path == "/credentials/models":
                    self.fetch_llm_models(form)
                elif parsed.path == "/settings":
                    self.update_settings(form)
                elif parsed.path == "/reset-review-data":
                    self.reset_review_data(form)
                elif parsed.path == "/manual-review":
                    self.update_manual_review(form)
                else:
                    self.send_page(404, page("Not found", "<div class='card'><h1>Not found</h1></div>"))
            except (ReviewError, UnicodeDecodeError) as exc:
                self.send_page(
                    400,
                    page(
                        "Invalid request",
                        f"<div class='card auth'><h1>Invalid request</h1>"
                        f"<p class='error'>{html.escape(str(exc))}</p>"
                        "<a class='button secondary' href='/'>Return</a></div>",
                    ),
                )

        def show_setup(self, error: str = "") -> None:
            if store.user_count() > 0:
                self.redirect("/login")
                return
            csrf, headers = self.preauth_token()
            error_html = f"<p class='error'>{html.escape(error)}</p>" if error else ""
            body = f"""
            <div class='card auth'><h1>Create administrator</h1>
            <p class='sub'>Create the local account first. You will sign in and configure the reviewer afterward.</p>
            {error_html}<form method='post' action='/setup'>
            <input type='hidden' name='csrf' value='{html.escape(csrf)}'>
            <div class='field'><label for='username'>Username</label><input id='username' name='username' autocomplete='username' required></div><br>
            <div class='field'><label for='password'>Password</label><input id='password' name='password' type='password' minlength='12' autocomplete='new-password' required><small>Use at least 12 characters.</small></div><br>
            <div class='field'><label for='confirm'>Confirm password</label><input id='confirm' name='confirm' type='password' minlength='12' autocomplete='new-password' required></div>
            <div class='actions'><button type='submit'>Create administrator</button></div>
            </form></div>"""
            self.send_page(200, page("Initial setup", body), headers)

        def create_admin(self, form: dict[str, str]) -> None:
            expected = cookie_value(self.headers.get("Cookie"), "reviewer_csrf")
            if not self.valid_csrf(form.get("csrf", ""), expected):
                raise ReviewError("The setup form expired. Reload the page and try again.")
            username = form.get("username", "").strip()
            password = form.get("password", "")
            if not USERNAME_PATTERN.fullmatch(username):
                self.show_setup("Username must be 3–64 letters, numbers, dots, dashes, or underscores.")
                return
            if len(password) < 12 or len(password) > 1024:
                self.show_setup("Password must contain between 12 and 1,024 characters.")
                return
            if password != form.get("confirm", ""):
                self.show_setup("The passwords do not match.")
                return
            store.create_first_user(username, password)
            self.redirect("/login")

        def show_login(
            self, query: dict[str, list[str]] | None = None, error: str = ""
        ) -> None:
            if store.user_count() == 0:
                self.redirect("/setup")
                return
            csrf, headers = self.preauth_token()
            error_html = f"<p class='error'>{html.escape(error)}</p>" if error else ""
            restart_notice = (
                "<p class='notice'>The service was restarted. Sign in again to unlock the encrypted credentials.</p>"
                if (query or {}).get("reason", [""])[0] == "restart"
                else ""
            )
            body = f"""
            <div class='card auth'><h1>Design Review</h1><p class='sub'>Sign in to manage review settings and see results.</p>
            {restart_notice}{error_html}<form method='post' action='/login'>
            <input type='hidden' name='csrf' value='{html.escape(csrf)}'>
            <div class='field'><label for='username'>Username</label><input id='username' name='username' autocomplete='username' required></div><br>
            <div class='field'><label for='password'>Password</label><input id='password' name='password' type='password' autocomplete='current-password' required></div>
            <div class='actions'><button type='submit'>Sign in</button></div></form></div>"""
            self.send_page(200, page("Sign in", body), headers)

        def login(self, form: dict[str, str]) -> None:
            remote = self.client_address[0]
            expected = cookie_value(self.headers.get("Cookie"), "reviewer_csrf")
            if not self.valid_csrf(form.get("csrf", ""), expected):
                raise ReviewError("The login form expired. Reload the page and try again.")
            if store.login_blocked(remote):
                self.send_page(429, page("Try later", "<div class='card auth'><h1>Too many attempts</h1><p class='error'>Try again in 15 minutes.</p></div>"))
                return
            username = form.get("username", "")
            password = form.get("password", "")
            user = (
                store.authenticate(username, password)
                if len(username) <= 64 and len(password) <= 1024
                else None
            )
            if user is None:
                store.record_failed_login(remote)
                self.show_login(error="Invalid username or password.")
                return
            if store.credentials_configured():
                try:
                    credentials, salt, encryption_key = (
                        store.unlock_credentials_with_key(password)
                    )
                except ReviewError as exc:
                    self.show_login(error=str(exc))
                    return
                vault.set(credentials, salt=salt, encryption_key=encryption_key)
            else:
                vault.prepare(password)
            store.clear_failed_logins(remote)
            token, _ = store.create_session(int(user["id"]))
            headers = [("Set-Cookie", self.make_cookie("reviewer_session", token, SESSION_LIFETIME_SECONDS))]
            self.redirect("/", headers)

        def logout(self, form: dict[str, str]) -> None:
            session = self.require_session()
            if session is None:
                return
            token, user = session
            if not self.valid_csrf(form.get("csrf", ""), str(user["csrf_token"])):
                raise ReviewError("Invalid form token.")
            store.delete_session(token)
            headers = [("Set-Cookie", self.make_cookie("reviewer_session", "", 0))]
            self.redirect("/login", headers)

        def update_credentials(self, form: dict[str, str]) -> None:
            session = self.require_session()
            if session is None:
                return
            _, user = session
            if not self.valid_csrf(form.get("csrf", ""), str(user["csrf_token"])):
                raise ReviewError("Invalid form token.")
            existing, salt, encryption_key = self.credential_context()
            credentials = self.merged_credentials(form, existing)
            store.save_encrypted_credentials(credentials, salt, encryption_key)
            vault.set(credentials)
            if credentials.comparison_ready():
                message = "Credentials saved; four-model comparison reviews are active."
            elif credentials.review_ready():
                message = (
                    "Credentials saved; Anthropic-only reviews are active. "
                    "Add OpenAI and Copilot credentials later to enable comparison reviews."
                )
            else:
                message = "Credentials saved; MR discovery is active. Add an Anthropic API key to start reviews."
            self.redirect("/settings?message=" + urllib.parse.quote(message))

        def update_manual_review(self, form: dict[str, str]) -> None:
            session = self.require_session()
            if session is None:
                return
            _, user = session
            if not self.valid_csrf(form.get("csrf", ""), str(user["csrf_token"])):
                raise ReviewError("Invalid form token.")
            try:
                project_id = int(form.get("project_id", ""))
                mr_iid = int(form.get("mr_iid", ""))
            except ValueError as exc:
                raise ReviewError("Invalid merge-request reference.") from exc
            head_sha = form.get("head_sha", "").strip()
            item_key = form.get("item_key", "").strip()
            if not re.fullmatch(r"[0-9a-fA-F]{7,64}", head_sha):
                raise ReviewError("Invalid merge-request revision.")
            if item_key != MR_MANUAL_REVIEW_KEY and not re.fullmatch(
                r"[0-9a-f]{64}", item_key
            ):
                raise ReviewError("Invalid manual-review item.")
            review = store.report(project_id, mr_iid, head_sha)
            if review is None:
                raise ReviewError("The merge-request revision no longer exists.")
            valid_keys = {MR_MANUAL_REVIEW_KEY}
            valid_keys.update(
                finding["item_key"]
                for finding in parse_security_findings(
                    str(review["report_content"] or "")
                )
            )
            try:
                comparison = json.loads(str(review["comparison_json"] or "{}"))
            except (KeyError, TypeError, json.JSONDecodeError):
                comparison = {}
            if isinstance(comparison, dict):
                for profile, result in comparison.items():
                    if not isinstance(result, dict):
                        continue
                    valid_keys.add(
                        hashlib.sha256(
                            f"{profile}\0{MR_MANUAL_REVIEW_KEY}".encode("utf-8")
                        ).hexdigest()
                    )
                    for finding in parse_security_findings(
                        str(result.get("report_content", ""))
                    ):
                        valid_keys.add(
                            hashlib.sha256(
                                f"{profile}\0{finding['item_key']}".encode("utf-8")
                            ).hexdigest()
                        )
            if item_key not in valid_keys:
                raise ReviewError("The design-review item no longer exists.")

            workflow_status = form.get("workflow_status", "").strip()
            if workflow_status not in MANUAL_REVIEW_STATUSES:
                raise ReviewError("Choose a valid manual-review status.")
            resolution = form.get("resolution", "").strip()
            severity = form.get("severity", "").strip().upper()
            comments = form.get("comments", "").strip()
            if len(comments) > 4000:
                raise ReviewError("Comments cannot exceed 4,000 characters.")
            if workflow_status == "done":
                if resolution not in MANUAL_REVIEW_RESOLUTIONS:
                    raise ReviewError("Choose false positive or confirmed finding.")
                if not comments:
                    raise ReviewError("Add comments before marking the review Done.")
                if resolution == "finding" and severity not in MANUAL_FINDING_SEVERITIES:
                    raise ReviewError("Choose a severity for the confirmed finding.")
                if resolution == "false_positive":
                    severity = ""
            else:
                resolution = ""
                severity = ""
                comments = ""

            store.save_manual_review(
                project_id,
                mr_iid,
                head_sha,
                item_key,
                workflow_status,
                resolution,
                severity,
                comments,
                str(user["username"]),
            )
            return_to = form.get("return_to", "/").strip()
            return_url = urllib.parse.urlparse(return_to)
            if (
                return_url.scheme
                or return_url.netloc
                or return_url.path not in {"/", "/completed", "/repository"}
            ):
                return_to = "/"
            self.redirect(return_to)

        def credential_context(self) -> tuple[Credentials, bytes, bytes]:
            existing, _ = vault.snapshot()
            salt, encryption_key = vault.encryption_context()
            if store.credentials_configured() and existing is None:
                raise ReviewError(
                    "The credential vault is locked. Sign in again before changing credentials."
                )
            return existing or Credentials("", "", ""), salt, encryption_key

        def merged_credentials(
            self, form: dict[str, str], existing: Credentials
        ) -> Credentials:
            submitted_gitlab_url = form.get("gitlab_url", "").strip()
            submitted_gitlab_token = form.get("gitlab_token", "").strip()
            return validated_credentials(
                submitted_gitlab_url or existing.gitlab_url,
                submitted_gitlab_token or existing.gitlab_token,
                form.get("anthropic_api_key", "").strip() or existing.llm_api_key,
                "anthropic",
                "",
                form.get("anthropic_model", "").strip() or existing.llm_model,
                gitlab_group_path=form.get("gitlab_group_path", "").strip(),
                openai_api_key=(
                    form.get("openai_api_key", "").strip()
                    or existing.openai_api_key
                ),
                openai_model=(
                    form.get("openai_model", "").strip() or existing.openai_model
                ),
                copilot_api_key=(
                    form.get("copilot_api_key", "").strip()
                    or existing.copilot_api_key
                ),
                copilot_anthropic_model=(
                    form.get("copilot_anthropic_model", "").strip()
                    or existing.copilot_anthropic_model
                ),
                copilot_openai_model=(
                    form.get("copilot_openai_model", "").strip()
                    or existing.copilot_openai_model
                ),
            )

        def test_gitlab_credentials(self, form: dict[str, str]) -> None:
            session = self.require_session()
            if session is None:
                return
            _, user = session
            if not self.valid_csrf(form.get("csrf", ""), str(user["csrf_token"])):
                raise ReviewError("Invalid form token.")
            existing, _, _ = self.credential_context()
            credentials = self.merged_credentials(form, existing)
            projects = GitLabClient(
                credentials.gitlab_url,
                credentials.gitlab_token,
                credentials.gitlab_group_path,
            ).list_projects()
            self.redirect(
                "/settings?message="
                + urllib.parse.quote(
                    f"GitLab access test succeeded: {len(projects)} repositories are visible to this token."
                )
            )

        def test_llm_credentials(self, form: dict[str, str]) -> None:
            session = self.require_session()
            if session is None:
                return
            _, user = session
            if not self.valid_csrf(form.get("csrf", ""), str(user["csrf_token"])):
                raise ReviewError("Invalid form token.")
            existing, _, _ = self.credential_context()
            credentials = self.merged_credentials(form, existing)
            if not credentials.review_ready():
                raise ReviewError("Save an Anthropic API key before testing the review model.")
            if credentials.comparison_ready():
                configs = (
                    ("Anthropic", "anthropic", credentials.llm_api_key, credentials.llm_model),
                    ("OpenAI", "openai", credentials.openai_api_key, credentials.openai_model),
                    ("Copilot · Anthropic", "copilot", credentials.copilot_api_key, credentials.copilot_anthropic_model),
                    ("Copilot · OpenAI", "copilot", credentials.copilot_api_key, credentials.copilot_openai_model),
                )
            else:
                configs = (("Anthropic", "anthropic", credentials.llm_api_key, credentials.llm_model),)
            for profile, provider, key, model in configs:
                config = Config.from_credentials(
                    credentials.gitlab_url,
                    credentials.gitlab_token,
                    key,
                    store.settings(),
                    llm_provider=provider,
                    llm_model=model,
                    gitlab_group_path=credentials.gitlab_group_path,
                    review_profile=profile,
                )
                test_llm_connection(config)
            message = (
                "All four model connection tests succeeded."
                if credentials.comparison_ready()
                else "Anthropic model connection test succeeded."
            )
            self.redirect("/settings?message=" + urllib.parse.quote(message))

        def fetch_llm_models(self, form: dict[str, str]) -> None:
            session = self.session()
            if session is None:
                self.send_json(401, {"error": "Sign in again before fetching models."})
                return
            _, user = session
            if not self.valid_csrf(form.get("csrf", ""), str(user["csrf_token"])):
                self.send_json(403, {"error": "The form expired. Reload Settings and try again."})
                return
            try:
                existing, _, _ = self.credential_context()
                provider = form.get("model_provider", "").strip().lower()
                key_field = {
                    "anthropic": "anthropic_api_key",
                    "openai": "openai_api_key",
                    "copilot": "copilot_api_key",
                }.get(provider)
                if key_field is None:
                    raise ReviewError("Select a supported model provider.")
                stored_key = {
                    "anthropic": existing.llm_api_key,
                    "openai": existing.openai_api_key,
                    "copilot": existing.copilot_api_key,
                }[provider]
                api_key = form.get(key_field, "").strip() or stored_key
                models = list_llm_models(provider, api_key)
            except ReviewError as exc:
                self.send_json(400, {"error": str(exc)})
                return
            self.send_json(200, {"models": models})

        def reviewer_status(self) -> tuple[str, str]:
            active_credentials, _ = vault.snapshot()
            heartbeat = Path(os.environ.get("HEARTBEAT_FILE", "/data/heartbeat"))
            try:
                running = heartbeat.is_file() and time.time() - heartbeat.stat().st_mtime < 180
            except OSError:
                running = False
            if running and active_credentials is not None:
                return (
                    "Reviews active"
                    if active_credentials.comparison_ready()
                    else (
                        "Anthropic review active"
                        if active_credentials.review_ready()
                        else "GitLab discovery active"
                    ),
                    "completed",
                )
            if running:
                return "Reviewer locked", "failed"
            return "Waiting for reviewer heartbeat", "failed"

        def application_response(
            self,
            title: str,
            heading: str,
            subtitle: str,
            body: str,
            user: sqlite3.Row,
            active_page: str,
            header_actions: str = "",
            header_status: tuple[str, str] | None = None,
        ) -> None:
            reviewer_label, reviewer_class = self.reviewer_status()
            self.send_page(
                200,
                application_page(
                    title,
                    heading,
                    subtitle,
                    body,
                    str(user["username"]),
                    str(user["csrf_token"]),
                    active_page,
                    reviewer_label,
                    reviewer_class,
                    header_actions,
                    header_status,
                ),
            )

        def activity_window(self, query: dict[str, list[str]]) -> dict[str, Any]:
            period = query.get("period", ["week"])[0]
            if period not in {"day", "week", "month"}:
                period = "week"
            start_date = query.get("start_date", [""])[0].strip()
            end_date = query.get("end_date", [""])[0].strip()
            labels = {
                "day": "last 24 hours",
                "week": "last 7 days",
                "month": "last 30 days",
            }
            date_error = ""
            try:
                projects, activity_start, activity_end = store.repository_activity(
                    period, start_date, end_date
                )
            except ReviewError as exc:
                date_error = str(exc)
                start_date = ""
                end_date = ""
                projects, activity_start, activity_end = store.repository_activity(period)
            filter_label = (
                (
                    f"{start_date} UTC"
                    if start_date == end_date
                    else f"{start_date} to {end_date} UTC"
                )
                if start_date and end_date
                else labels[period]
            )
            activity_query = (
                {"start_date": start_date, "end_date": end_date}
                if start_date and end_date
                else {"period": period}
            )
            return {
                "period": period,
                "start_date": start_date,
                "end_date": end_date,
                "projects": projects,
                "activity_start": activity_start,
                "activity_end": activity_end,
                "filter_label": filter_label,
                "activity_query": activity_query,
                "date_error": date_error,
            }

        def filter_controls(
            self,
            context: dict[str, Any],
            action: str,
            fixed_query: Mapping[str, Any] | None = None,
        ) -> str:
            period = str(context["period"])
            fixed = dict(fixed_query or {})
            period_links = "".join(
                f"<a class='button {'primary' if choice == period else 'secondary'}' "
                f"href='{html.escape(action + '?' + urllib.parse.urlencode({**fixed, 'period': choice}))}'>{label}</a>"
                for choice, label in (("day", "Day"), ("week", "Week"), ("month", "Month"))
            )
            hidden_fields = "".join(
                f"<input type='hidden' name='{html.escape(str(key))}' value='{html.escape(str(value))}'>"
                for key, value in fixed.items()
            )
            maximum_date = datetime.now(timezone.utc).date().isoformat()
            return f"""
            <div class='filter-bar'><div class='actions'>{period_links}</div>
            <form class='date-filter' method='get' action='{action}'>
            {hidden_fields}
            <div><label for='activity_start_date'>Start date (UTC)</label><input id='activity_start_date' name='start_date' type='date' value='{html.escape(str(context['start_date']))}' max='{maximum_date}' required></div>
            <div><label for='activity_end_date'>End date (UTC)</label><input id='activity_end_date' name='end_date' type='date' value='{html.escape(str(context['end_date']))}' max='{maximum_date}' required></div>
            <button class='secondary' type='submit'>Apply range</button></form></div>"""

        def model_tabs(
            self,
            action: str,
            active_profile: str,
            query: Mapping[str, Any],
        ) -> str:
            tabs = "".join(
                f"<a class='model-tab' role='tab' aria-selected='{'true' if profile == active_profile else 'false'}' "
                f"href='{html.escape(action + '?' + urllib.parse.urlencode({**dict(query), 'profile': profile, 'page': 1}))}'>"
                f"{html.escape(COMPARISON_PROFILE_LABELS[profile])}</a>"
                for profile in COMPARISON_PROFILES
            )
            return f"<nav class='model-tabs' role='tablist' aria-label='Review model'>{tabs}</nav>"

        def usage_tiles(
            self, reports: Iterable[Mapping[str, Any]], profile: str
        ) -> str:
            report_list = list(reports)
            summary = profile_usage_summary(report_list, profile)
            model = (
                str(report_list[0].get("llm_model", ""))
                if report_list
                else ""
            )
            average_ms = summary["average_ms"]
            average_display = (
                f"{float(average_ms) / 1000:,.1f} s"
                if average_ms is not None
                else "Not reported"
            )
            model_text = html.escape(model or "No completed reviews")
            return f"""
            <div class='comparison-summary' aria-label='Selected model performance and cost'>
              <div class='comparison-model'><span>Selected model</span><strong>{model_text}</strong></div>
              <div class='comparison-stat'><span>Reviews</span><strong>{int(summary['reviews']):,}</strong></div>
              <div class='comparison-stat'><span>Average runtime</span><strong>{html.escape(average_display)}</strong></div>
              <div class='comparison-stat'><span>Input tokens</span><strong>{int(summary['input_tokens']):,}</strong></div>
              <div class='comparison-stat'><span>Output tokens</span><strong>{int(summary['output_tokens']):,}</strong></div>
              <div class='comparison-stat'><span>Reported cost</span><strong>{html.escape(str(summary['cost_display']))}</strong></div>
            </div>"""

        def findings_rows(
            self, findings: list[dict[str, Any]], return_to: str
        ) -> str:
            rows = []
            for finding in findings:
                severity = str(finding["severity"])
                mr_label = (
                    f"{html.escape(str(finding['project_path']))} !{int(finding['mr_iid'])}"
                )
                mr_url = str(finding["mr_url"])
                mr_display = (
                    f"<a href='{html.escape(mr_url)}' target='_blank' "
                    f"rel='noopener noreferrer'>{mr_label}</a>"
                    if mr_url
                    else mr_label
                )
                rows.append(
                    "<tr>"
                    f"<td><span class='severity severity-{severity.lower()}'>{html.escape(severity)}</span></td>"
                    f"<td>{html.escape(str(finding['title']))}</td>"
                    f"<td>{mr_display}</td>"
                    "<td><details><summary>View details</summary>"
                    f"<pre class='finding-details'>{html.escape(str(finding['details']))}</pre>"
                    "</details></td>"
                    f"<td>{manual_review_button(project_id=int(finding['project_id']), mr_iid=int(finding['mr_iid']), head_sha=str(finding['head_sha']), item_key=str(finding['item_key']), workflow_status=str(finding['manual_status']), resolution=str(finding['manual_resolution']), severity=str(finding['severity']) if str(finding['manual_resolution']) == 'finding' else '', comments=str(finding['manual_comments']), return_to=return_to)}</td></tr>"
                )
            return "".join(rows) or (
                "<tr><td class='empty-state' colspan='5'>No open Critical or High security findings in this period.</td></tr>"
            )

        def vault_notice(self) -> str:
            active_credentials, _ = vault.snapshot()
            if active_credentials is None and store.credentials_configured():
                return (
                    "<p class='error'>The credential session is unavailable. "
                    "Sign out and sign in again.</p>"
                )
            if active_credentials is None:
                return (
                    "<p class='error'>GitLab access is not configured. "
                    "<a href='/settings'>Open Settings</a> to start MR discovery.</p>"
                )
            if not active_credentials.comparison_ready():
                return ""
            return "<p class='notice'>GitLab discovery and four-model comparison reviews are active.</p>"

        def gitlab_connection_status(self) -> tuple[str, str]:
            scan_status = store.scan_status()
            state = scan_status.get("last_gitlab_check_status", "")
            check_time = scan_status.get("last_gitlab_check_at", "")[:19].replace("T", " ")
            checked_at = check_time + " UTC" if check_time else "recently"
            if state == "success":
                return f"GitLab connected · Last checked {checked_at}", "up"
            if state == "failed":
                return f"GitLab connection failed · Last checked {checked_at}", "down"
            return "GitLab connection not yet verified", "down"

        def show_dashboard(self, query: dict[str, list[str]]) -> None:
            if store.user_count() == 0:
                self.redirect("/setup")
                return
            session = self.require_session()
            if session is None:
                return
            _, user = session
            context = self.activity_window(query)
            selected_profile = query.get("profile", ["anthropic"])[0]
            if selected_profile not in COMPARISON_PROFILES:
                selected_profile = "anthropic"
            counts, _ = store.dashboard()
            manual_reviews = store.manual_review_map()
            profile_reports = store.latest_review_reports(
                context["activity_start"], context["activity_end"], selected_profile
            )
            findings, _ = collect_security_findings(profile_reports, manual_reviews)
            findings = [
                finding
                for finding in findings
                if str(finding["severity"]) in {"CRITICAL", "HIGH"}
            ]
            date_notice = (
                f"<p class='error'>{html.escape(str(context['date_error']))}</p>"
                if context["date_error"]
                else ""
            )
            body = f"""
            {date_notice}{self.vault_notice()}
            <section class='card'><div class='section-heading'><div><h2>Review status</h2><p class='sub'>Current outcome across all recorded merge-request revisions.</p></div></div>
            <div class='grid'>
              <div class='metric'>Queued<strong>{counts.get('pending', 0)}</strong></div>
              <div class='metric success'>Completed<strong>{counts.get('completed', 0)}</strong></div>
              <div class='metric critical'>High findings<strong>{len(findings)}</strong></div>
              <div class='metric'>Manual review<strong>{counts.get('manual_review_required', 0)}</strong></div>
              <div class='metric'>Failed<strong>{counts.get('failed', 0)}</strong></div>
            </div></section>
            <section class='card'><div class='section-heading'><div><h2>High-severity findings</h2><p class='sub'>Critical and High findings from {html.escape(COMPARISON_PROFILE_LABELS[selected_profile])} for the latest reviewed revision of each MR in {html.escape(str(context['filter_label']))}.</p></div><span class='severity severity-high'>{len(findings)} findings</span></div>
            {self.model_tabs('/', selected_profile, context['activity_query'])}
            {self.usage_tiles(profile_reports, selected_profile)}
            {self.filter_controls(context, '/', {'profile': selected_profile})}
            <div class='table-wrap'><table><thead><tr><th>Severity</th><th>Finding title</th><th>MR</th><th>Vulnerability details</th><th>Manual review</th></tr></thead><tbody>{self.findings_rows(findings, self.path)}</tbody></table></div></section>
            {manual_review_dialog(str(user['csrf_token']))}<script src='/app.js' defer></script>"""
            connection_status = self.gitlab_connection_status()
            self.application_response(
                "Dashboard",
                "Review dashboard",
                "",
                body,
                user,
                "dashboard",
                "<a class='button secondary' href='/repositories'>View repositories</a>",
                connection_status,
            )

        def show_completed(self, query: dict[str, list[str]]) -> None:
            if store.user_count() == 0:
                self.redirect("/setup")
                return
            session = self.require_session()
            if session is None:
                return
            _, user = session
            selected_profile = query.get("profile", ["anthropic"])[0]
            if selected_profile not in COMPARISON_PROFILES:
                selected_profile = "anthropic"
            reviews = store.completed_reviews(selected_profile)
            manual_reviews = store.manual_review_map()
            entries = completed_review_entries(reviews, manual_reviews)
            selected_severity = query.get("severity", ["all"])[0].lower()
            if selected_severity not in COMPLETED_SEVERITIES:
                selected_severity = "all"
            selected_status = query.get("manual_status", ["all"])[0].lower()
            if selected_status not in MANUAL_REVIEW_FILTERS:
                selected_status = "all"
            filtered_entries = [
                entry
                for entry in entries
                if (
                    selected_severity == "all"
                    or str(entry["severity"]).lower() == selected_severity
                )
                and (
                    selected_status == "all"
                    or str(entry["manual_status"]) == selected_status
                )
            ]
            try:
                requested_page = int(query.get("page", ["1"])[0])
            except ValueError:
                requested_page = 1
            page_count = max(
                1,
                (len(filtered_entries) + COMPLETED_ROWS_PER_PAGE - 1)
                // COMPLETED_ROWS_PER_PAGE,
            )
            page_number = min(max(requested_page, 1), page_count)
            start = (page_number - 1) * COMPLETED_ROWS_PER_PAGE
            page_entries = filtered_entries[start : start + COMPLETED_ROWS_PER_PAGE]
            severity_counts = {
                severity: sum(
                    1
                    for entry in entries
                    if str(entry["severity"]).lower() == severity
                )
                for severity in ("critical", "high", "medium", "low", "safe")
            }
            filter_links = "".join(
                f"<a class='button {'primary' if value == selected_severity else 'secondary'}' "
                f"href='/completed?{urllib.parse.urlencode({'profile': selected_profile, 'severity': value, 'manual_status': selected_status})}'>{label} ({len(entries) if value == 'all' else severity_counts[value]})</a>"
                for value, label in (
                    ("all", "All"),
                    ("critical", "Critical"),
                    ("high", "High"),
                    ("medium", "Medium"),
                    ("low", "Low"),
                    ("safe", "Safe"),
                )
            )
            status_counts = {
                status: sum(
                    1 for entry in entries if str(entry["manual_status"]) == status
                )
                for status in ("open", "in_progress", "done")
            }
            status_filter_links = "".join(
                f"<a class='button {'primary' if value == selected_status else 'secondary'}' "
                f"href='/completed?{urllib.parse.urlencode({'profile': selected_profile, 'severity': selected_severity, 'manual_status': value})}'>{label} ({len(entries) if value == 'all' else status_counts[value]})</a>"
                for value, label in (
                    ("all", "All statuses"),
                    ("open", "Open"),
                    ("in_progress", "In Progress"),
                    ("done", "Done"),
                )
            )
            rows = []
            for index, entry in enumerate(page_entries, start=start):
                severity = str(entry["severity"])
                detail_id = f"completed-review-{index}"
                mr_label = (
                    f"{html.escape(str(entry['project_path']))} !{int(entry['mr_iid'])}"
                )
                mr_url = str(entry["mr_url"])
                mr_display = (
                    f"<a href='{html.escape(mr_url)}' target='_blank' rel='noopener noreferrer'>{mr_label}</a>"
                    if mr_url
                    else mr_label
                )
                diff_content = str(entry["diff_content"])
                diff_display = (
                    render_diff_html(diff_content)
                    if diff_content
                    else "<p class='historical-note'>The reviewed diff was not retained for this historical record. New reviews store the bounded diff automatically.</p>"
                )
                report_query = urllib.parse.urlencode(
                    {
                        "project_id": int(entry["project_id"]),
                        "mr_iid": int(entry["mr_iid"]),
                        "sha": str(entry["head_sha"]),
                        "profile": selected_profile,
                    }
                )
                evidence_heading = "Review result" if severity == "SAFE" else "Finding evidence"
                reviewed_at = str(entry["reviewed_at"])[:19].replace("T", " ") + " UTC"
                commit_summary = inline_commit_summary(
                    int(entry["project_id"]),
                    int(entry["mr_iid"]),
                    str(entry["head_sha"]),
                )
                project_url = str(entry["project_web_url"])
                parsed_project_url = urllib.parse.urlparse(project_url)
                commit_url = (
                    project_url.rstrip("/")
                    + "/-/commit/"
                    + urllib.parse.quote(str(entry["head_sha"]), safe="")
                    if parsed_project_url.scheme == "https"
                    and parsed_project_url.netloc
                    else ""
                )
                commit_display = (
                    f"<a href='{html.escape(commit_url)}' target='_blank' rel='noopener noreferrer'><code>{html.escape(str(entry['head_sha'])[:12])}</code></a>"
                    if commit_url
                    else f"<code>{html.escape(str(entry['head_sha'])[:12])}</code>"
                )
                decision_details = ""
                if str(entry["manual_status"]) == "done":
                    resolution_label = (
                        "False positive"
                        if str(entry["manual_resolution"]) == "false_positive"
                        else f"Confirmed finding · {html.escape(str(entry['manual_severity']))}"
                    )
                    decision_details = (
                        "<section class='manual-decision'><strong>Manual resolution: "
                        f"{resolution_label}</strong><p class='review-copy'>"
                        f"{html.escape(str(entry['manual_comments']))}</p></section>"
                    )
                action = manual_review_button(
                    project_id=int(entry["project_id"]),
                    mr_iid=int(entry["mr_iid"]),
                    head_sha=str(entry["head_sha"]),
                    item_key=str(entry["item_key"]),
                    workflow_status=str(entry["manual_status"]),
                    resolution=str(entry["manual_resolution"]),
                    severity=str(entry["manual_severity"]),
                    comments=str(entry["manual_comments"]),
                    return_to=self.path,
                )
                rows.append(
                    f"<tr class='expandable-row' data-details-id='{detail_id}' tabindex='0' role='button' aria-expanded='false'>"
                    f"<td><span class='severity severity-{severity.lower()}'>{html.escape(severity)}</span></td>"
                    f"<td>{html.escape(str(entry['title']))}</td><td>{mr_display}</td>"
                    "<td><button class='row-toggle secondary' type='button'>View review</button></td>"
                    f"<td>{action}</td></tr>"
                    f"<tr class='expanded-review' id='{detail_id}' hidden><td colspan='5'><div class='review-details'>"
                    "<div class='review-detail-grid'>"
                    f"<section class='review-section'><h3>Review summary</h3><p class='review-copy'>{html.escape(str(entry['summary']))}</p></section>"
                    f"<section class='review-section'><h3>Severity explanation</h3><p class='review-copy'>{html.escape(str(entry['severity_explanation']))}</p></section>"
                    f"</div><section class='review-section'><h3>{evidence_heading}</h3><p class='review-copy'>{html.escape(str(entry['finding_details']))}</p></section>{decision_details}"
                    f"<section class='review-section'><h3>Reviewed code diff</h3>{commit_summary}{diff_display}</section>"
                    f"<div class='review-meta'><span class='sub'>Reviewed {html.escape(reviewed_at)} · Commit {commit_display}</span>"
                    f"<a class='button secondary' href='/report?{report_query}'>Open full report</a></div>"
                    "</div></td></tr>"
                )
            table_rows = "".join(rows) or (
                "<tr><td class='empty-state' colspan='5'>No completed reviews match these filters.</td></tr>"
            )
            page_query = {"profile": selected_profile, "severity": selected_severity, "manual_status": selected_status}
            previous_page = (
                f"<a class='button secondary' href='/completed?{urllib.parse.urlencode({**page_query, 'page': page_number - 1})}'>Previous</a>"
                if page_number > 1
                else ""
            )
            next_page = (
                f"<a class='button secondary' href='/completed?{urllib.parse.urlencode({**page_query, 'page': page_number + 1})}'>Next</a>"
                if page_number < page_count
                else ""
            )
            if filtered_entries:
                first = start + 1
                last = min(start + COMPLETED_ROWS_PER_PAGE, len(filtered_entries))
                result_range = f"Showing {first}–{last} of {len(filtered_entries)} review result(s)"
            else:
                result_range = "No review results to display"
            pagination = f"<div class='pagination'><p class='sub'>{result_range}</p><div class='actions'>{previous_page}<span>Page {page_number} of {page_count}</span>{next_page}</div></div>"
            body = f"""
            <section class='card'><div class='section-heading'><div><h2>Completed review results</h2><p class='sub'>Latest {html.escape(COMPARISON_PROFILE_LABELS[selected_profile])} result for every reviewed MR, including reviews with no findings. Select a row to inspect the evidence.</p></div><span class='severity severity-safe'>{len(reviews)} MRs</span></div>
            {self.model_tabs('/completed', selected_profile, {'severity': selected_severity, 'manual_status': selected_status})}
            {self.usage_tiles(reviews, selected_profile)}
            <nav class='severity-filter' aria-label='Filter completed reviews by severity'>{filter_links}</nav>
            <nav class='severity-filter' aria-label='Filter completed reviews by manual-review status'>{status_filter_links}</nav>
            <div class='table-wrap'><table><thead><tr><th>Severity</th><th>Finding title</th><th>MR</th><th>Vulnerability details</th><th>Manual review</th></tr></thead><tbody>{table_rows}</tbody></table></div>{pagination}</section>
            {manual_review_dialog(str(user['csrf_token']))}<script src='/app.js' defer></script>"""
            self.application_response(
                "Completed MRs",
                "Completed MRs",
                "Review every completed merge-request assessment and its retained evidence.",
                body,
                user,
                "completed",
            )

        def show_repositories(self, query: dict[str, list[str]]) -> None:
            if store.user_count() == 0:
                self.redirect("/setup")
                return
            session = self.require_session()
            if session is None:
                return
            _, user = session
            context = self.activity_window(query)
            projects = context["projects"]
            manual_reviews = store.manual_review_map()
            findings, finding_counts = collect_security_findings(
                store.latest_review_reports(
                    context["activity_start"], context["activity_end"]
                ),
                manual_reviews,
            )
            fetched_mrs = sum(int(project["mr_count"]) for project in projects)
            total_repositories = len(projects)
            page_size = normalize_repository_page_size(
                query.get("page_size", [str(REPOSITORIES_PER_PAGE)])[0]
            )
            paged_projects, page_number, page_count = paginate_repositories(
                projects, query.get("repo_page", ["1"])[0], page_size
            )
            activity_query = context["activity_query"]
            navigation_query = {**activity_query, "page_size": page_size}
            page_options = "".join(
                f"<option value='{number}' {'selected' if number == page_number else ''}>{number}</option>"
                for number in range(1, page_count + 1)
            )
            page_size_options = "".join(
                f"<option value='{size}' {'selected' if size == page_size else ''}>{size}</option>"
                for size in REPOSITORY_PAGE_SIZES
            )
            hidden_fields = "".join(
                f"<input type='hidden' name='{html.escape(str(key))}' value='{html.escape(str(value))}'>"
                for key, value in activity_query.items()
            )
            page_size_control = f"""
            <div class='table-controls'><form class='page-selector auto-submit-selector' method='get' action='/repositories'>
            {hidden_fields}<input type='hidden' name='repo_page' value='1'>
            <label for='repo_page_size'>Rows per page</label><select id='repo_page_size' name='page_size'>{page_size_options}</select>
            </form></div>"""
            previous_page = (
                f"<a class='button secondary' href='/repositories?{urllib.parse.urlencode({**navigation_query, 'repo_page': page_number - 1})}'>Previous</a>"
                if page_number > 1
                else ""
            )
            next_page = (
                f"<a class='button secondary' href='/repositories?{urllib.parse.urlencode({**navigation_query, 'repo_page': page_number + 1})}'>Next</a>"
                if page_number < page_count
                else ""
            )
            if total_repositories:
                first = (page_number - 1) * page_size + 1
                last = min(page_number * page_size, total_repositories)
                repository_range = f"Showing {first}–{last} of {total_repositories} repositories"
            else:
                repository_range = "No repositories to display"
            pagination = f"""
            <div class='pagination'><p class='sub'>{repository_range}</p><div class='actions'>{previous_page}
            <form class='page-selector auto-submit-selector' method='get' action='/repositories'>{hidden_fields}
            <input type='hidden' name='page_size' value='{page_size}'>
            <label for='repo_page'>Page</label><select id='repo_page' name='repo_page'>{page_options}</select>
            <span>of {page_count}</span></form>{next_page}</div></div>"""
            rows = []
            for project in paged_projects:
                project_path = html.escape(str(project["project_path"]))
                raw_url = str(project["web_url"])
                parsed_url = urllib.parse.urlparse(raw_url)
                project_name = (
                    f"<a href='{html.escape(raw_url)}' target='_blank' rel='noopener noreferrer'>{project_path}</a>"
                    if parsed_url.scheme == "https" and parsed_url.netloc
                    else project_path
                )
                project_status = str(project["last_check_status"])
                if project_status not in {"up", "down"}:
                    project_status = "unknown"
                status_title = (
                    str(project["last_check_error"])
                    if project_status == "down"
                    else (
                        "Latest GitLab repository check succeeded."
                        if project_status == "up"
                        else "Awaiting the first repository check."
                    )
                )
                latest_mr = (
                    str(project["latest_mr_at"])[:19].replace("T", " ") + " UTC"
                    if project["latest_mr_at"]
                    else "—"
                )
                mr_count = int(project["mr_count"])
                detail_query = urllib.parse.urlencode(
                    {"project_id": int(project["project_id"]), **activity_query}
                )
                mr_display = (
                    f"<a href='/repository?{detail_query}'>{mr_count}</a>"
                    if mr_count
                    else "0"
                )
                rows.append(
                    "<tr>"
                    f"<td>{project_name}</td><td>{int(project['project_id'])}</td>"
                    f"<td><span class='status {html.escape(project_status)}' title='{html.escape(status_title)}'>{html.escape(project_status.title())}</span></td>"
                    f"<td>{mr_display}</td><td>{finding_counts.get(int(project['project_id']), 0)}</td>"
                    f"<td>{html.escape(latest_mr)}</td></tr>"
                )
            table_rows = "".join(rows) or (
                "<tr><td class='empty-state' colspan='6'>No repositories discovered yet.</td></tr>"
            )
            scan_status = store.scan_status()
            deployment_time = scan_status.get("deployment_started_at", "")[:19].replace("T", " ")
            date_notice = (
                f"<p class='error'>{html.escape(str(context['date_error']))}</p>"
                if context["date_error"]
                else ""
            )
            body = f"""
            {date_notice}{self.vault_notice()}
            <section class='card'><div class='section-heading'><div><h2>Repositories and MRs</h2><p class='sub'>Visible repositories and MRs first discovered after {html.escape(deployment_time + ' UTC' if deployment_time else 'initialization')}. Current filter: {html.escape(str(context['filter_label']))}.</p></div></div>
            {self.filter_controls(context, '/repositories', {'page_size': page_size})}
            <div class='grid'><div class='metric'>Visible repositories<strong>{total_repositories}</strong></div><div class='metric'>Fetched MRs<strong>{fetched_mrs}</strong></div><div class='metric'>Findings<strong>{len(findings)}</strong></div></div>
            {page_size_control}<div class='table-wrap'><table><thead><tr><th>Repository</th><th>ID</th><th>Status</th><th>MRs</th><th>Findings</th><th>Latest MR</th></tr></thead><tbody>{table_rows}</tbody></table></div>{pagination}</section>
            <script src='/app.js' defer></script>"""
            self.application_response(
                "Repositories",
                "Repositories",
                "Monitor GitLab coverage, repository access, and merge-request activity.",
                body,
                user,
                "repositories",
            )

        def show_settings(self, query: dict[str, list[str]]) -> None:
            if store.user_count() == 0:
                self.redirect("/setup")
                return
            session = self.require_session()
            if session is None:
                return
            _, user = session
            saved = store.settings()
            try:
                settings = effective_runtime_settings(saved)
            except ReviewError:
                settings = effective_runtime_settings({})
            fields = "".join(
                form_field(item.key, settings[item.key]) for item in RUNTIME_SETTINGS
            )
            message = query.get("message", [""])[0]
            notice = (
                f"<p class='notice'>{html.escape(message)}</p>" if message else ""
            )
            active_credentials, _ = vault.snapshot()
            credentials_configured = store.credentials_configured()
            if credentials_configured and active_credentials is None:
                credential_panel = (
                    "<section class='card'><h2>Credential session expired</h2>"
                    "<p class='error'>Sign out and sign in again to unlock the encrypted credentials.</p></section>"
                )
            elif not credentials_configured and not vault.ready_for_updates():
                credential_panel = (
                    "<section class='card'><h2>Configure encrypted credentials</h2>"
                    "<p class='error'>Sign out and sign in again before saving credentials. "
                    "This prepares the in-memory encryption key without storing your password.</p></section>"
                )
            else:
                displayed_credentials = active_credentials or Credentials("", "", "")
                gitlab_url = displayed_credentials.gitlab_url or "https://gitlab.com"
                gitlab_group_path = displayed_credentials.gitlab_group_path
                gitlab_token_placeholder = (
                    "•••••••••••• (stored)"
                    if displayed_credentials.gitlab_token
                    else "Enter GitLab token"
                )
                anthropic_key_placeholder = (
                    "•••••••••••• (stored)"
                    if displayed_credentials.llm_api_key
                    else "Enter Anthropic API key"
                )
                openai_key_placeholder = (
                    "•••••••••••• (stored)"
                    if displayed_credentials.openai_api_key
                    else "Enter OpenAI API key"
                )
                copilot_key_placeholder = (
                    "•••••••••••• (stored)"
                    if displayed_credentials.copilot_api_key
                    else "Enter GitHub Copilot token"
                )
                anthropic_model = displayed_credentials.llm_model or LLM_DEFAULT_MODELS["anthropic"]
                openai_model = displayed_credentials.openai_model or LLM_DEFAULT_MODELS["openai"]
                copilot_anthropic_model = displayed_credentials.copilot_anthropic_model or "claude-sonnet-5"
                copilot_openai_model = displayed_credentials.copilot_openai_model or "gpt-5.4"
                credential_panel = f"""
                <section class='card'><h2>Configure or rotate encrypted credentials</h2>
                <p class='sub'>GitLab discovery can run independently. Anthropic-only reviews start as soon as the Anthropic key is stored; adding OpenAI and Copilot credentials enables four-model comparisons. Blank secret fields retain their encrypted values.</p>
                <form id='credential_form' method='post' action='/credentials'><input type='hidden' name='csrf' value='{html.escape(str(user['csrf_token']))}'><div class='form-grid'>
                <div class='field'><label for='rotate_gitlab_url'>GitLab URL</label><input id='rotate_gitlab_url' name='gitlab_url' type='url' value='{html.escape(gitlab_url)}' required></div>
                <div class='field'><label for='gitlab_group_path'>GitLab group path (optional)</label><input id='gitlab_group_path' name='gitlab_group_path' value='{html.escape(gitlab_group_path)}' placeholder='maas' maxlength='512'><small>Enter a namespace path such as maas or company/platform, not a URL. Subgroups are included automatically. Leave blank for user-wide discovery.</small></div>
                <div class='field'><label for='rotate_gitlab_token'>GitLab token</label><input id='rotate_gitlab_token' name='gitlab_token' type='password' autocomplete='off' placeholder='{html.escape(gitlab_token_placeholder)}'><small>Required the first time; leave blank later to keep the stored token.</small></div>
                <div class='field'><label for='anthropic_api_key'>Anthropic API key</label><input id='anthropic_api_key' name='anthropic_api_key' type='password' autocomplete='off' placeholder='{html.escape(anthropic_key_placeholder)}'><small>Used for the direct Anthropic comparison.</small></div>
                <div class='field'><label for='anthropic_model'>Direct Anthropic model</label><div class='inline-control'><input id='anthropic_model' name='anthropic_model' value='{html.escape(anthropic_model)}' maxlength='256'><button class='secondary fetch-models' type='button' data-provider='anthropic' data-key-field='anthropic_api_key' data-model-field='anthropic_model' data-picker='anthropic_models' data-status='anthropic_model_status'>Fetch models</button></div><select class='model-picker' id='anthropic_models' hidden><option value=''>Select a fetched model...</option></select><small class='model-status' id='anthropic_model_status'>Billed directly by Anthropic.</small></div>
                <div class='field'><label for='openai_api_key'>OpenAI API key</label><input id='openai_api_key' name='openai_api_key' type='password' autocomplete='off' placeholder='{html.escape(openai_key_placeholder)}'><small>Used for the direct OpenAI comparison.</small></div>
                <div class='field'><label for='openai_model'>Direct OpenAI model</label><div class='inline-control'><input id='openai_model' name='openai_model' value='{html.escape(openai_model)}' maxlength='256'><button class='secondary fetch-models' type='button' data-provider='openai' data-key-field='openai_api_key' data-model-field='openai_model' data-picker='openai_models' data-status='openai_model_status'>Fetch models</button></div><select class='model-picker' id='openai_models' hidden><option value=''>Select a fetched model...</option></select><small class='model-status' id='openai_model_status'>Billed directly by OpenAI.</small></div>
                <div class='field'><label for='copilot_api_key'>GitHub Copilot token</label><input id='copilot_api_key' name='copilot_api_key' type='password' autocomplete='off' placeholder='{html.escape(copilot_key_placeholder)}'><small>One GitHub token is used for both Copilot-hosted comparisons and must have Copilot access.</small></div>
                <div class='field'><label for='copilot_anthropic_model'>Copilot Anthropic model</label><div class='inline-control'><input id='copilot_anthropic_model' name='copilot_anthropic_model' value='{html.escape(copilot_anthropic_model)}' maxlength='256'><button class='secondary fetch-models' type='button' data-provider='copilot' data-key-field='copilot_api_key' data-model-field='copilot_anthropic_model' data-picker='copilot_anthropic_models' data-status='copilot_anthropic_status'>Fetch models</button></div><select class='model-picker' id='copilot_anthropic_models' hidden><option value=''>Select a fetched model...</option></select><small class='model-status' id='copilot_anthropic_status'>Select an Anthropic model enabled in Copilot policy.</small></div>
                <div class='field'><label for='copilot_openai_model'>Copilot OpenAI model</label><div class='inline-control'><input id='copilot_openai_model' name='copilot_openai_model' value='{html.escape(copilot_openai_model)}' maxlength='256'><button class='secondary fetch-models' type='button' data-provider='copilot' data-key-field='copilot_api_key' data-model-field='copilot_openai_model' data-picker='copilot_openai_models' data-status='copilot_openai_status'>Fetch models</button></div><select class='model-picker' id='copilot_openai_models' hidden><option value=''>Select a fetched model...</option></select><small class='model-status' id='copilot_openai_status'>Select an OpenAI model enabled in Copilot policy.</small></div>
                </div><div class='actions'><button type='submit'>Save encrypted credentials</button>
                <button class='secondary' type='submit' formaction='/credentials/test-gitlab'>Test GitLab access</button>
                <button class='secondary' type='submit' formaction='/credentials/test-llm'>Test configured model connection(s)</button></div>
                <p class='sub'>Tests do not save entered values. The model test sends one minimal request to each configured model and may incur API usage charges.</p></form></section>"""
            body = f"""
            {notice}<section class='card'><h2>Runtime settings</h2><p class='sub'>Saved in SQLite and applied automatically at the next polling cycle.</p>
            <form method='post' action='/settings'><input type='hidden' name='csrf' value='{html.escape(str(user['csrf_token']))}'><div class='form-grid'>{fields}</div><div class='actions'><button type='submit'>Save settings</button></div></form></section>
            {credential_panel}
            <section class='card danger-zone'><h2>Reset repository and MR data</h2>
            <p>Clear the repository inventory, MR revisions, reports, and findings from SQLite and start a new deployment period. Administrator accounts, encrypted credentials, runtime settings, and the current login are preserved.</p>
            <p class='error'><strong>This cannot be undone.</strong> Open MRs created before the reset time will not be imported again.</p>
            <form method='post' action='/reset-review-data'><input type='hidden' name='csrf' value='{html.escape(str(user['csrf_token']))}'>
            <div class='field'><label for='reset_confirmation'>Type RESET to confirm</label><input id='reset_confirmation' name='confirmation' autocomplete='off' pattern='RESET' required></div>
            <div class='actions'><button class='danger' type='submit'>Clear repositories and MRs</button></div></form></section>
            <script src='/app.js' defer></script>"""
            self.application_response(
                "Settings",
                "Settings",
                "Manage review behavior, GitLab access, and encrypted LLM credentials.",
                body,
                user,
                "settings",
            )

        def update_settings(self, form: dict[str, str]) -> None:
            session = self.require_session()
            if session is None:
                return
            _, user = session
            if not self.valid_csrf(form.get("csrf", ""), str(user["csrf_token"])):
                raise ReviewError("Invalid form token.")
            normalized = {
                setting.key: normalize_runtime_setting(setting, form.get(setting.key, ""))
                for setting in RUNTIME_SETTINGS
            }
            store.save_settings(normalized)
            message = "Settings saved. They will apply on the next polling cycle."
            self.redirect("/settings?message=" + urllib.parse.quote(message))

        def reset_review_data(self, form: dict[str, str]) -> None:
            session = self.require_session()
            if session is None:
                return
            _, user = session
            if not self.valid_csrf(form.get("csrf", ""), str(user["csrf_token"])):
                raise ReviewError("Invalid form token.")
            if form.get("confirmation", "") != "RESET":
                raise ReviewError(
                    "Type RESET exactly to confirm deletion of repository and MR data."
                )
            repositories, reviews, reset_at = store.reset_review_data()
            vault.notify_change()
            message = (
                f"Review data reset at {reset_at}: removed {repositories} repository "
                f"record(s) and {reviews} MR revision(s). Administrator accounts, "
                "credentials, and runtime settings were preserved."
            )
            self.redirect("/settings?message=" + urllib.parse.quote(message))

        def show_mr_diff(self, query: dict[str, list[str]]) -> None:
            if self.require_session() is None:
                return
            try:
                project_id = int(query.get("project_id", [""])[0])
                mr_iid = int(query.get("mr_iid", [""])[0])
            except ValueError:
                self.send_json(400, {"error": "Invalid MR reference."})
                return
            head_sha = query.get("sha", [""])[0].strip()
            if not head_sha or len(head_sha) > 128:
                self.send_json(400, {"error": "Invalid MR revision."})
                return
            revision = store.mr_revision(project_id, mr_iid, head_sha)
            if revision is None:
                self.send_json(404, {"error": "MR revision not found."})
                return
            stored_diff = str(revision["diff_content"] or "")
            if stored_diff:
                self.send_json(200, {"diff": stored_diff, "source": "stored"})
                return
            credentials, _ = vault.snapshot()
            if credentials is None:
                self.send_json(
                    503,
                    {"error": "Sign in again to unlock the GitLab credentials."},
                )
                return
            try:
                config = Config.from_credentials(
                    credentials.gitlab_url,
                    credentials.gitlab_token,
                    credentials.llm_api_key,
                    store.settings(),
                    llm_provider=credentials.llm_provider,
                    llm_api_url=credentials.llm_api_url,
                    llm_model=credentials.llm_model,
                    gitlab_group_path=credentials.gitlab_group_path,
                )
                client = GitLabClient(
                    config.gitlab_url,
                    config.gitlab_token,
                    config.gitlab_group_path,
                )
                diffs = client.get_merge_request_diffs(
                    str(revision["project_path"]), mr_iid
                )
                mr = client.get_merge_request(str(revision["project_path"]), mr_iid)
                diff_refs = mr.get("diff_refs")
                if not isinstance(diff_refs, Mapping):
                    diff_refs = {}
                current_sha = str(mr.get("sha") or diff_refs.get("head_sha") or "")
                if current_sha != head_sha:
                    self.send_json(
                        409,
                        {
                            "error": (
                                "A newer MR revision exists. Wait for the next discovery "
                                "cycle, then reload this page."
                            )
                        },
                    )
                    return
                rendered_diff = render_diffs(diffs, config) or (
                    "GitLab returned no changed lines for this MR revision."
                )
            except ReviewError as exc:
                self.send_json(502, {"error": str(exc)})
                return
            if not store.cache_mr_diff(project_id, mr_iid, head_sha, rendered_diff):
                self.send_json(404, {"error": "MR revision is no longer available."})
                return
            self.send_json(200, {"diff": rendered_diff, "source": "gitlab"})

        def show_mr_commits(self, query: dict[str, list[str]]) -> None:
            if self.require_session() is None:
                return
            try:
                project_id = int(query.get("project_id", [""])[0])
                mr_iid = int(query.get("mr_iid", [""])[0])
            except ValueError:
                self.send_json(400, {"error": "Invalid MR reference."})
                return
            head_sha = query.get("sha", [""])[0].strip()
            if not head_sha or len(head_sha) > 128:
                self.send_json(400, {"error": "Invalid MR revision."})
                return
            revision = store.mr_revision(project_id, mr_iid, head_sha)
            if revision is None:
                self.send_json(404, {"error": "MR revision not found."})
                return
            credentials, _ = vault.snapshot()
            if credentials is None:
                self.send_json(
                    503,
                    {"error": "Sign in again to unlock the GitLab credentials."},
                )
                return
            try:
                config = Config.from_credentials(
                    credentials.gitlab_url,
                    credentials.gitlab_token,
                    credentials.llm_api_key,
                    store.settings(),
                    llm_provider=credentials.llm_provider,
                    llm_api_url=credentials.llm_api_url,
                    llm_model=credentials.llm_model,
                    gitlab_group_path=credentials.gitlab_group_path,
                )
                client = GitLabClient(
                    config.gitlab_url,
                    config.gitlab_token,
                    config.gitlab_group_path,
                )
                mr = client.get_merge_request(str(revision["project_path"]), mr_iid)
                diff_refs = mr.get("diff_refs")
                if not isinstance(diff_refs, Mapping):
                    diff_refs = {}
                current_sha = str(mr.get("sha") or diff_refs.get("head_sha") or "")
                if current_sha != head_sha:
                    self.send_json(
                        409,
                        {
                            "error": (
                                "A newer MR revision exists. Reload after the next "
                                "discovery cycle to view its commit list."
                            )
                        },
                    )
                    return
                commits = client.get_merge_request_commits(
                    str(revision["project_path"]), mr_iid
                )
            except ReviewError as exc:
                self.send_json(502, {"error": str(exc)})
                return
            self.send_json(
                200,
                {
                    "commits": normalize_gitlab_commits(
                        commits, config.gitlab_url
                    )
                },
            )

        def show_repository(self, query: dict[str, list[str]]) -> None:
            session = self.require_session()
            if session is None:
                return
            _, user = session
            try:
                project_id = int(query.get("project_id", [""])[0])
            except ValueError:
                self.send_page(
                    400,
                    page(
                        "Invalid repository",
                        "<div class='card'><h1>Invalid repository reference</h1>"
                        "<a class='button secondary' href='/repositories'>Return</a></div>",
                    ),
                )
                return
            period = query.get("period", ["week"])[0]
            if period not in {"day", "week", "month"}:
                period = "week"
            start_date = query.get("start_date", [""])[0].strip()
            end_date = query.get("end_date", [""])[0].strip()
            try:
                projects, start, end = store.repository_activity(
                    period, start_date, end_date
                )
            except ReviewError as exc:
                self.send_page(
                    400,
                    page(
                        "Invalid date",
                        f"<div class='card'><h1>Invalid date</h1><p class='error'>{html.escape(str(exc))}</p>"
                        "<a class='button secondary' href='/repositories'>Return</a></div>",
                    ),
                )
                return
            project = next(
                (row for row in projects if int(row["project_id"]) == project_id),
                None,
            )
            if project is None:
                self.send_page(
                    404,
                    page(
                        "Repository not found",
                        "<div class='card'><h1>Repository not found</h1>"
                        "<a class='button secondary' href='/repositories'>Return</a></div>",
                    ),
                )
                return
            selected_status = query.get("manual_status", ["all"])[0].lower()
            if selected_status not in MANUAL_REVIEW_FILTERS:
                selected_status = "all"
            manual_reviews = store.manual_review_map()
            repository_rows = store.repository_mrs(project_id, start, end)
            row_statuses = {
                (int(row["mr_iid"]), str(row["head_sha"])): manual_review_status_for_mr(
                    int(row["project_id"]),
                    int(row["mr_iid"]),
                    str(row["head_sha"]),
                    str(row["report_content"] or ""),
                    manual_reviews,
                )
                for row in repository_rows
            }
            status_counts = {
                status: sum(1 for value in row_statuses.values() if value == status)
                for status in ("open", "in_progress", "done")
            }
            rows = []
            for index, row in enumerate(repository_rows):
                manual_status = row_statuses[(int(row["mr_iid"]), str(row["head_sha"]))]
                if selected_status != "all" and manual_status != selected_status:
                    continue
                params = urllib.parse.urlencode(
                    {
                        "project_id": row["project_id"],
                        "mr_iid": row["mr_iid"],
                        "sha": row["head_sha"],
                    }
                )
                report_link = (
                    f"<a href='/report?{params}'>View report</a>"
                    if row["report_content"] or row["report_path"]
                    else "—"
                )
                detail_id = f"repository-mr-{index}"
                diff_query = urllib.parse.urlencode(
                    {
                        "project_id": row["project_id"],
                        "mr_iid": row["mr_iid"],
                        "sha": row["head_sha"],
                    }
                )
                stored_diff = str(row["diff_content"] or "")
                diff_display = (
                    render_diff_html(stored_diff)
                    if stored_diff
                    else (
                        "<pre class='diff-view' data-lazy-diff data-loaded='false'>"
                        "Select this row to load the bounded diff from GitLab.</pre>"
                    )
                )
                project_url = str(project["web_url"] or "")
                parsed_project_url = urllib.parse.urlparse(project_url)
                mr_url = (
                    project_url.rstrip("/")
                    + f"/-/merge_requests/{int(row['mr_iid'])}"
                    if parsed_project_url.scheme == "https"
                    and parsed_project_url.netloc
                    else ""
                )
                gitlab_link = (
                    f"<a class='button secondary' href='{html.escape(mr_url)}' target='_blank' rel='noopener noreferrer'>Open in GitLab</a>"
                    if mr_url
                    else ""
                )
                commit_url = (
                    project_url.rstrip("/")
                    + "/-/commit/"
                    + urllib.parse.quote(str(row["head_sha"]), safe="")
                    if parsed_project_url.scheme == "https"
                    and parsed_project_url.netloc
                    else ""
                )
                latest_commit_display = (
                    f"<a href='{html.escape(commit_url)}' target='_blank' rel='noopener noreferrer'><code>{html.escape(str(row['head_sha'])[:12])}</code></a>"
                    if commit_url
                    else f"<code>{html.escape(str(row['head_sha'])[:12])}</code>"
                )
                commit_summary = inline_commit_summary(
                    int(row["project_id"]),
                    int(row["mr_iid"]),
                    str(row["head_sha"]),
                )
                mr_decision = manual_reviews.get(
                    (
                        int(row["project_id"]),
                        int(row["mr_iid"]),
                        str(row["head_sha"]),
                        MR_MANUAL_REVIEW_KEY,
                    )
                )
                action = manual_review_button(
                    project_id=int(row["project_id"]),
                    mr_iid=int(row["mr_iid"]),
                    head_sha=str(row["head_sha"]),
                    item_key=MR_MANUAL_REVIEW_KEY,
                    workflow_status=manual_status,
                    resolution=str(mr_decision["resolution"] or "") if mr_decision else "",
                    severity=str(mr_decision["severity"] or "") if mr_decision else "",
                    comments=str(mr_decision["comments"] or "") if mr_decision else "",
                    return_to=self.path,
                )
                rows.append(
                    f"<tr class='expandable-row' data-details-id='{detail_id}' "
                    f"data-diff-url='/mr-diff?{html.escape(diff_query)}' "
                    "data-open-label='View diff' data-close-label='Hide diff' "
                    "tabindex='0' role='button' aria-expanded='false'>"
                    f"<td>!{int(row['mr_iid'])}</td>"
                    f"<td>{latest_commit_display}</td>"
                    f"<td class='status {html.escape(str(row['status']))}'>{html.escape(str(row['status']))}</td>"
                    f"<td>{html.escape(str(row['mr_created_at'])[:19].replace('T', ' '))} UTC</td>"
                    f"<td>{report_link}</td>"
                    "<td><button class='row-toggle secondary' type='button'>View diff</button></td>"
                    f"<td>{action}</td></tr>"
                    f"<tr class='expanded-review' id='{detail_id}' hidden><td colspan='7'>"
                    "<div class='review-details'><section class='review-section'>"
                    f"<h3>MR !{int(row['mr_iid'])} reviewed code diff</h3>{commit_summary}{diff_display}"
                    f"</section><div class='review-meta'>{gitlab_link}</div></div></td></tr>"
                )
            table_rows = "".join(rows) or (
                "<tr><td class='empty-state' colspan='7'>No MRs match this date range and manual-review status.</td></tr>"
            )
            filter_label = (
                (
                    f"{start_date} UTC"
                    if start_date == end_date
                    else f"{start_date} to {end_date} UTC"
                )
                if start_date and end_date
                else {"day": "last 24 hours", "week": "last 7 days", "month": "last 30 days"}[period]
            )
            back_query = urllib.parse.urlencode(
                {"start_date": start_date, "end_date": end_date}
                if start_date and end_date
                else {"period": period}
            )
            date_query = (
                {"start_date": start_date, "end_date": end_date}
                if start_date and end_date
                else {"period": period}
            )
            status_filter_links = "".join(
                f"<a class='button {'primary' if value == selected_status else 'secondary'}' "
                f"href='/repository?{urllib.parse.urlencode({'project_id': project_id, **date_query, 'manual_status': value})}'>{label} ({len(repository_rows) if value == 'all' else status_counts[value]})</a>"
                for value, label in (
                    ("all", "All statuses"),
                    ("open", "Open"),
                    ("in_progress", "In Progress"),
                    ("done", "Done"),
                )
            )
            body = f"""
            <section class='card'><div class='section-heading'><div><h2>Merge requests</h2><p class='sub'>Select a date range, then select an MR row to inspect its bounded code diff.</p></div></div>
            {self.filter_controls({'period': period, 'start_date': start_date, 'end_date': end_date}, '/repository', {'project_id': project_id, 'manual_status': selected_status})}
            <nav class='severity-filter' aria-label='Filter merge requests by manual-review status'>{status_filter_links}</nav>
            <div class='table-wrap'><table><thead><tr>
            <th>MR</th><th>Latest commit</th><th>AI review</th><th>MR created</th><th>Report</th><th>Code diff</th><th>Manual review</th>
            </tr></thead><tbody>{table_rows}</tbody></table></div></section>
            {manual_review_dialog(str(user['csrf_token']))}<script src='/app.js' defer></script>"""
            self.application_response(
                "Repository MRs",
                str(project["project_path"]),
                f"Latest revision of each MR in {filter_label}.",
                body,
                user,
                "repositories",
                f"<a class='button secondary' href='/repositories?{back_query}'>Back to repositories</a>",
            )

        def show_report(self, query: dict[str, list[str]]) -> None:
            session = self.require_session()
            if session is None:
                return
            _, user = session
            try:
                project_id = int(query.get("project_id", [""])[0])
                mr_iid = int(query.get("mr_iid", [""])[0])
                head_sha = query.get("sha", [""])[0]
            except ValueError:
                self.send_page(400, page("Invalid report", "<div class='card'><h1>Invalid report reference</h1></div>"))
                return
            row = store.report(project_id, mr_iid, head_sha)
            selected_profile = query.get("profile", [""])[0]
            comparison_content = ""
            if row is not None and selected_profile in COMPARISON_PROFILES:
                try:
                    comparison = json.loads(str(row["comparison_json"] or "{}"))
                except (TypeError, json.JSONDecodeError):
                    comparison = {}
                result = comparison.get(selected_profile) if isinstance(comparison, dict) else None
                if isinstance(result, dict):
                    comparison_content = str(result.get("report_content", ""))
            if row is None or not (
                comparison_content or row["report_content"] or row["report_path"]
            ):
                self.send_page(404, page("Report not found", "<div class='card'><h1>Report not found</h1></div>"))
                return
            if comparison_content:
                content = comparison_content[:1_000_000]
            elif row["report_content"]:
                content = str(row["report_content"])[:1_000_000]
            else:
                path = Path(str(row["report_path"])).resolve()
                root = report_dir.resolve()
                try:
                    path.relative_to(root)
                except ValueError:
                    self.send_page(403, page("Report unavailable", "<div class='card'><h1>Report path rejected</h1></div>"))
                    return
                try:
                    content = path.read_text(encoding="utf-8")[:1_000_000]
                except OSError:
                    self.send_page(404, page("Report not found", "<div class='card'><h1>Report file not found</h1></div>"))
                    return
            body = f"<section class='card'><pre>{html.escape(content)}</pre></section>"
            self.application_response(
                "Security report",
                "Security report",
                f"{row['project_path']} !{int(row['mr_iid'])} · {str(row['head_sha'])[:12]}",
                body,
                user,
                "dashboard",
                "<a class='button secondary' href='/'>Back to dashboard</a>",
            )

    return Handler


def run_web(managed: bool = False) -> int:
    state_db = Path(os.environ.get("STATE_DB", "/data/state/reviews.sqlite3"))
    report_dir = Path(os.environ.get("REPORT_DIR", "/data/reports"))
    host = os.environ.get("WEB_HOST", "0.0.0.0")
    port = int(os.environ.get("WEB_PORT", "8080"))
    secure_cookies = os.environ.get("WEB_SECURE_COOKIES", "false").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    try:
        store = WebStore(state_db)
    except ReviewError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr, flush=True)
        return 1
    invalidated_sessions = store.delete_all_sessions()
    vault = MemoryVault()
    if managed:
        from .service import run_managed_poll

        threading.Thread(
            target=run_managed_poll,
            args=(state_db, vault, store.operation_lock),
            daemon=True,
        ).start()
    server = ThreadingHTTPServer(
        (host, port), handler_factory(store, report_dir, secure_cookies, vault)
    )
    print(f"Design Review web console listening on {host}:{port}", flush=True)
    if invalidated_sessions:
        print(
            f"Invalidated {invalidated_sessions} existing web session(s) after restart.",
            flush=True,
        )
    if store.user_count() == 0:
        print("Open /setup to create the first administrator account.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
