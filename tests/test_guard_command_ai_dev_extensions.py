"""Structured ai-dev command extension tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    risk_classes_for_command_action,
)
from codex_plugin_scanner.guard.runtime.command_model import parse_shell_command
from codex_plugin_scanner.guard.runtime.extension_contribution import load_contribution_payloads
from codex_plugin_scanner.guard.runtime.extension_trust import ids_for_class
from tests.command_extension_contracts import (
    assert_safe_command_cases,
)

_INSTALL_FORCE_ACTION = "ai-dev forced integration config overwrite command"
_INDEX_DAEMON_ACTION = "ai-dev index daemon lifecycle command"
_AGENT_MUTATION_ACTION = "ai-dev agent coordination mutation command"

AI_DEV_REVIEW_CASES: tuple[tuple[str, str, str], ...] = (
    # --- Integrations install --force ---
    (
        "ai-dev integrations install --force",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install -f",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install --forc",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install --for",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install --fo",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install --f",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev --verbose integrations install --force",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install claude --force",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install $FORCE_FLAG",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        'ai-dev integrations install "$FORCE_FLAG"',
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install ${FORCE_FLAG}",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install $(echo --force)",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    (
        "ai-dev integrations install `echo --force`",
        _INSTALL_FORCE_ACTION,
        "command.ai-dev.integrations-install-force",
    ),
    # --- Index daemon start ---
    (
        "ai-dev index daemon start",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        "ai-dev index daemon",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        "ai-dev --json index daemon start",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        "ai-dev index daemon start --foreground",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        "ai-dev index daemon start --workers 4",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        "ai-dev index daemon $ACTION",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        'ai-dev index daemon "$ACTION"',
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        "ai-dev index daemon ${ACTION}",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        "ai-dev index daemon $(echo start)",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    (
        "ai-dev index daemon `echo start`",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-start",
    ),
    # --- Index daemon stop ---
    (
        "ai-dev index daemon stop",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-stop",
    ),
    (
        "ai-dev index daemon stop --force",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-stop",
    ),
    (
        "ai-dev index daemon stop -f",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-stop",
    ),
    (
        "ai-dev index daemon stop --timeout 30",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-stop",
    ),
    (
        "ai-dev index daemon stop -t 30",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-stop",
    ),
    (
        "ai-dev --quiet index daemon stop",
        _INDEX_DAEMON_ACTION,
        "command.ai-dev.index-daemon-stop",
    ),
    # --- Agents claim ---
    (
        "ai-dev agents claim task-123",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-claim",
    ),
    (
        "ai-dev agents claim task-123 --agent bot-1",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-claim",
    ),
    (
        "ai-dev agents --agent bot-1 claim task-123",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-claim",
    ),
    (
        "ai-dev agents claim 'task with spaces'",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-claim",
    ),
    (
        'ai-dev agents claim "task with spaces"',
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-claim",
    ),
    (
        "ai-dev agents claim $TASK_ID",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-claim",
    ),
    # --- Agents release ---
    (
        "ai-dev agents release task-123",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-release",
    ),
    (
        "ai-dev agents release task-123 --agent bot-1",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-release",
    ),
    (
        "ai-dev agents release task-123 --reason 'blocked on external api'",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-release",
    ),
    (
        'ai-dev agents release task-123 --reason "blocked on external api"',
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-release",
    ),
    (
        "ai-dev agents release 'task with spaces'",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-release",
    ),
    (
        "ai-dev agents release $TASK_ID",
        _AGENT_MUTATION_ACTION,
        "command.ai-dev.agents-release",
    ),
)


AI_DEV_WRAPPER_REVIEW_COMMANDS: tuple[tuple[str, str], ...] = (
    # Executable suffixes
    ("ai-dev.exe integrations install --force", "command.ai-dev.integrations-install-force"),
    ("ai-dev.exe index daemon start", "command.ai-dev.index-daemon-start"),
    ("ai-dev.exe index daemon stop", "command.ai-dev.index-daemon-stop"),
    ("ai-dev.exe agents claim task-123", "command.ai-dev.agents-claim"),
    ("ai-dev.exe agents release task-123", "command.ai-dev.agents-release"),
    # Python launcher variants (ai_dev and ai_dev_tools)
    ("python -m ai_dev integrations install --force", "command.ai-dev.integrations-install-force"),
    ("python -m ai_dev_tools integrations install --force", "command.ai-dev.integrations-install-force"),
    ("python3 -m ai_dev integrations install --force", "command.ai-dev.integrations-install-force"),
    ("python3 -m ai_dev_tools integrations install --force", "command.ai-dev.integrations-install-force"),
    ("py -m ai_dev integrations install --force", "command.ai-dev.integrations-install-force"),
    ("py -m ai_dev_tools integrations install --force", "command.ai-dev.integrations-install-force"),
    ("python -m ai_dev index daemon start", "command.ai-dev.index-daemon-start"),
    ("python3 -m ai_dev index daemon stop", "command.ai-dev.index-daemon-stop"),
    ("py -m ai_dev agents claim task-123", "command.ai-dev.agents-claim"),
    ("python -m ai_dev agents release task-123", "command.ai-dev.agents-release"),
    # Common wrappers: sudo, exec, env, xargs
    ("sudo ai-dev integrations install --force", "command.ai-dev.integrations-install-force"),
    ("exec ai-dev integrations install --force", "command.ai-dev.integrations-install-force"),
    ("env FOO=bar ai-dev integrations install --force", "command.ai-dev.integrations-install-force"),
    ("xargs ai-dev integrations install --force", "command.ai-dev.integrations-install-force"),
    ("xargs -n 1 ai-dev integrations install --force", "command.ai-dev.integrations-install-force"),
    ("xargs -n 1 python -m ai_dev integrations install --force", "command.ai-dev.integrations-install-force"),
    ("sudo ai-dev index daemon start", "command.ai-dev.index-daemon-start"),
    ("exec ai-dev index daemon stop", "command.ai-dev.index-daemon-stop"),
    ("sudo ai-dev agents claim task-123", "command.ai-dev.agents-claim"),
    ("exec ai-dev agents release task-123", "command.ai-dev.agents-release"),
)


AI_DEV_PIPELINE_AND_CHAINED_CASES: tuple[tuple[str, str], ...] = (
    ("echo yes | ai-dev integrations install --force", "command.ai-dev.integrations-install-force"),
    ("ai-dev index daemon status && ai-dev index daemon start", "command.ai-dev.index-daemon-start"),
    ("ai-dev index daemon stop; ai-dev index daemon start", "command.ai-dev.index-daemon-stop"),
    ("ai-dev index daemon stop; ai-dev index daemon start", "command.ai-dev.index-daemon-start"),
    ("ai-dev agents list || ai-dev agents claim task-123", "command.ai-dev.agents-claim"),
    ("ai-dev agents claim task-1; ai-dev agents release task-2", "command.ai-dev.agents-claim"),
    ("ai-dev agents claim task-1; ai-dev agents release task-2", "command.ai-dev.agents-release"),
)


AI_DEV_SAFE_COMMANDS: tuple[str, ...] = (
    # integrations without --force
    "ai-dev integrations install",
    "ai-dev integrations install claude",
    "ai-dev integrations install --help",
    "ai-dev integrations list",
    # index daemon read/status queries
    "ai-dev index daemon status",
    "ai-dev index daemon status --json",
    "ai-dev index daemon status -v",
    "ai-dev index daemon --help",
    "ai-dev index query 'test search'",
    "ai-dev index stats",
    # agents read queries
    "ai-dev agents list",
    "ai-dev agents show task-123",
    "ai-dev agents status",
    "ai-dev agents --help",
    "ai-dev agents claim --help",
    "ai-dev agents release --help",
    # global help & version
    "ai-dev --help",
    "ai-dev -h",
    "ai-dev --version",
    "ai-dev -V",
    # unrelated commands & strings
    "grep 'ai-dev integrations install --force' docs.md",
    "echo ai-dev integrations install --force",
    "cat ai-dev.log",
)


def test_ai_dev_review_cases_match_rules(tmp_path: Path) -> None:
    """All v1 mutation commands match their designated rule in the built-in catalog."""
    for command, _action_class, expected_rule in AI_DEV_REVIEW_CASES:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.ai-dev"}
        assert expected_rule in matched, f"Expected {expected_rule} for {command!r}, got {matched!r}"


def test_ai_dev_wrapper_and_launcher_invocations_match_rules(tmp_path: Path) -> None:
    """Indirect wrappers and launchers properly attribute to ai-dev rules."""
    for command, expected_rule in AI_DEV_WRAPPER_REVIEW_COMMANDS:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.ai-dev"}
        assert expected_rule in matched, f"Expected {expected_rule} for {command!r}, got {matched!r}"


def test_ai_dev_pipeline_and_chained_commands_match_rules(tmp_path: Path) -> None:
    """Pipelines, semicolons, and boolean chains evaluate individual commands."""
    for command, expected_rule in AI_DEV_PIPELINE_AND_CHAINED_CASES:
        observations = BUILT_IN_COMMAND_EXTENSION_REGISTRY.observations(
            parse_shell_command(command, cwd=tmp_path, home_dir=tmp_path)
        )
        matched = {item.rule.rule_id for item in observations if item.extension.extension_id == "command.ai-dev"}
        assert expected_rule in matched, f"Expected {expected_rule} for {command!r}, got {matched!r}"


def test_ai_dev_safe_commands_remain_safe(tmp_path: Path) -> None:
    """Read-only and benign commands remain unflagged."""
    assert_safe_command_cases(AI_DEV_SAFE_COMMANDS, tmp_path)


def test_ai_dev_rules_stay_inert_until_enabled(tmp_path: Path) -> None:
    """Opt-in extension remains inert in baseline evaluation when not activated."""
    for command, _action_class, rule_id in AI_DEV_REVIEW_CASES:
        evaluation = evaluate_command(command, cwd=tmp_path, home_dir=tmp_path)
        assert evaluation.controlling_rule_id != rule_id
        assert all(item.extension.extension_id != "command.ai-dev" for item in evaluation.extension_observations)


def test_ai_dev_extension_metadata_and_risk_classes() -> None:
    """Extension metadata, references, and risk mappings conform to spec."""
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get("command.ai-dev")
    assert extension is not None
    assert extension.extension_id == "command.ai-dev"
    assert extension.reference_urls
    assert all(url.startswith("https://") for url in extension.reference_urls)

    assert "command.ai-dev" in ids_for_class("external")
    payload = next(item for item in load_contribution_payloads() if item.get("id") == "command.ai-dev")
    assert payload["activation"] == "opt-in"
    assert payload["trustClass"] == "external"

    assert risk_classes_for_command_action(_INSTALL_FORCE_ACTION) == ("destructive_shell",)
    assert risk_classes_for_command_action(_INDEX_DAEMON_ACTION) == ("destructive_shell", "execution")
    assert risk_classes_for_command_action(_AGENT_MUTATION_ACTION) == ("destructive_shell",)
