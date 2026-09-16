"""Structured rules and metadata for the ai-dev command safety extension."""

from __future__ import annotations

from dataclasses import dataclass

from .command_extension_matchers import executable_matcher, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_rules import (
    AnyMatcher,
    CommandSafetyRule,
    _after_leading_options,
    _segment_matches_executable,
    _without_options,
)
from .command_structured_matchers import leading_flags_and_operands

# Flag surface verified against ai-dev-cli-tools 1.3.0 (cli.py):
# - `integrations install [client]` accepts --force (store_true, no -f alias in argparse definition).
# - `index daemon [daemon_action]` accepts start, status, stop, foreground (defaults to start).
#   Accepts --poll, --max-updates, --idle-timeout options with values.
# - `agents claim` accepts task_id positional, --agent (required), --lease-seconds.
# - `agents release` accepts task_id positional, --agent (required).
# - Global options: --project <path> (options_with_values), --json, --quiet (flags).
#   These may precede, be interspersed within, or follow subcommands.
# - Module invocation (`python/-m ai_dev_tools ...`) enforces the module name as
#   literal subcommand tokens because option-value tracking does not retain `-m` values.
#
# Conservative matching covers:
# - Standard launcher variants: ai-dev, python -m ai_dev_tools, python3 -m ai_dev_tools, py -m ai_dev_tools
# - Shell wrappers: exec ai-dev ..., xargs ai-dev ...
# - Flag abbreviations: Python argparse accepts unambiguous prefixes (--f, --fo, ..., --force)
# - Unresolved shell expansions ($VAR, ${VAR}, $(...), backticks) that may supply --force
# - Fail-secure option parsing: unknown options prevent unsafe dry-run / preview bypasses

_AI_DEV_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    ("ai-dev",),
    ("python", "-m", "ai_dev_tools"),
    ("python3", "-m", "ai_dev_tools"),
    ("py", "-m", "ai_dev_tools"),
    ("exec", "ai-dev"),
    ("exec", "python", "-m", "ai_dev_tools"),
    ("exec", "python3", "-m", "ai_dev_tools"),
    ("exec", "py", "-m", "ai_dev_tools"),
    ("xargs", "ai-dev"),
    ("xargs", "python", "-m", "ai_dev_tools"),
    ("xargs", "python3", "-m", "ai_dev_tools"),
    ("xargs", "py", "-m", "ai_dev_tools"),
)
_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})
_AI_DEV_GLOBAL_OPTIONS_WITH_VALUES = frozenset({"--project"})
_AI_DEV_GLOBAL_FLAGS = frozenset({"--json", "--quiet"})

# argparse resolves any unambiguous long-option prefix, so every prefix of
# --force is the destructive flag itself.
_FORCE_FLAGS: tuple[str, ...] = (
    "--force",
    "--forc",
    "--for",
    "--fo",
    "--f",
)
_EXPANSION_MARKERS: frozenset[str] = frozenset({"$", "`"})

_AI_DEV_INTEGRATIONS_INSTALL_FORCE = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "integrations",
            "install",
            required_flags=frozenset({force_flag}),
            global_options_with_values=_AI_DEV_GLOBAL_OPTIONS_WITH_VALUES,
            global_flags=_AI_DEV_GLOBAL_FLAGS,
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _AI_DEV_LAUNCHERS
        for force_flag in _FORCE_FLAGS
    )
)


@dataclass(frozen=True, slots=True)
class AiDevUnresolvedExpansionMatcher:
    """Match ai-dev integrations install commands whose flags may be supplied by shell expansion.

    A `$VAR`, `${VAR}`, `$(...)`, or backtick token can expand to `--force` at
    execution time, so its presence in an `integrations install` invocation means the
    destructive flag cannot be proven absent.
    """

    subcommands: tuple[str, ...] = ("integrations", "install")
    launchers: tuple[tuple[str, ...], ...] = _AI_DEV_LAUNCHERS
    leading_options_with_values: frozenset[str] = _WRAPPER_LEADING_OPTIONS_WITH_VALUES
    global_options_with_values: frozenset[str] = _AI_DEV_GLOBAL_OPTIONS_WITH_VALUES
    global_flags: frozenset[str] = _AI_DEV_GLOBAL_FLAGS
    expansion_markers: frozenset[str] = _EXPANSION_MARKERS

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if segment.executable is None:
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            for launcher in self.launchers:
                if not _segment_matches_executable(segment, frozenset({launcher[0]})):
                    continue
                candidate_arguments = lowered_arguments
                if launcher[0] in ("exec", "xargs"):
                    candidate_arguments = _after_leading_options(
                        candidate_arguments,
                        self.leading_options_with_values,
                        frozenset(),
                    )
                candidate_arguments = _without_options(
                    candidate_arguments,
                    self.global_options_with_values,
                    self.global_flags,
                )
                prefix = (*launcher[1:], *self.subcommands)
                if candidate_arguments[: len(prefix)] != prefix:
                    continue
                remaining_arguments = candidate_arguments[len(prefix) :]
                if any(
                    any(marker in argument for marker in self.expansion_markers) for argument in remaining_arguments
                ):
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched ai-dev arguments that may expand to destructive flags.",
                        )
                    )
                break
        return tuple(evidence)


_AI_DEV_INTEGRATIONS_INSTALL_FORCE_WITH_EXPANSIONS = AnyMatcher(
    matchers=(*_AI_DEV_INTEGRATIONS_INSTALL_FORCE.matchers, AiDevUnresolvedExpansionMatcher()),
)

_AI_DEV_INDEX_DAEMON_START_EXPLICIT = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "index",
            "daemon",
            "start",
            global_options_with_values=_AI_DEV_GLOBAL_OPTIONS_WITH_VALUES,
            global_flags=_AI_DEV_GLOBAL_FLAGS,
            options_with_values=frozenset({"--poll", "--max-updates", "--idle-timeout"}),
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _AI_DEV_LAUNCHERS
    )
)


@dataclass(frozen=True, slots=True)
class AiDevIndexDaemonDefaultMatcher:
    """Match `ai-dev index daemon` when no explicit action operand is provided.

    In ai-dev CLI, bare `ai-dev index daemon` defaults to starting the daemon
    unless a known action operand (status, stop, foreground) or help flag is given.
    """

    subcommands: tuple[str, ...] = ("index", "daemon")
    launchers: tuple[tuple[str, ...], ...] = _AI_DEV_LAUNCHERS
    leading_options_with_values: frozenset[str] = _WRAPPER_LEADING_OPTIONS_WITH_VALUES
    global_options_with_values: frozenset[str] = _AI_DEV_GLOBAL_OPTIONS_WITH_VALUES
    global_flags: frozenset[str] = _AI_DEV_GLOBAL_FLAGS
    daemon_options_with_values: frozenset[str] = frozenset({"--poll", "--max-updates", "--idle-timeout"})

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if segment.executable is None:
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            for launcher in self.launchers:
                if not _segment_matches_executable(segment, frozenset({launcher[0]})):
                    continue
                candidate_arguments = lowered_arguments
                if launcher[0] in ("exec", "xargs"):
                    candidate_arguments = _after_leading_options(
                        candidate_arguments,
                        self.leading_options_with_values,
                        frozenset(),
                    )
                candidate_arguments = _without_options(
                    candidate_arguments,
                    self.global_options_with_values,
                    self.global_flags,
                )
                prefix = (*launcher[1:], *self.subcommands)
                if candidate_arguments[: len(prefix)] != prefix:
                    continue
                remaining_arguments = candidate_arguments[len(prefix) :]
                flags, operands = leading_flags_and_operands(
                    remaining_arguments,
                    options_with_values=self.daemon_options_with_values,
                )
                if {"-h", "--help"}.intersection(flags):
                    break
                if not operands:
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched ai-dev default background index daemon invocation.",
                        )
                    )
                break
        return tuple(evidence)


@dataclass(frozen=True, slots=True)
class AiDevIndexDaemonExpansionMatcher:
    """Match `ai-dev index daemon <expansion>` where the action operand is a shell variable.

    A `$VAR`, `${VAR}`, `$(...)`, or backtick token in the daemon-action position
    may expand to `start` or `stop` at execution time, so its presence means the
    intended action cannot be proven safe.
    """

    subcommands: tuple[str, ...] = ("index", "daemon")
    launchers: tuple[tuple[str, ...], ...] = _AI_DEV_LAUNCHERS
    leading_options_with_values: frozenset[str] = _WRAPPER_LEADING_OPTIONS_WITH_VALUES
    global_options_with_values: frozenset[str] = _AI_DEV_GLOBAL_OPTIONS_WITH_VALUES
    global_flags: frozenset[str] = _AI_DEV_GLOBAL_FLAGS
    daemon_options_with_values: frozenset[str] = frozenset({"--poll", "--max-updates", "--idle-timeout"})
    expansion_markers: frozenset[str] = _EXPANSION_MARKERS

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if segment.executable is None:
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            for launcher in self.launchers:
                if not _segment_matches_executable(segment, frozenset({launcher[0]})):
                    continue
                candidate_arguments = lowered_arguments
                if launcher[0] in ("exec", "xargs"):
                    candidate_arguments = _after_leading_options(
                        candidate_arguments,
                        self.leading_options_with_values,
                        frozenset(),
                    )
                candidate_arguments = _without_options(
                    candidate_arguments,
                    self.global_options_with_values,
                    self.global_flags,
                )
                prefix = (*launcher[1:], *self.subcommands)
                if candidate_arguments[: len(prefix)] != prefix:
                    continue
                remaining_arguments = candidate_arguments[len(prefix) :]
                flags, operands = leading_flags_and_operands(
                    remaining_arguments,
                    options_with_values=self.daemon_options_with_values,
                )
                if {"-h", "--help"}.intersection(flags):
                    break
                if operands and any(
                    any(marker in operand for marker in self.expansion_markers) for operand in operands
                ):
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched ai-dev index daemon with unresolved expansion in action position.",
                        )
                    )
                break
        return tuple(evidence)


_AI_DEV_INDEX_DAEMON_START = AnyMatcher(
    matchers=(
        *_AI_DEV_INDEX_DAEMON_START_EXPLICIT.matchers,
        AiDevIndexDaemonDefaultMatcher(),
        AiDevIndexDaemonExpansionMatcher(),
    )
)

_AI_DEV_INDEX_DAEMON_STOP = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "index",
            "daemon",
            "stop",
            global_options_with_values=_AI_DEV_GLOBAL_OPTIONS_WITH_VALUES,
            global_flags=_AI_DEV_GLOBAL_FLAGS,
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _AI_DEV_LAUNCHERS
    )
)

_AI_DEV_AGENTS_CLAIM = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "agents",
            "claim",
            global_options_with_values=_AI_DEV_GLOBAL_OPTIONS_WITH_VALUES,
            global_flags=_AI_DEV_GLOBAL_FLAGS,
            options_with_values=frozenset({"--agent", "--lease-seconds"}),
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _AI_DEV_LAUNCHERS
    )
)

_AI_DEV_AGENTS_RELEASE = AnyMatcher(
    matchers=tuple(
        executable_matcher(
            *launcher,
            "agents",
            "release",
            global_options_with_values=_AI_DEV_GLOBAL_OPTIONS_WITH_VALUES,
            global_flags=_AI_DEV_GLOBAL_FLAGS,
            options_with_values=frozenset({"--agent"}),
            allow_leading_options=launcher[0] in ("exec", "xargs"),
            leading_options_with_values=(
                _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in ("exec", "xargs") else frozenset()
            ),
            fail_secure_unknown_options=True,
        )
        for launcher in _AI_DEV_LAUNCHERS
    )
)

AI_DEV_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.ai-dev.integrations-install-force",
        title="ai-dev forced integration overwrite",
        description=(
            "Identifies `ai-dev integrations install --force`, which overwrites or "
            "mutates existing IDE and agent configuration files (.codex/config.toml, "
            ".cursor/mcp.json, .gemini/settings.json, .mcp.json). Invocations carrying "
            "unresolved shell expansions are reviewed because they cannot prove --force "
            "absent."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("ai-dev forced integration config overwrite command",),
        safer_alternatives=(
            "Run ai-dev integrations install without --force to preserve existing IDE configurations.",
            "Confirm existing .codex, .cursor, .gemini, or .mcp.json files are backed up before forcing.",
        ),
        matcher=_AI_DEV_INTEGRATIONS_INSTALL_FORCE_WITH_EXPANSIONS,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _AI_DEV_INTEGRATIONS_INSTALL_FORCE,
                variant_id="help",
                title="ai-dev integrations install help",
                flag="--help",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.ai-dev.index-daemon-start",
        title="ai-dev index daemon background start",
        description=(
            "Identifies `ai-dev index daemon start` invocations that spawn a detached "
            "background watcher process and open a localhost TCP control socket."
        ),
        severity="medium",
        risk_classes=("execution",),
        action_classes=("ai-dev index daemon lifecycle command",),
        safer_alternatives=(
            "Check running daemon state with ai-dev index daemon status before starting.",
            "Run a one-shot repository index with ai-dev index update instead of a persistent daemon.",
        ),
        matcher=_AI_DEV_INDEX_DAEMON_START,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _AI_DEV_INDEX_DAEMON_START_EXPLICIT,
                variant_id="help",
                title="ai-dev index daemon help",
                flag="--help",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.ai-dev.index-daemon-stop",
        title="ai-dev index daemon termination",
        description=(
            "Identifies `ai-dev index daemon stop` invocations that signal and terminate "
            "the background repository index watcher process."
        ),
        severity="medium",
        risk_classes=("destructive_shell", "execution"),
        action_classes=("ai-dev index daemon lifecycle command",),
        safer_alternatives=("Query daemon health with ai-dev index daemon status before stopping.",),
        matcher=_AI_DEV_INDEX_DAEMON_STOP,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _AI_DEV_INDEX_DAEMON_STOP,
                variant_id="help",
                title="ai-dev index daemon stop help",
                flag="--help",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.ai-dev.agents-claim",
        title="ai-dev multi-agent task lock claim",
        description=(
            "Identifies `ai-dev agents claim` invocations that place an exclusive lease lock "
            "on shared tasks and file paths in the coordination state."
        ),
        severity="medium",
        risk_classes=("destructive_shell",),
        action_classes=("ai-dev agent coordination mutation command",),
        safer_alternatives=("Inspect active agent locks with ai-dev agents status before claiming.",),
        matcher=_AI_DEV_AGENTS_CLAIM,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _AI_DEV_AGENTS_CLAIM,
                variant_id="help",
                title="ai-dev agents claim help",
                flag="--help",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.ai-dev.agents-release",
        title="ai-dev multi-agent task lock release",
        description=(
            "Identifies `ai-dev agents release` invocations that revoke an active lease lock "
            "and re-queue the task in shared coordination state."
        ),
        severity="low",
        risk_classes=("destructive_shell",),
        action_classes=("ai-dev agent coordination mutation command",),
        safer_alternatives=("Verify task ownership with ai-dev agents status before releasing.",),
        matcher=_AI_DEV_AGENTS_RELEASE,
        default_mode="review",
        safe_variants=(
            safe_flag_variant(
                _AI_DEV_AGENTS_RELEASE,
                variant_id="help",
                title="ai-dev agents release help",
                flag="--help",
            ),
        ),
    ),
)

# Action-class risk declarations for the ai-dev extension, merged into the
# global COMMAND_ACTION_RISK_CLASSES map by command_action_risk_classes.py the
# way it merges blitcp and github action classes.
AI_DEV_ACTION_RISK_CLASSES: dict[str, tuple[str, ...]] = {
    "ai-dev forced integration config overwrite command": ("destructive_shell",),
    "ai-dev index daemon lifecycle command": ("destructive_shell", "execution"),
    "ai-dev agent coordination mutation command": ("destructive_shell",),
}

AI_DEV_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.ai-dev",
        name="ai-dev command protection",
        description=(
            "Reviews ai-dev commands that force-overwrite IDE configurations, "
            "manage background index daemons, or mutate multi-agent task locks."
        ),
        action_classes=(
            "ai-dev forced integration config overwrite command",
            "ai-dev index daemon lifecycle command",
            "ai-dev agent coordination mutation command",
        ),
        risk_classes=("destructive_shell", "execution"),
        safer_alternatives=(
            "Run ai-dev integrations install without --force to preserve existing IDE configurations.",
            "Check running daemon state with ai-dev index daemon status before starting or stopping.",
            "Inspect active agent locks with ai-dev agents status before claiming or releasing.",
        ),
        reference_urls=("https://github.com/MatthiasLew/ai-dev-cli-tools",),
    ),
)
