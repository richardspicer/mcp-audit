"""Command injection payload library for MCP05 testing.

Provides categorized payloads for detecting command injection
vulnerabilities in MCP tool parameters. Payloads use canary markers
that appear in output only if injection succeeds.

Each payload includes a canary string that scanners check for in
the tool's response to determine if injection occurred.
"""

from __future__ import annotations

from dataclasses import dataclass

# Unique marker that should never appear in legitimate output.
# If this shows up in a tool response, injection succeeded.
CANARY = "MCP_AUDIT_CANARY_7f3a9b2e"


@dataclass(frozen=True)
class InjectionPayload:
    """A single injection test payload.

    Attributes:
        value: The string to inject into a tool parameter.
        canary: The marker to look for in the response.
        technique: Human-readable name of the injection technique.
        platform: Target OS ('unix', 'windows', 'any').
        description: What this payload tests for.
    """

    value: str
    canary: str
    technique: str
    platform: str = "any"
    description: str = ""


def _unix_payloads() -> list[InjectionPayload]:
    """Unix/Linux command injection payloads."""
    return [
        InjectionPayload(
            value=f"; echo {CANARY}",
            canary=CANARY,
            technique="semicolon_chaining",
            platform="unix",
            description="Semicolon command separator — terminates prior command, runs echo",
        ),
        InjectionPayload(
            value=f"| echo {CANARY}",
            canary=CANARY,
            technique="pipe_injection",
            platform="unix",
            description="Pipe operator — pipes prior output into echo canary",
        ),
        InjectionPayload(
            value=f"&& echo {CANARY}",
            canary=CANARY,
            technique="and_chaining",
            platform="unix",
            description="AND operator — runs echo if prior command succeeds",
        ),
        InjectionPayload(
            value=f"|| echo {CANARY}",
            canary=CANARY,
            technique="or_chaining",
            platform="unix",
            description="OR operator — runs echo if prior command fails",
        ),
        InjectionPayload(
            value=f"$(echo {CANARY})",
            canary=CANARY,
            technique="command_substitution_dollar",
            platform="unix",
            description="Dollar-paren command substitution",
        ),
        InjectionPayload(
            value=f"`echo {CANARY}`",
            canary=CANARY,
            technique="command_substitution_backtick",
            platform="unix",
            description="Backtick command substitution",
        ),
        InjectionPayload(
            value=f"\necho {CANARY}\n",
            canary=CANARY,
            technique="newline_injection",
            platform="unix",
            description="Newline injection — starts new command on new line",
        ),
    ]


def _windows_payloads() -> list[InjectionPayload]:
    """Windows command injection payloads."""
    return [
        InjectionPayload(
            value=f"& echo {CANARY}",
            canary=CANARY,
            technique="ampersand_chaining",
            platform="windows",
            description="Ampersand command separator (Windows CMD)",
        ),
        InjectionPayload(
            value=f"| echo {CANARY}",
            canary=CANARY,
            technique="pipe_injection",
            platform="windows",
            description="Pipe operator (Windows CMD)",
        ),
        InjectionPayload(
            value=f"&& echo {CANARY}",
            canary=CANARY,
            technique="and_chaining",
            platform="windows",
            description="AND operator (Windows CMD)",
        ),
        InjectionPayload(
            value=f"|| echo {CANARY}",
            canary=CANARY,
            technique="or_chaining",
            platform="windows",
            description="OR operator (Windows CMD)",
        ),
    ]


def get_injection_payloads(
    platform: str = "all",
) -> list[InjectionPayload]:
    """Get injection payloads filtered by platform.

    Args:
        platform: Target platform filter. Options:
            - 'all': All payloads (unix + windows)
            - 'unix': Unix/Linux payloads only
            - 'windows': Windows payloads only

    Returns:
        List of InjectionPayload objects for testing.

    Example:
        >>> payloads = get_injection_payloads(platform="unix")
        >>> for p in payloads:
        ...     print(f"{p.technique}: {p.value!r}")
    """
    if platform == "unix":
        return _unix_payloads()
    elif platform == "windows":
        return _windows_payloads()
    else:
        return _unix_payloads() + _windows_payloads()
