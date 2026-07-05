"""
Seshat PEP — Policy Enforcement Point Plugin
=============================================
Intercepts every tool call via pre_tool_call hook, evaluates against
YAML governance policies, blocks DENY, logs to JSONL audit trail.

Architecture: PEP/PDP split
  - This plugin (PEP) = mandatory enforcement, runs on every tool call
  - seshat-governance skill (PDP) = advisory reasoning, agent self-governance

Based on Seshat v0.4 evaluation engine by Matthew Green.
"""

import logging
from pathlib import Path

from . import evaluator, plugin_hooks

logger = logging.getLogger(__name__)


def register(ctx):
    """Register Seshat PEP hooks — fires on every tool call."""
    logger.info("Seshat PEP v0.5.0 — Policy Enforcement Point active")

    ctx.register_hook("pre_tool_call", plugin_hooks.seshat_pre_tool_call)
    ctx.register_hook("post_tool_call", plugin_hooks.seshat_post_tool_call)
