#!/usr/bin/env bash
# install.sh — Sync Seshat from this repo to live Hermes locations
# ================================================================
# Usage:  bash install.sh          # install everything
#         bash install.sh plugin   # plugin only
#         bash install.sh skill    # skill only
#         bash install.sh config   # policies + contexts only
#
# This is a ONE-WAY sync: repo → live. Never edit live files directly.
# The repo is the single source of truth.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
HERMES_HOME="${HERMES_HOME:-$HOME/AppData/Local/hermes}"
PLUGINS_DIR="$HERMES_HOME/plugins/seshat_pep"
SKILLS_DIR="$HERMES_HOME/skills/governance/seshat-governance"
SESHAT_HOME="$HOME/.seshat"

install_plugin() {
    echo "Installing plugin → $PLUGINS_DIR"
    mkdir -p "$PLUGINS_DIR"
    cp "$REPO_DIR"/plugin/__init__.py "$PLUGINS_DIR/"
    cp "$REPO_DIR"/plugin/evaluator.py "$PLUGINS_DIR/"
    cp "$REPO_DIR"/plugin/plugin_hooks.py "$PLUGINS_DIR/"
    cp "$REPO_DIR"/plugin/plugin.yaml "$PLUGINS_DIR/"
    echo "  ✓ Plugin installed"
}

install_skill() {
    echo "Installing skill → $SKILLS_DIR"
    mkdir -p "$SKILLS_DIR/scripts" "$SKILLS_DIR/references" "$SKILLS_DIR/templates"
    cp "$REPO_DIR"/skill/SKILL.md "$SKILLS_DIR/"
    cp "$REPO_DIR"/skill/scripts/eval.py "$SKILLS_DIR/scripts/"
    cp "$REPO_DIR"/skill/scripts/test_eval.py "$SKILLS_DIR/scripts/"
    cp "$REPO_DIR"/skill/references/*.md "$SKILLS_DIR/references/"
    cp "$REPO_DIR"/skill/templates/*.yml "$SKILLS_DIR/templates/"
    echo "  ✓ Skill installed"
}

install_config() {
    echo "Installing policies + contexts → $SESHAT_HOME"
    mkdir -p "$SESHAT_HOME/policies" "$SESHAT_HOME/contexts"
    cp "$REPO_DIR"/policies/*.yml "$SESHAT_HOME/policies/"
    cp "$REPO_DIR"/contexts/*.yaml "$SESHAT_HOME/contexts/"
    echo "  ✓ Policies + contexts installed"
    echo "  ⚠  Live context at ~/.seshat/contexts/ may have local customizations."
    echo "     This overwrites example_inspector.yaml with the repo version."
}

case "${1:-all}" in
    plugin)  install_plugin ;;
    skill)   install_skill ;;
    config)  install_config ;;
    all)
        install_plugin
        install_skill
        install_config
        echo ""
        echo "Done. Restart your Hermes session to load the updated plugin."
        ;;
    *)
        echo "Usage: bash install.sh [plugin|skill|config|all]"
        exit 1
        ;;
esac
