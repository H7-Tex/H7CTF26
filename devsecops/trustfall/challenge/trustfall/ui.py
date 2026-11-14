from __future__ import annotations

import json
from html import escape

from .ui_base import PORTAL_TEMPLATE as _BASE_PORTAL_TEMPLATE


def _replace_once(template: str, old: str, new: str) -> str:
    if template.count(old) != 1:
        raise RuntimeError("portal template patch no longer matches exactly once")
    return template.replace(old, new, 1)


def _patched_template() -> str:
    template = _BASE_PORTAL_TEMPLATE
    template = _replace_once(
        template,
        'const state = { repo: null, runs: [], assurances: [], selectedPath: null, poll: null };',
        'const state = { repo: null, runs: [], assurances: [], selectedPath: null, draftTree: null, draftHead: null, poll: null };',
    )
    template = _replace_once(
        template,
        '  state.repo = repo;\n  state.runs = [...runs].sort((a, b) => Number(b.number) - Number(a.number));',
        '  state.repo = repo;\n  if (!state.draftTree || state.draftHead !== repo.head) {\n    state.draftTree = { ...repo.tree };\n    state.draftHead = repo.head;\n  }\n  state.runs = [...runs].sort((a, b) => Number(b.number) - Number(a.number));',
    )
    template = _replace_once(
        template,
        '  const files = Object.keys(state.repo.tree).sort();\n  state.selectedPath = state.selectedPath && state.repo.tree[state.selectedPath] !== undefined ? state.selectedPath : files[0];',
        '  const tree = state.draftTree || state.repo.tree;\n  const files = Object.keys(tree).sort();\n  state.selectedPath = state.selectedPath && tree[state.selectedPath] !== undefined ? state.selectedPath : files[0];',
    )
    template = _replace_once(
        template,
        '  const editor = byId("source-editor"); editor.value = state.repo.tree[state.selectedPath] || "";',
        '  const editor = byId("source-editor"); editor.value = tree[state.selectedPath] || ""; editor.oninput = () => { state.draftTree[state.selectedPath] = editor.value; };',
    )
    template = _replace_once(
        template,
        '  byId("commit-update").onclick = event => commitUpdate(event.currentTarget, editor.value);',
        '  byId("commit-update").onclick = event => commitUpdate(event.currentTarget);',
    )
    template = _replace_once(
        template,
        'async function commitUpdate(button, value) {',
        'async function commitUpdate(button) {',
    )
    template = _replace_once(
        template,
        '    const tree = { ...state.repo.tree, [state.selectedPath]: value };',
        '    const tree = { ...state.draftTree };',
    )
    template = _replace_once(
        template,
        'Commit creation uses optimistic head matching; a stale editor cannot silently advance the candidate.',
        'Edits are kept while you switch files and committed together. Commit creation uses optimistic head matching; a stale editor cannot silently advance the candidate.',
    )
    return template


PORTAL_TEMPLATE = _patched_template()


def render_portal_page(title: str, view: str, player_ref: str, seed_suppression: str) -> str:
    return (
        PORTAL_TEMPLATE.replace("__TITLE__", escape(title))
        .replace("__VIEW_JSON__", json.dumps(view))
        .replace("__PLAYER_REF_JSON__", json.dumps(player_ref))
        .replace("__SEED_JSON__", json.dumps(seed_suppression))
    )
