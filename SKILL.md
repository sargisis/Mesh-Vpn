# Graphify Skill

## Description
This skill allows the agent to navigate a pre-built knowledge graph of the codebase instead of reading raw source files sequentially. Use this to reduce token usage and get accurate structural context for the Mesh-Vpn project.

## When to use
- When the user asks about project architecture, dependencies, or high-level logic.
- Before editing files that have complex cross-imports.
- To discover which files are affected by a specific change.

## Instructions for the Agent
1. The knowledge graph data is stored in the `graphify-out/` directory at the project root.
2. Instead of scanning all files blindly, inspect the generated graph artifacts in `graphify-out/` to find relationships, dependencies, and code structure.
3. Use these graph relationships to build a target list of files before performing modifications.