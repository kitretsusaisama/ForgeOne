"""Advanced Project Analyzer (Phase 1 Skeleton)

This module implements the *minimum-viable* architecture needed to begin
satisfying the user specification for an extremely detailed project documentation
tool.  It already supports:

1. Project structure analysis (directory tree, file sizes, permissions and
   symbolic links).
2. Basic Python code analysis (functions, classes, imports, cyclomatic
   complexity via *radon* if available).
3. A plugin architecture so that further analysers can be developed and plugged
   in very easily.
4. A simple text renderer that produces a multi-section report aligned with the
   “Main Index Sections” described by the user.

Run with:
    python -m debbuger.ind <project_root> [-o OUTPUT] [--json]

Further features will be added iteratively in subsequent phases.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import textwrap
from abc import ABC, abstractmethod
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

# Optional heavy dependencies — we import lazily
try:
    from radon.complexity import cc_visit  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    cc_visit = None  # noqa: N816

################################################################################
# Plugin framework
################################################################################

class AnalysisResult(Dict[str, Any]):
    """Type alias for plugin results."""


class AnalyzerPlugin(ABC):
    """Base-class for all analyzer plugins."""

    name: str = "base"

    @abstractmethod
    def analyze(self, project_root: Path) -> AnalysisResult:  # noqa: D401
        """Return structured information for this plugin."""


class PluginManager:
    """Registers and runs all analyzer plugins."""

    _registry: List[AnalyzerPlugin] = []

    @classmethod
    def register(cls, plugin: AnalyzerPlugin) -> None:  # noqa: D401
        cls._registry.append(plugin)

    @classmethod
    def run_all(cls, project_root: Path) -> Dict[str, AnalysisResult]:  # noqa: D401
        results: Dict[str, AnalysisResult] = {}
        for plugin in cls._registry:
            try:
                results[plugin.name] = plugin.analyze(project_root)
            except Exception as exc:  # pragma: no cover
                results[plugin.name] = {"error": str(exc)}
        return results

################################################################################
# Concrete plugins – Phase 1
################################################################################

class ProjectStructurePlugin(AnalyzerPlugin):
    name = "project_structure"

    def analyze(self, project_root: Path) -> AnalysisResult:  # noqa: D401
        tree_lines: List[str] = []
        dir_sizes: Dict[str, int] = defaultdict(int)

        for root, dirs, files in os.walk(project_root, followlinks=False):
            depth = Path(root).relative_to(project_root).parts
            indent = "    " * len(depth)
            rel_root = Path(root).relative_to(project_root)
            tree_lines.append(f"{indent}{rel_root or '.'}/")

            for fname in files:
                fpath = Path(root) / fname
                size = fpath.stat().st_size
                dir_sizes[str(rel_root)] += size
                perms = stat.filemode(fpath.stat().st_mode)
                is_hidden = fname.startswith('.')
                is_symlink = fpath.is_symlink()
                target = os.readlink(fpath) if is_symlink else ""
                tree_lines.append(
                    f"{indent}    {fname} | {size}B | {perms} | hidden={is_hidden} | link→{target}"
                )

        total_size = sum(dir_sizes.values())
        return {
            "tree": "\n".join(tree_lines),
            "dir_sizes": dict(dir_sizes),
            "total_size": total_size,
        }


class PythonCodePlugin(AnalyzerPlugin):
    name = "python_code"

    def analyze(self, project_root: Path) -> AnalysisResult:  # noqa: D401
        results: List[Dict[str, Any]] = []
        for pyfile in project_root.rglob("*.py"):
            try:
                source = pyfile.read_text(encoding="utf-8")
            except Exception:
                continue

            entry: Dict[str, Any] = {"file": str(pyfile.relative_to(project_root))}

            # AST parsing
            import ast  # local import to speed initial startup

            try:
                tree = ast.parse(source)
            except SyntaxError as exc:
                entry["syntax_error"] = str(exc)
                results.append(entry)
                continue

            functions, classes, imports = [], [], []
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    functions.append(node.name)
                elif isinstance(node, ast.AsyncFunctionDef):
                    functions.append(f"async {node.name}")
                elif isinstance(node, ast.ClassDef):
                    classes.append(node.name)
                elif isinstance(node, ast.Import):
                    imports.extend(name.name for name in node.names)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    imports.extend(f"{module}:{name.name}" for name in node.names)

            entry.update(
                {
                    "functions": sorted(functions),
                    "classes": sorted(classes),
                    "imports": sorted(imports),
                }
            )

            # Cyclomatic complexity (optional)
            if cc_visit is not None:
                try:
                    complexity_scores = [block.complexity for block in cc_visit(source)]
                    entry["mean_cyclomatic_complexity"] = (
                        sum(complexity_scores) / len(complexity_scores)
                        if complexity_scores
                        else 0
                    )
                except Exception:
                    entry["mean_cyclomatic_complexity"] = None
            else:
                entry["mean_cyclomatic_complexity"] = None

            results.append(entry)

        return {"python_files": results}


# Register plugins
PluginManager.register(ProjectStructurePlugin())
PluginManager.register(PythonCodePlugin())

################################################################################
# Rendering
################################################################################

def render_text(report: Dict[str, AnalysisResult]) -> str:  # noqa: D401
    """Render a human-readable text report."""
    lines: List[str] = []

    # Executive summary
    ps = report.get("project_structure", {})
    total_size = ps.get("total_size", 0)
    py_files = len(report.get("python_code", {}).get("python_files", []))
    lines.append("EXECUTIVE SUMMARY")
    lines.append("==================")
    lines.append(f"Total project size: {total_size:,} bytes")
    lines.append(f"Python files analysed: {py_files}")
    lines.append("")

    # Project architecture / directory tree
    if "tree" in ps:
        lines.append("PROJECT ARCHITECTURE")
        lines.append("====================")
        lines.append(ps["tree"])
        lines.append("")

    # Python code overview
    pc = report.get("python_code", {})
    if pc:
        lines.append("CODE STRUCTURE REFERENCE (Python)")
        lines.append("=================================")
        for f_entry in pc.get("python_files", []):
            lines.append(f"→ {f_entry['file']}")
            if f_entry.get("functions"):
                lines.append("    Functions: " + ", ".join(f_entry["functions"]))
            if f_entry.get("classes"):
                lines.append("    Classes  : " + ", ".join(f_entry["classes"]))
            if f_entry.get("mean_cyclomatic_complexity") is not None:
                lines.append(
                    f"    Mean CC : {f_entry['mean_cyclomatic_complexity']:.2f}"
                )
        lines.append("")

    return "\n".join(lines)

################################################################################
# CLI
################################################################################

def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:  # noqa: D401
    p = argparse.ArgumentParser(description="Advanced Project Analyzer (Phase 1)")
    p.add_argument("project_root", type=Path, help="Root directory of the project to analyse")
    p.add_argument("-o", "--output", type=Path, help="Path to write the report file")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:  # noqa: D401
    args = _parse_args(argv)
    project_root: Path = args.project_root.expanduser().resolve()
    if not project_root.exists():
        print(f"Error: {project_root} does not exist", file=sys.stderr)
        sys.exit(1)

    report = PluginManager.run_all(project_root)
    if args.json:
        output_data = json.dumps(report, indent=2)
    else:
        output_data = render_text(report)

    if args.output:
        args.output.write_text(output_data, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(output_data)


if __name__ == "__main__":  # pragma: no cover
    main()
