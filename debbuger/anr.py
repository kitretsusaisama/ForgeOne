import re
import sys
import json
import logging
import os
import threading
import concurrent.futures
import subprocess
import tempfile
import shutil
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Tuple, Set, Any, Union
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
import ast
import time
import hashlib

import requests
import google.generativeai as genai
import pandas as pd
import matplotlib.pyplot as plt
from tqdm import tqdm
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("../enhanced_error.log"),
        logging.StreamHandler()
    ]
)

# Configure Gemini API
api_key = os.getenv("GEMINI_API_KEY")
if api_key:
    genai.configure(api_key=api_key)

@dataclass
class FileLocation:
    """Represents a location in a file"""
    file_path: Path
    line: int
    column: int
    
    def __str__(self):
        return f"{self.file_path}:{self.line}:{self.column}"

@dataclass
class Symbol:
    """Represents a symbol in the code"""
    name: str
    symbol_type: str  # function, struct, enum, trait, variable, etc.
    location: FileLocation
    visibility: str  # pub, pub(crate), private
    signature: Optional[str] = None
    documentation: Optional[str] = None

@dataclass
class FileInfo:
    """Information about a Rust file"""
    path: Path
    content: str
    symbols: List[Symbol] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    dependencies: Set[str] = field(default_factory=set)
    last_modified: float = 0.0

@dataclass
class ErrorContext:
    """Enhanced error context with surrounding code"""
    error_location: FileLocation
    error_code: Optional[str]
    message: str
    surrounding_code: List[str] = field(default_factory=list)
    affected_symbols: List[Symbol] = field(default_factory=list)
    dependency_chain: List[str] = field(default_factory=list)
    related_errors: List[str] = field(default_factory=list)

class SuggestionType(Enum):
    """Types of code suggestions"""
    IMPORT_MISSING = "import_missing"
    TYPE_CONVERSION = "type_conversion"
    LIFETIME_ANNOTATION = "lifetime_annotation"
    TRAIT_IMPLEMENTATION = "trait_implementation"
    FUNCTION_SIGNATURE = "function_signature"
    PATTERN_MATCHING = "pattern_matching"
    MACRO_USAGE = "macro_usage"
    OWNERSHIP_FIX = "ownership_fix"
    BORROWING_FIX = "borrowing_fix"
    VISIBILITY_FIX = "visibility_fix"

@dataclass
class CodeSuggestion:
    """Represents a code suggestion"""
    suggestion_type: SuggestionType
    target_file: Path
    line_range: Tuple[int, int]
    original_code: str
    suggested_code: str
    confidence_score: float
    dependencies: List[Path] = field(default_factory=list)
    explanation: str = ""
    imports_needed: List[str] = field(default_factory=list)

class ProjectAnalyzer:
    """Analyzes entire Rust project structure"""
    
    def __init__(self, project_root: Path):
        self.project_root = Path(project_root)
        self.file_map: Dict[Path, FileInfo] = {}
        self.symbol_table: Dict[str, List[Symbol]] = defaultdict(list)
        self.dependency_graph: Dict[str, Set[str]] = defaultdict(set)
        self.type_hierarchy: Dict[str, Dict] = {}
        self.trait_implementations: Dict[str, List[FileLocation]] = defaultdict(list)
        self.macro_definitions: Dict[str, FileLocation] = {}
        
    def analyze_project(self) -> None:
        """Perform comprehensive project analysis"""
        logging.info(f"Starting project analysis for {self.project_root}")
        
        # Find all Rust files
        rust_files = list(self.project_root.rglob("*.rs"))
        logging.info(f"Found {len(rust_files)} Rust files")
        
        # Analyze each file
        for file_path in tqdm(rust_files, desc="Analyzing files"):
            try:
                self._analyze_file(file_path)
            except Exception as e:
                logging.error(f"Error analyzing {file_path}: {e}")
        
        # Build dependency relationships
        self._build_dependency_graph()
        
        # Analyze type hierarchy
        self._analyze_type_hierarchy()
        
        logging.info("Project analysis completed")
    
    def _analyze_file(self, file_path: Path) -> None:
        """Analyze a single Rust file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            logging.error(f"Could not read {file_path}: {e}")
            return
        
        file_info = FileInfo(
            path=file_path,
            content=content,
            last_modified=os.path.getmtime(file_path)
        )
        
        # Extract symbols
        file_info.symbols = self._extract_symbols(content, file_path)
        
        # Extract imports
        file_info.imports = self._extract_imports(content)
        
        # Extract dependencies
        file_info.dependencies = self._extract_dependencies(content)
        
        self.file_map[file_path] = file_info
        
        # Update symbol table
        for symbol in file_info.symbols:
            self.symbol_table[symbol.name].append(symbol)
    
    def _extract_symbols(self, content: str, file_path: Path) -> List[Symbol]:
        """Extract symbols from Rust code"""
        symbols = []
        lines = content.split('\n')
        
        # Patterns for different symbol types
        patterns = {
            'function': re.compile(r'^(\s*)(pub\s+|pub\(.*?\)\s+)?fn\s+(\w+)'),
            'struct': re.compile(r'^(\s*)(pub\s+|pub\(.*?\)\s+)?struct\s+(\w+)'),
            'enum': re.compile(r'^(\s*)(pub\s+|pub\(.*?\)\s+)?enum\s+(\w+)'),
            'trait': re.compile(r'^(\s*)(pub\s+|pub\(.*?\)\s+)?trait\s+(\w+)'),
            'impl': re.compile(r'^(\s*)impl\s+(?:<.*?>)?\s*(\w+)'),
            'const': re.compile(r'^(\s*)(pub\s+|pub\(.*?\)\s+)?const\s+(\w+)'),
            'static': re.compile(r'^(\s*)(pub\s+|pub\(.*?\)\s+)?static\s+(\w+)'),
            'macro': re.compile(r'^(\s*)macro_rules!\s+(\w+)'),
        }
        
        for line_num, line in enumerate(lines, 1):
            for symbol_type, pattern in patterns.items():
                match = pattern.match(line)
                if match:
                    visibility = "private"
                    if match.group(2):
                        if match.group(2).strip() == "pub":
                            visibility = "pub"
                        elif match.group(2).strip().startswith("pub("):
                            visibility = "pub(crate)"
                    
                    symbol_name = match.group(3) if symbol_type != 'impl' else match.group(2)
                    
                    symbol = Symbol(
                        name=symbol_name,
                        symbol_type=symbol_type,
                        location=FileLocation(file_path, line_num, match.start(3) if symbol_type != 'impl' else match.start(2)),
                        visibility=visibility,
                        signature=line.strip()
                    )
                    symbols.append(symbol)
                    
                    if symbol_type == 'macro':
                        self.macro_definitions[symbol_name] = symbol.location
        
        return symbols
    
    def _extract_imports(self, content: str) -> List[str]:
        """Extract use statements from Rust code"""
        imports = []
        use_pattern = re.compile(r'use\s+([^;]+);')
        
        for match in use_pattern.finditer(content):
            imports.append(match.group(1).strip())
        
        return imports
    
    def _extract_dependencies(self, content: str) -> Set[str]:
        """Extract module dependencies"""
        dependencies = set()
        
        # Extract from use statements
        use_pattern = re.compile(r'use\s+(\w+)(?:::.*)?;')
        for match in use_pattern.finditer(content):
            dependencies.add(match.group(1))
        
        # Extract from mod statements
        mod_pattern = re.compile(r'mod\s+(\w+);')
        for match in mod_pattern.finditer(content):
            dependencies.add(match.group(1))
        
        return dependencies
    
    def _build_dependency_graph(self) -> None:
        """Build dependency relationships between modules"""
        for file_path, file_info in self.file_map.items():
            module_name = file_path.stem
            for dep in file_info.dependencies:
                self.dependency_graph[module_name].add(dep)
    
    def _analyze_type_hierarchy(self) -> None:
        """Analyze type relationships and trait implementations"""
        for file_path, file_info in self.file_map.items():
            content = file_info.content
            
            # Find trait implementations
            impl_pattern = re.compile(r'impl\s+(?:<.*?>)?\s*(\w+)\s+for\s+(\w+)')
            for match in impl_pattern.finditer(content):
                trait_name = match.group(1)
                type_name = match.group(2)
                line_num = content[:match.start()].count('\n') + 1
                
                location = FileLocation(file_path, line_num, match.start())
                self.trait_implementations[trait_name].append(location)
    
    def find_symbol(self, name: str, context_file: Optional[Path] = None) -> List[Symbol]:
        """Find symbols by name, considering scope and visibility"""
        candidates = self.symbol_table.get(name, [])
        
        if not context_file:
            return candidates
        
        # Filter by visibility and scope
        visible_symbols = []
        for symbol in candidates:
            if self._is_symbol_visible(symbol, context_file):
                visible_symbols.append(symbol)
        
        return visible_symbols
    
    def _is_symbol_visible(self, symbol: Symbol, from_file: Path) -> bool:
        """Check if a symbol is visible from a given file"""
        if symbol.visibility == "pub":
            return True
        
        if symbol.visibility == "private":
            # Only visible within the same file
            return symbol.location.file_path == from_file
        
        if symbol.visibility == "pub(crate)":
            # Visible within the same crate
            return True  # Simplified - would need proper crate boundary detection
        
        return False

class CodeSuggestionEngine:
    """Generates intelligent code suggestions"""
    
    def __init__(self, project_analyzer: ProjectAnalyzer):
        self.project_analyzer = project_analyzer
        self.suggestion_patterns = self._load_suggestion_patterns()
    
    def _load_suggestion_patterns(self) -> Dict[str, Any]:
        """Load patterns for common Rust fixes"""
        return {
            'E0425': {  # cannot find value/function/variable
                'pattern': r"cannot find (?:value|function|variable) `(\w+)`",
                'handler': self._suggest_missing_import
            },
            'E0308': {  # mismatched types
                'pattern': r"mismatched types.*expected `([^`]+)`, found `([^`]+)`",
                'handler': self._suggest_type_conversion
            },
            'E0277': {  # trait bound not satisfied
                'pattern': r"the trait bound `([^`]+): ([^`]+)` is not satisfied",
                'handler': self._suggest_trait_implementation
            },
            'E0106': {  # missing lifetime specifier
                'pattern': r"missing lifetime specifier",
                'handler': self._suggest_lifetime_annotation
            },
            'E0382': {  # use of moved value
                'pattern': r"use of moved value: `([^`]+)`",
                'handler': self._suggest_ownership_fix
            },
            'E0502': {  # cannot borrow as mutable
                'pattern': r"cannot borrow `([^`]+)` as mutable",
                'handler': self._suggest_borrowing_fix
            }
        }
    
    def generate_suggestions(self, error_context: ErrorContext) -> List[CodeSuggestion]:
        """Generate suggestions for an error"""
        suggestions = []
        
        if error_context.error_code in self.suggestion_patterns:
            pattern_info = self.suggestion_patterns[error_context.error_code]
            pattern = pattern_info['pattern']
            handler = pattern_info['handler']
            
            match = re.search(pattern, error_context.message)
            if match:
                suggestion = handler(error_context, match)
                if suggestion:
                    suggestions.append(suggestion)
        
        # Try generic pattern matching
        generic_suggestions = self._generate_generic_suggestions(error_context)
        suggestions.extend(generic_suggestions)
        
        return suggestions
    
    def _suggest_missing_import(self, error_context: ErrorContext, match: re.Match) -> Optional[CodeSuggestion]:
        """Suggest missing import statements"""
        missing_symbol = match.group(1)
        
        # Find the symbol in the project
        symbols = self.project_analyzer.find_symbol(missing_symbol)
        if not symbols:
            return None
        
        # Find the best candidate
        best_symbol = self._find_best_symbol_candidate(symbols, error_context.error_location.file_path)
        if not best_symbol:
            return None
        
        # Generate import path
        import_path = self._generate_import_path(best_symbol, error_context.error_location.file_path)
        if not import_path:
            return None
        
        # Find insertion point for import
        file_info = self.project_analyzer.file_map[error_context.error_location.file_path]
        insertion_line = self._find_import_insertion_point(file_info.content)
        
        return CodeSuggestion(
            suggestion_type=SuggestionType.IMPORT_MISSING,
            target_file=error_context.error_location.file_path,
            line_range=(insertion_line, insertion_line),
            original_code="",
            suggested_code=f"use {import_path};",
            confidence_score=0.9,
            explanation=f"Import {missing_symbol} from {import_path}",
            imports_needed=[import_path]
        )
    
    def _suggest_type_conversion(self, error_context: ErrorContext, match: re.Match) -> Optional[CodeSuggestion]:
        """Suggest type conversions"""
        expected_type = match.group(1)
        found_type = match.group(2)
        
        # Common type conversion patterns
        conversions = {
            ('&str', 'String'): '.to_string()',
            ('String', '&str'): '.as_str()',
            ('i32', 'usize'): ' as usize',
            ('usize', 'i32'): ' as i32',
            ('Option<T>', 'T'): '.unwrap()',
            ('Result<T, E>', 'T'): '.unwrap()',
            ('T', 'Option<T>'): 'Some({})',
            ('T', 'Result<T, E>'): 'Ok({})',
        }
        
        conversion_key = (expected_type, found_type)
        if conversion_key not in conversions:
            # Try generic conversions
            if 'Option' in expected_type and 'Option' not in found_type:
                conversion = 'Some({})'
            elif 'Result' in expected_type and 'Result' not in found_type:
                conversion = 'Ok({})'
            elif expected_type.endswith('&str') and found_type == 'String':
                conversion = '.as_str()'
            elif expected_type == 'String' and found_type.endswith('&str'):
                conversion = '.to_string()'
            else:
                conversion = f'.into() // Convert {found_type} to {expected_type}'
        else:
            conversion = conversions[conversion_key]
        
        # Find the problematic expression
        error_line = error_context.error_location.line - 1
        if error_line < len(error_context.surrounding_code):
            original_line = error_context.surrounding_code[error_line]
            
            # Apply the conversion
            if '{}' in conversion:
                suggested_line = conversion.format(original_line.strip())
            else:
                suggested_line = original_line.rstrip() + conversion
            
            return CodeSuggestion(
                suggestion_type=SuggestionType.TYPE_CONVERSION,
                target_file=error_context.error_location.file_path,
                line_range=(error_context.error_location.line, error_context.error_location.line),
                original_code=original_line,
                suggested_code=suggested_line,
                confidence_score=0.8,
                explanation=f"Convert {found_type} to {expected_type} using {conversion}"
            )
        
        return None
    
    def _suggest_trait_implementation(self, error_context: ErrorContext, match: re.Match) -> Optional[CodeSuggestion]:
        """Suggest trait implementations"""
        type_name = match.group(1)
        trait_name = match.group(2)
        
        # Generate basic trait implementation
        impl_template = f"""
            impl {trait_name} for {type_name} {{
                // TODO: Implement required methods
            }}"""
        
        # Find insertion point (end of file or after type definition)
        file_info = self.project_analyzer.file_map[error_context.error_location.file_path]
        insertion_line = len(file_info.content.split('\n'))
        
        return CodeSuggestion(
            suggestion_type=SuggestionType.TRAIT_IMPLEMENTATION,
            target_file=error_context.error_location.file_path,
            line_range=(insertion_line, insertion_line),
            original_code="",
            suggested_code=impl_template,
            confidence_score=0.7,
            explanation=f"Implement {trait_name} trait for {type_name}"
        )
    
    def _suggest_lifetime_annotation(self, error_context: ErrorContext, match: re.Match) -> Optional[CodeSuggestion]:
        """Suggest lifetime annotations"""
        # This is complex and would require sophisticated analysis
        # For now, provide a basic suggestion
        error_line_idx = error_context.error_location.line - 1
        if error_line_idx < len(error_context.surrounding_code):
            original_line = error_context.surrounding_code[error_line_idx]
            
            # Simple heuristic: add 'a lifetime to function parameters
            if 'fn ' in original_line and '&' in original_line:
                suggested_line = original_line.replace('&', "&'a ")
                
                return CodeSuggestion(
                    suggestion_type=SuggestionType.LIFETIME_ANNOTATION,
                    target_file=error_context.error_location.file_path,
                    line_range=(error_context.error_location.line, error_context.error_location.line),
                    original_code=original_line,
                    suggested_code=suggested_line,
                    confidence_score=0.6,
                    explanation="Add lifetime annotation to resolve borrowing issues"
                )
        
        return None
    
    def _suggest_ownership_fix(self, error_context: ErrorContext, match: re.Match) -> Optional[CodeSuggestion]:
        """Suggest ownership fixes"""
        moved_value = match.group(1)
        
        # Common ownership fixes
        fixes = [
            f"{moved_value}.clone()",
            f"&{moved_value}",
            f"{moved_value}.as_ref()",
        ]
        
        error_line_idx = error_context.error_location.line - 1
        if error_line_idx < len(error_context.surrounding_code):
            original_line = error_context.surrounding_code[error_line_idx]
            
            # Try to apply the most appropriate fix
            if moved_value in original_line:
                suggested_line = original_line.replace(moved_value, f"{moved_value}.clone()")
                
                return CodeSuggestion(
                    suggestion_type=SuggestionType.OWNERSHIP_FIX,
                    target_file=error_context.error_location.file_path,
                    line_range=(error_context.error_location.line, error_context.error_location.line),
                    original_code=original_line,
                    suggested_code=suggested_line,
                    confidence_score=0.7,
                    explanation=f"Clone {moved_value} to avoid move"
                )
        
        return None
    
    def _suggest_borrowing_fix(self, error_context: ErrorContext, match: re.Match) -> Optional[CodeSuggestion]:
        """Suggest borrowing fixes"""
        borrowed_value = match.group(1)

        error_line_idx = error_context.error_location.line - 1
        if error_line_idx < len(error_context.surrounding_code):
            original_line = error_context.surrounding_code[error_line_idx]

        # Suggest using a different scope or cloning
        suggested_line = original_line.replace(borrowed_value, f"{borrowed_value}.clone()")

        return CodeSuggestion(
            suggestion_type=SuggestionType.BORROWING_FIX,
            target_file=error_context.error_location.file_path,
            line_range=(error_context.error_location.line, error_context.error_location.line),
            original_code=original_line,
            suggested_code=suggested_line,
            confidence_score=0.6,
            explanation="Try cloning the borrowed value to avoid lifetime issues"
        )

    def _suggest_ownership_fix(self, error_context: ErrorContext, match: re.Match) -> Optional[CodeSuggestion]:
        """Suggest ownership fixes"""
        moved_value = match.group(1)
        
        # Common ownership fixes
        fixes = [
            f"{moved_value}.clone()",
            f"&{moved_value}",
            f"{moved_value}.as_ref()",
        ]
        
        error_line_idx = error_context.error_location.line - 1
        if error_line_idx < len(error_context.surrounding_code):
            original_line = error_context.surrounding_code[error_line_idx]
            
            # Try to apply the most appropriate fix
            if moved_value in original_line:
                suggested_line = original_line.replace(moved_value, f"{moved_value}.clone()")
                
                return CodeSuggestion(
                    suggestion_type=SuggestionType.OWNERSHIP_FIX,
                    target_file=error_context.error_location.file_path,
                    line_range=(error_context.error_location.line, error_context.error_location.line),
                    original_code=original_line,
                    suggested_code=suggested_line,
                    confidence_score=0.7,
                    explanation=f"Clone {moved_value} to avoid move"
                )
        
        return None

    def _suggest_borrowing_fix(self, error_context: ErrorContext, match: re.Match) -> Optional[CodeSuggestion]:
        """Suggest borrowing fixes"""
        borrowed_value = match.group(1)
        
        error_line_idx = error_context.error_location.line - 1
        if error_line_idx < len(error_context.surrounding_code):
            original_line = error_context.surrounding_code[error_line_idx]
            
            # Suggest using a different scope or cloning
            suggested_line = original_line.replace(borrowed_value, f"{borrowed_value}.clone()")
            
            return CodeSuggestion(
                suggestion_type=SuggestionType.BORROWING_FIX,
                target_file=error_context.error_location.file_path,
                line_range=(error_context.error_location.line, error_context.error_location.line),
                original_code=original_line,
                suggested_code=suggested_line,
                confidence_score=0.6,
                explanation=f"Clone {borrowed_value} to resolve borrowing conflict"
            )
        
        return None

    def _generate_generic_suggestions(self, error_context: ErrorContext) -> List[CodeSuggestion]:
        """Generate generic suggestions based on error patterns"""
        suggestions = []

        # Pattern-based suggestions
        if "cannot find" in error_context.message:
            # Suggest common imports
            common_imports = [
                "std::collections::HashMap",
                "std::fs::File",
                "std::io::Read",
                "serde::{Serialize, Deserialize}",
            ]

            for import_path in common_imports:
                if any(part in error_context.message for part in import_path.split("::")[-1:]):
                    file_info = self.project_analyzer.file_map[error_context.error_location.file_path]
                    insertion_line = self._find_import_insertion_point(file_info.content)

                    suggestion = CodeSuggestion(
                        suggestion_type=SuggestionType.IMPORT_MISSING,
                        target_file=error_context.error_location.file_path,
                        line_range=(insertion_line, insertion_line),
                        original_code="",
                        suggested_code=f"use {import_path};",
                        confidence_score=0.5,
                        explanation=f"Try importing {import_path}",
                        imports_needed=[import_path]
                    )
                    suggestions.append(suggestion)

        return suggestions

    def _find_best_symbol_candidate(self, symbols: List[Symbol], context_file: Path) -> Optional[Symbol]:
        """Find the best symbol candidate based on context"""
        if not symbols:
            return None
        
        # Prefer symbols from the same crate/project
        project_symbols = [s for s in symbols if str(s.location.file_path).startswith(str(self.project_analyzer.project_root))]
        if project_symbols:
            return project_symbols[0]
            
            # Prefer symbols from the same crate/project
            project_symbols = [s for s in symbols if str(s.location.file_path).startswith(str(self.project_analyzer.project_root))]
            if project_symbols:
                return project_symbols[0]
            
            return symbols[0]
    
    def _generate_import_path(self, symbol: Symbol, from_file: Path) -> Optional[str]:
        """Generate import path for a symbol"""
        # Simplified import path generation
        symbol_file = symbol.location.file_path
        
        # If it's in the same file, no import needed
        if symbol_file == from_file:
            return None
        
        # Generate relative module path
        try:
            rel_path = symbol_file.relative_to(self.project_analyzer.project_root)
            module_path = str(rel_path.with_suffix('')).replace('/', '::').replace('\\', '::')
            
            if symbol.symbol_type in ['function', 'struct', 'enum', 'trait']:
                return f"{module_path}::{symbol.name}"
            else:
                return module_path
        except ValueError:
            return None
    
    def _find_import_insertion_point(self, content: str) -> int:
        """Find the best place to insert import statements"""
        lines = content.split('\n')
        
        # Find the last use statement
        last_use_line = 0
        for i, line in enumerate(lines):
            if line.strip().startswith('use '):
                last_use_line = i + 1
        
        # If no use statements, insert after any initial comments/attributes
        if last_use_line == 0:
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped and not stripped.startswith('//') and not stripped.startswith('#'):
                    return i
        
        return last_use_line

class ImpactAnalyzer:
    """Analyzes the impact of code changes across multiple files"""
    
    def __init__(self, project_analyzer: ProjectAnalyzer):
        self.project_analyzer = project_analyzer
    
    def analyze_change_impact(self, suggestion: CodeSuggestion) -> Dict[str, Any]:
        """Analyze the impact of applying a code suggestion"""
        impact = {
            'affected_files': [],
            'breaking_changes': [],
            'cascading_fixes': [],
            'risk_level': 'low'
        }
        
        # Analyze based on suggestion type
        if suggestion.suggestion_type == SuggestionType.IMPORT_MISSING:
            impact['risk_level'] = 'low'
            impact['affected_files'] = [suggestion.target_file]
        
        elif suggestion.suggestion_type == SuggestionType.TRAIT_IMPLEMENTATION:
            impact['risk_level'] = 'medium'
            impact['affected_files'] = self._find_trait_usage_files(suggestion)
        
        elif suggestion.suggestion_type == SuggestionType.FUNCTION_SIGNATURE:
            impact['risk_level'] = 'high'
            impact['affected_files'] = self._find_function_usage_files(suggestion)
            impact['breaking_changes'] = self._identify_breaking_changes(suggestion)
        
        return impact
    
    def _find_trait_usage_files(self, suggestion: CodeSuggestion) -> List[Path]:
        """Find files that might be affected by trait implementation changes"""
        affected_files = [suggestion.target_file]
        
        # Search for files that might use this trait
        trait_name = self._extract_trait_name_from_suggestion(suggestion)
        if trait_name:
            for file_path, file_info in self.project_analyzer.file_map.items():
                if trait_name in file_info.content:
                    affected_files.append(file_path)
        
        return list(set(affected_files))
    
    def _find_function_usage_files(self, suggestion: CodeSuggestion) -> List[Path]:
        """Find files that call a function being modified"""
        affected_files = [suggestion.target_file]
        
        function_name = self._extract_function_name_from_suggestion(suggestion)
        if function_name:
            for file_path, file_info in self.project_analyzer.file_map.items():
                if function_name in file_info.content:
                    affected_files.append(file_path)
        
        return list(set(affected_files))
    
    def _identify_breaking_changes(self, suggestion: CodeSuggestion) -> List[str]:
        """Identify potential breaking changes"""
        breaking_changes = []
        
        if suggestion.suggestion_type == SuggestionType.FUNCTION_SIGNATURE:
            breaking_changes.append("Function signature change may break existing callers")
        
        return breaking_changes
    
    def _extract_trait_name_from_suggestion(self, suggestion: CodeSuggestion) -> Optional[str]:
        """Extract trait name from suggestion"""
        if 'impl ' in suggestion.suggested_code:
            match = re.search(r'impl\s+(\w+)\s+for', suggestion.suggested_code)
            if match:
                return match.group(1)
        return None
    
    def _extract_function_name_from_suggestion(self, suggestion: CodeSuggestion) -> Optional[str]:
        """Extract function name from suggestion"""
        if 'fn ' in suggestion.suggested_code:
            match = re.search(r'fn\s+(\w+)', suggestion.suggested_code)
            if match:
                return match.group(1)
        return None

class FileEditor:
    """Handles precise file editing with backup and rollback capabilities"""
    
    def __init__(self, project_root: Path):
        self.project_root = Path(project_root)
        self.backup_dir = self.project_root / ".forge_backups"
        self.backup_dir.mkdir(exist_ok=True)
        self.applied_changes: List[Dict] = []
    
    def apply_suggestion(self, suggestion: CodeSuggestion, dry_run: bool = False) -> bool:
        """Apply a code suggestion to a file"""
        try:
            if not suggestion.target_file.exists():

                logging.error(f"Target file does not exist: {suggestion.target_file}")
                return False
            
            # Create backup
            backup_path = self._create_backup(suggestion.target_file)
            
            # Read current content
            with open(suggestion.target_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            # Apply the change
            start_line, end_line = suggestion.line_range
            start_idx = start_line - 1  # Convert to 0-based indexing
            end_idx = end_line - 1
            
            # Store original content for rollback
            original_lines = lines[start_idx:end_idx + 1] if end_idx < len(lines) else []
            
            if dry_run:
                logging.info(f"DRY RUN: Would apply suggestion to {suggestion.target_file}:{start_line}-{end_line}")
                return True
            
            # Apply imports if needed
            if suggestion.imports_needed:
                self._add_imports(lines, suggestion.imports_needed)
            
            # Apply the main change
            if suggestion.original_code == "":
                # Insert new code
                lines.insert(start_idx, suggestion.suggested_code + '\n')
            elif suggestion.suggested_code == "":
                # Delete lines
                del lines[start_idx:end_idx + 1]
            else:
                # Replace lines
                new_lines = [suggestion.suggested_code + '\n']
                lines[start_idx:end_idx + 1] = new_lines
            
            # Write back to file
            with open(suggestion.target_file, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            # Format the file
            self._format_file(suggestion.target_file)
            
            # Record the change for potential rollback
            change_record = {
                'file': suggestion.target_file,
                'backup_path': backup_path,
                'suggestion': suggestion,
                'original_lines': original_lines,
                'timestamp': time.time()
            }
            self.applied_changes.append(change_record)
            
            logging.info(f"Applied suggestion to {suggestion.target_file}")
            return True
            
        except Exception as e:
            logging.error(f"Error applying suggestion: {e}")
            return False
    
    def _create_backup(self, file_path: Path) -> Path:
        """Create a backup of the file"""
        timestamp = int(time.time())
        backup_name = f"{file_path.name}.{timestamp}.backup"
        backup_path = self.backup_dir / backup_name
        
        shutil.copy2(file_path, backup_path)
        return backup_path
    
    def _add_imports(self, lines: List[str], imports: List[str]) -> None:
        """Add import statements to the file"""
        # Find insertion point
        insertion_idx = 0
        for i, line in enumerate(lines):
            if line.strip().startswith('use '):
                insertion_idx = i + 1
            elif line.strip() and not line.strip().startswith('//') and not line.strip().startswith('#'):
                break
        
        # Add imports
        for import_stmt in imports:
            import_line = f"use {import_stmt};\n"
            if import_line not in lines:
                lines.insert(insertion_idx, import_line)
                insertion_idx += 1
    
    def _format_file(self, file_path: Path) -> None:
        """Format the file using rustfmt"""
        try:
            subprocess.run(['rustfmt', str(file_path)], check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            logging.warning(f"rustfmt failed for {file_path}: {e}")
        except FileNotFoundError:
            logging.warning("rustfmt not found, skipping formatting")
    
    def validate_changes(self) -> bool:
        """Validate changes by running cargo check"""
        try:
            result = subprocess.run(
                ['cargo', 'check'],
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=60
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            logging.error("cargo check timed out")
            return False
        except Exception as e:
            logging.error(f"Error running cargo check: {e}")
            return False
    
    def rollback_last_change(self) -> bool:
        """Rollback the last applied change"""
        if not self.applied_changes:
            logging.warning("No changes to rollback")
            return False
        
        last_change = self.applied_changes.pop()
        try:
            shutil.copy2(last_change['backup_path'], last_change['file'])
            logging.info(f"Rolled back changes to {last_change['file']}")
            return True
        except Exception as e:
            logging.error(f"Error rolling back changes: {e}")
            return False
    
    def rollback_all_changes(self) -> bool:
        """Rollback all applied changes"""
        success = True
        while self.applied_changes:
            if not self.rollback_last_change():
                success = False
        return success

class FixApplicator:
    """Manages the application of fixes with user interaction"""
    
    def __init__(self, project_analyzer: ProjectAnalyzer, file_editor: FileEditor):
        self.project_analyzer = project_analyzer
        self.file_editor = file_editor
        self.impact_analyzer = ImpactAnalyzer(project_analyzer)
    
    def apply_fixes_interactive(self, suggestions: List[CodeSuggestion]) -> Dict[str, Any]:
        """Apply fixes interactively with user confirmation"""
        results = {
            'applied': [],
            'skipped': [],
            'failed': [],
            'total_suggestions': len(suggestions)
        }
        
        # Sort suggestions by confidence score
        sorted_suggestions = sorted(suggestions, key=lambda x: x.confidence_score, reverse=True)
        
        for suggestion in sorted_suggestions:
            # Analyze impact
            impact = self.impact_analyzer.analyze_change_impact(suggestion)
            
            # Show suggestion details
            self._display_suggestion(suggestion, impact)
            
            # Get user decision
            decision = self._get_user_decision(suggestion, impact)
            
            if decision == 'apply':
                if self.file_editor.apply_suggestion(suggestion):
                    results['applied'].append(suggestion)
                    
                    # Validate the change
                    if not self.file_editor.validate_changes():
                        logging.warning("Validation failed, rolling back...")
                        self.file_editor.rollback_last_change()
                        results['failed'].append(suggestion)
                else:
                    results['failed'].append(suggestion)
            elif decision == 'skip':
                results['skipped'].append(suggestion)
            else:  # quit
                break
        
        return results
    
    def apply_fixes_batch(self, suggestions: List[CodeSuggestion], 
                         confidence_threshold: float = 0.8) -> Dict[str, Any]:
        """Apply fixes in batch mode with confidence threshold"""
        results = {
            'applied': [],
            'skipped': [],
            'failed': [],
            'total_suggestions': len(suggestions)
        }
        
        high_confidence_suggestions = [
            s for s in suggestions if s.confidence_score >= confidence_threshold
        ]
        
        logging.info(f"Applying {len(high_confidence_suggestions)} high-confidence suggestions")
        
        for suggestion in tqdm(high_confidence_suggestions, desc="Applying fixes"):
            if self.file_editor.apply_suggestion(suggestion):
                results['applied'].append(suggestion)
                
                # Validate after each change
                if not self.file_editor.validate_changes():
                    logging.warning(f"Validation failed for {suggestion.target_file}, rolling back")
                    self.file_editor.rollback_last_change()
                    results['failed'].append(suggestion)
            else:
                results['failed'].append(suggestion)
        
        return results
    
    def _display_suggestion(self, suggestion: CodeSuggestion, impact: Dict[str, Any]) -> None:
        """Display suggestion details to the user"""
        print(f"\n{'='*60}")
        print(f"Suggestion: {suggestion.suggestion_type.value}")
        print(f"File: {suggestion.target_file}")
        print(f"Lines: {suggestion.line_range[0]}-{suggestion.line_range[1]}")
        print(f"Confidence: {suggestion.confidence_score:.2f}")
        print(f"Risk Level: {impact['risk_level']}")
        print(f"\nExplanation: {suggestion.explanation}")
        
        if suggestion.original_code:
            print(f"\nOriginal code:")
            print(f"  {suggestion.original_code}")
        
        print(f"\nSuggested code:")
        print(f"  {suggestion.suggested_code}")
        
        if impact['affected_files']:
            print(f"\nAffected files: {len(impact['affected_files'])}")
            for file_path in impact['affected_files'][:5]:  # Show first 5
                print(f"  - {file_path}")
            if len(impact['affected_files']) > 5:
                print(f"  ... and {len(impact['affected_files']) - 5} more")
    
    def _get_user_decision(self, suggestion: CodeSuggestion, impact: Dict[str, Any]) -> str:
        """Get user decision on whether to apply the suggestion"""
        while True:
            choice = input("\nApply this suggestion? [y/n/q] (y=yes, n=no, q=quit): ").lower().strip()
            if choice in ['y', 'yes']:
                return 'apply'
            elif choice in ['n', 'no']:
                return 'skip'
            elif choice in ['q', 'quit']:
                return 'quit'
            else:
                print("Please enter 'y', 'n', or 'q'")

class EnhancedGeminiClient:
    """Enhanced Gemini client with context-rich prompts"""
    
    def __init__(self, project_analyzer: ProjectAnalyzer):
        self.project_analyzer = project_analyzer
        self.model = None
        if api_key:
            try:
                self.model = genai.GenerativeModel("gemini-1.5-flash")
            except Exception as e:
                logging.error(f"Failed to initialize Gemini: {e}")
    
    def get_enhanced_suggestion(self, error_context: ErrorContext) -> str:
        """Get enhanced suggestion with full project context"""
        if not self.model:
            return "AI suggestions unavailable"
        
        # Build context-rich prompt
        prompt = self._build_context_prompt(error_context)
        
        try:
            response = self.model.generate_content(prompt)
            return response.text.strip()
        except Exception as e:
            logging.error(f"Error getting enhanced suggestion: {e}")
            return f"AI suggestion error: {str(e)}"
    
    def _build_context_prompt(self, error_context: ErrorContext) -> str:
        """Build a comprehensive prompt with project context"""
        file_info = self.project_analyzer.file_map.get(error_context.error_location.file_path)
        
        prompt_parts = [
            "You are an expert Rust developer. Help fix this compiler error with precise, actionable code changes.\n\n",
            f"ERROR DETAILS:\n",
            f"Error Code: {error_context.error_code or 'Unknown'}\n",
            f"Message: {error_context.message}\n",
            f"File: {error_context.error_location.file_path}\n",
            f"Line: {error_context.error_location.line}\n\n",
        ]
        
        # Add surrounding code context
        if error_context.surrounding_code:
            prompt_parts.append("SURROUNDING CODE:\n")
            for i, line in enumerate(error_context.surrounding_code):
                line_num = error_context.error_location.line - 5 + i
                marker = " >>> " if line_num == error_context.error_location.line else "     "
                prompt_parts.append(f"{line_num:4d}{marker}{line}\n")
            prompt_parts.append("\n")
        
        # Add file imports context
        if file_info and file_info.imports:
            prompt_parts.append("CURRENT IMPORTS:\n")
            for import_stmt in file_info.imports:
                prompt_parts.append(f"use {import_stmt};\n")
            prompt_parts.append("\n")
        
        # Add available symbols context
        if error_context.affected_symbols:
            prompt_parts.append("AVAILABLE SYMBOLS:\n")
            for symbol in error_context.affected_symbols:
                prompt_parts.append(f"- {symbol.name} ({symbol.symbol_type}) in {symbol.location.file_path}\n")
            prompt_parts.append("\n")
        
        # Add specific instructions
        prompt_parts.extend([
            "REQUIREMENTS:\n",
            "1. Provide the exact code change needed\n",
            "2. If imports are needed, specify the exact use statements\n",
            "3. Explain why this fix works\n",
            "4. Consider Rust ownership, borrowing, and lifetime rules\n",
            "5. Ensure the fix follows Rust best practices\n\n",
            "Please provide your response in this format:\n",
            "SOLUTION:\n",
            "[exact code to replace the problematic line(s)]\n\n",
            "IMPORTS NEEDED:\n",
            "[any use statements to add]\n\n",
            "EXPLANATION:\n",
            "[detailed explanation of the fix]\n"
        ])
        
        return "".join(prompt_parts)

class EnhancedRustErrorAnalyzer:
    """Main enhanced analyzer class"""
    
    def __init__(self, log_file: str, project_root: str, output_dir: str = "enhanced_output"):
        self.log_file = log_file
        self.project_root = Path(project_root)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Initialize components
        self.project_analyzer = ProjectAnalyzer(self.project_root)
        self.suggestion_engine = CodeSuggestionEngine(self.project_analyzer)
        self.file_editor = FileEditor(self.project_root)
        self.fix_applicator = FixApplicator(self.project_analyzer, self.file_editor)
        self.gemini_client = EnhancedGeminiClient(self.project_analyzer)
        
        # Error storage
        self.error_contexts: List[ErrorContext] = []
        self.suggestions: List[CodeSuggestion] = []
    
    def analyze_and_fix(self, interactive: bool = True, confidence_threshold: float = 0.8) -> Dict[str, Any]:
        """Complete analysis and fix workflow"""
        logging.info("Starting enhanced Rust error analysis")
        
        # Step 1: Analyze project structure
        logging.info("Analyzing project structure...")
        self.project_analyzer.analyze_project()
        
        # Step 2: Parse error log with enhanced context
        logging.info("Parsing error log...")
        self._parse_enhanced_error_log()
        
        # Step 3: Generate intelligent suggestions
        logging.info("Generating code suggestions...")
        self._generate_all_suggestions()
        
        # Step 4: Apply fixes
        logging.info("Applying fixes...")
        if interactive:
            results = self.fix_applicator.apply_fixes_interactive(self.suggestions)
        else:
            results = self.fix_applicator.apply_fixes_batch(self.suggestions, confidence_threshold)
        
        # Step 5: Generate comprehensive reports
        logging.info("Generating reports...")
        self._generate_enhanced_reports(results)
        
        return results
    
    def _parse_enhanced_error_log(self) -> None:
        """Parse error log with enhanced context extraction"""
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                log_content = f.read()
        except Exception as e:
            logging.error(f"Error reading log file: {e}")
            return
        
        # Extract errors with enhanced patterns
        error_pattern = re.compile(
            r"error(?:\[(?P<code>E\d+)\])?: (?P<message>.*?)\n"
            r"\s*--> (?P<file>[^:]+):(?P<line>\d+):(?P<column>\d+)",
            re.MULTILINE | re.DOTALL
        )
        
        for match in error_pattern.finditer(log_content):
            error_code = match.group('code')
            message = match.group('message').strip()
            file_path = Path(match.group('file'))
            line = int(match.group('line'))
            column = int(match.group('column'))
            
            # Create error context with surrounding code
            error_context = ErrorContext(
                error_location=FileLocation(file_path, line, column),
                error_code=error_code,
                message=message,
                surrounding_code=self._extract_surrounding_code(file_path, line),
                affected_symbols=self._find_affected_symbols(file_path, line),
                dependency_chain=self._trace_dependency_chain(file_path)
            )
            
            self.error_contexts.append(error_context)
        
        logging.info(f"Extracted {len(self.error_contexts)} error contexts")
    
    def _extract_surrounding_code(self, file_path: Path, line: int, context_lines: int = 10) -> List[str]:
        """Extract surrounding code context"""
        try:
            if not file_path.exists():
                return []
            
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            start_line = max(0, line - context_lines - 1)
            end_line = min(len(lines), line + context_lines)
            
            return [line.rstrip() for line in lines[start_line:end_line]]
        except Exception as e:
            logging.error(f"Error extracting surrounding code from {file_path}: {e}")
            return []
    
    def _find_affected_symbols(self, file_path: Path, line: int) -> List[Symbol]:
        """Find symbols that might be affected by the error"""
        affected_symbols = []
        
        file_info = self.project_analyzer.file_map.get(file_path)
        if not file_info:
            return affected_symbols
        
        # Find symbols near the error location
        for symbol in file_info.symbols:
            if abs(symbol.location.line - line) <= 5:  # Within 5 lines
                affected_symbols.append(symbol)
        
        return affected_symbols
    
    def _trace_dependency_chain(self, file_path: Path) -> List[str]:
        """Trace the dependency chain for a file"""
        file_info = self.project_analyzer.file_map.get(file_path)
        if not file_info:
            return []
        
        return list(file_info.dependencies)
    
    def _generate_all_suggestions(self) -> None:
        """Generate suggestions for all error contexts"""
        for error_context in tqdm(self.error_contexts, desc="Generating suggestions"):
            # Generate pattern-based suggestions
            pattern_suggestions = self.suggestion_engine.generate_suggestions(error_context)
            self.suggestions.extend(pattern_suggestions)
            
            # Generate AI-enhanced suggestions
            if api_key:
                ai_suggestion_text = self.gemini_client.get_enhanced_suggestion(error_context)
                ai_suggestion = self._parse_ai_suggestion(error_context, ai_suggestion_text)
                if ai_suggestion:
                    self.suggestions.append(ai_suggestion)
        
        logging.info(f"Generated {len(self.suggestions)} total suggestions")
    
    def _parse_ai_suggestion(self, error_context: ErrorContext, ai_text: str) -> Optional[CodeSuggestion]:
        """Parse AI suggestion text into structured suggestion"""
        try:
            # Extract solution code
            solution_match = re.search(r"SOLUTION:\s*\n(.*?)\n\n", ai_text, re.DOTALL)
            if not solution_match:
                return None
            
            suggested_code = solution_match.group(1).strip()
            
            # Extract imports
            imports_match = re.search(r"IMPORTS NEEDED:\s*\n(.*?)\n\n", ai_text, re.DOTALL)
            imports_needed = []
            if imports_match:
                import_text = imports_match.group(1).strip()
                if import_text and import_text != "[none]":
                    imports_needed = [imp.strip() for imp in import_text.split('\n') if imp.strip()]
            
            # Extract explanation
            explanation_match = re.search(r"EXPLANATION:\s*\n(.*?)$", ai_text, re.DOTALL)
            explanation = explanation_match.group(1).strip() if explanation_match else "AI-generated suggestion"
            
            return CodeSuggestion(
                suggestion_type=SuggestionType.IMPORT_MISSING,  # Default, could be smarter
                target_file=error_context.error_location.file_path,
                line_range=(error_context.error_location.line, error_context.error_location.line),
                original_code="",  # Would need to extract from context
                suggested_code=suggested_code,
                confidence_score=0.75,  # AI suggestions get medium confidence
                explanation=explanation,
                imports_needed=imports_needed
            )
        
        except Exception as e:
            logging.error(f"Error parsing AI suggestion: {e}")
            return None
    
    def _generate_enhanced_reports(self, results: Dict[str, Any]) -> None:
        """Generate comprehensive reports"""
        # Generate JSON report
        self._save_enhanced_json_report(results)
        
        # Generate interactive HTML report
        self._save_interactive_html_report(results)
        
        # Generate visualization reports
        self._generate_enhanced_visualizations(results)
        
        # Generate diff report
        self._generate_diff_report(results)
    
    def _save_enhanced_json_report(self, results: Dict[str, Any]) -> None:
        """Save enhanced JSON report"""
        report = {
            "metadata": {
                "project_root": str(self.project_root),
                "log_file": self.log_file,
                "analysis_timestamp": time.time(),
                "total_files_analyzed": len(self.project_analyzer.file_map),
                "total_symbols_found": sum(len(symbols) for symbols in self.project_analyzer.symbol_table.values())
            },
            "project_structure": {
                "files": {str(path): {
                    "symbols": len(info.symbols),
                    "imports": len(info.imports),
                    "dependencies": list(info.dependencies)
                } for path, info in self.project_analyzer.file_map.items()},
                "dependency_graph": {k: list(v) for k, v in self.project_analyzer.dependency_graph.items()},
                "symbol_distribution": {
                    symbol_type: len([s for symbols in self.project_analyzer.symbol_table.values() 
                                    for s in symbols if s.symbol_type == symbol_type])
                    for symbol_type in ['function', 'struct', 'enum', 'trait', 'impl']
                }
            },
            "error_analysis": {
                "total_errors": len(self.error_contexts),
                "errors_by_code": self._group_errors_by_code(),
                "errors_by_file": self._group_errors_by_file(),
                "error_contexts": [self._serialize_error_context(ctx) for ctx in self.error_contexts]
            },
            "suggestions": {
                "total_suggestions": len(self.suggestions),
                "suggestions_by_type": self._group_suggestions_by_type(),
                "confidence_distribution": self._analyze_confidence_distribution(),
                "all_suggestions": [self._serialize_suggestion(s) for s in self.suggestions]
            },
            "fix_results": results
        }
        
        output_path = self.output_dir / "enhanced_analysis_report.json"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        logging.info(f"Enhanced JSON report saved to {output_path}")
    
    def _save_interactive_html_report(self, results: Dict[str, Any]) -> None:
        """Save interactive HTML report with code editor"""
        html_content = self._build_interactive_html(results)
        
        output_path = self.output_dir / "interactive_report.html"
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logging.info(f"Interactive HTML report saved to {output_path}")
    
    def _build_interactive_html(self, results: Dict[str, Any]) -> str:
        """Build interactive HTML report"""
        html_parts = [
            "<!DOCTYPE html>",
            "<html lang='en'>",
            "<head>",
            "  <meta charset='UTF-8'>",
            "  <meta name='viewport' content='width=device-width, initial-scale=1.0'>",
            "  <title>Enhanced Rust Error Analysis Report</title>",
            "  <link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/prism/1.24.1/themes/prism.min.css'>",
            "  <script src='https://cdnjs.cloudflare.com/ajax/libs/prism/1.24.1/components/prism-core.min.js'></script>",
            "  <script src='https://cdnjs.cloudflare.com/ajax/libs/prism/1.24.1/components/prism-rust.min.js'></script>",
            "  <style>",
            self._get_enhanced_css(),
            "  </style>",
            "</head>",
            "<body>",
            "  <div class='container'>",
            "    <header>",
            f"      <h1>Enhanced Rust Error Analysis Report</h1>",
            f"      <p>Project: {self.project_root}</p>",
            f"      <p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>",
            "    </header>",
            
            # Summary dashboard
            "    <section class='dashboard'>",
            "      <h2>Analysis Dashboard</h2>",
            "      <div class='stats-grid'>",
            f"        <div class='stat-card'><h3>{len(self.error_contexts)}</h3><p>Errors Found</p></div>",
            f"        <div class='stat-card'><h3>{len(self.suggestions)}</h3><p>Suggestions Generated</p></div>",
            f"        <div class='stat-card'><h3>{len(results.get('applied', []))}</h3><p>Fixes Applied</p></div>",
            f"        <div class='stat-card'><h3>{len(self.project_analyzer.file_map)}</h3><p>Files Analyzed</p></div>",
            "      </div>",
            "    </section>",
            
            # Interactive tabs
            "    <div class='tabs'>",
            "      <button class='tab-button active' onclick='showTab(\"errors\")'>Errors</button>",
            "      <button class='tab-button' onclick='showTab(\"suggestions\")'>Suggestions</button>",
            "      <button class='tab-button' onclick='showTab(\"fixes\")'>Applied Fixes</button>",
            "      <button class='tab-button' onclick='showTab(\"project\")'>Project Structure</button>",
            "    </div>",
            
            # Error analysis tab
            "    <div id='errors' class='tab-content active'>",
            "      <h2>Error Analysis</h2>",
            self._build_errors_section(),
            "    </div>",
            
            # Suggestions tab
            "    <div id='suggestions' class='tab-content'>",
            "      <h2>Code Suggestions</h2>",
            self._build_suggestions_section(),
            "    </div>",
            
            # Applied fixes tab
            "    <div id='fixes' class='tab-content'>",
            "      <h2>Applied Fixes</h2>",
            self._build_fixes_section(results),
            "    </div>",
            
            # Project structure tab
            "    <div id='project' class='tab-content'>",
            "      <h2>Project Structure</h2>",
            self._build_project_section(),
            "    </div>",
            
            "  </div>",
            "  <script>",
            self._get_interactive_js(),
            "  </script>",
            "</body>",
            "</html>"
        ]
        
        return "\n".join(html_parts)
    
    def _get_enhanced_css(self) -> str:
        """Get enhanced CSS for the interactive report"""
        return """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .dashboard { background: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px; }
        .stat-card { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; }
        .stat-card h3 { font-size: 2em; margin-bottom: 5px; }
                .tabs { display: flex; background: white; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .tab-button { flex: 1; padding: 15px 20px; border: none; background: transparent; cursor: pointer; font-size: 16px; transition: all 0.3s; }
        .tab-button:hover { background: #f0f0f0; }
        .tab-button.active { background: #667eea; color: white; }
        .tab-content { display: none; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .tab-content.active { display: block; }
        .error-item { border-left: 4px solid #e74c3c; padding: 20px; margin-bottom: 20px; background: #fff; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .suggestion-item { border-left: 4px solid #3498db; padding: 20px; margin-bottom: 20px; background: #fff; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .fix-item { border-left: 4px solid #27ae60; padding: 20px; margin-bottom: 20px; background: #fff; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .code-block { background: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 5px; overflow-x: auto; margin: 10px 0; }
        .diff-view { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 15px 0; }
        .diff-before { background: #ffeaea; border-left: 4px solid #e74c3c; padding: 15px; }
        .diff-after { background: #eafaf1; border-left: 4px solid #27ae60; padding: 15px; }
        .confidence-bar { width: 100%; height: 8px; background: #ecf0f1; border-radius: 4px; overflow: hidden; margin: 10px 0; }
        .confidence-fill { height: 100%; background: linear-gradient(90deg, #e74c3c 0%, #f39c12 50%, #27ae60 100%); transition: width 0.3s; }
        .file-tree { font-family: monospace; background: #f8f9fa; padding: 15px; border-radius: 5px; }
        .file-tree ul { list-style: none; padding-left: 20px; }
        .file-tree li { margin: 5px 0; }
        .expandable { cursor: pointer; user-select: none; }
        .expandable:before { content: '▶ '; }
        .expandable.expanded:before { content: '▼ '; }
        .hidden { display: none; }
        """
    
    def _build_errors_section(self) -> str:
        """Build the errors section of the HTML report"""
        html_parts = []
        
        for i, error_context in enumerate(self.error_contexts):
            html_parts.extend([
                f"<div class='error-item'>",
                f"  <h3>Error {i+1}: {error_context.error_code or 'Unknown'}</h3>",
                f"  <p><strong>File:</strong> {error_context.error_location.file_path}</p>",
                f"  <p><strong>Line:</strong> {error_context.error_location.line}:{error_context.error_location.column}</p>",
                f"  <p><strong>Message:</strong> {error_context.message}</p>",
                
                # Surrounding code
                "  <h4>Code Context:</h4>",
                "  <pre class='code-block'><code class='language-rust'>",
            ])
            
            for j, line in enumerate(error_context.surrounding_code):
                line_num = error_context.error_location.line - 5 + j
                if line_num == error_context.error_location.line:
                    html_parts.append(f">>> {line_num:4d}: {line}")
                else:
                    html_parts.append(f"    {line_num:4d}: {line}")
            
            html_parts.extend([
                "  </code></pre>",
                
                # Affected symbols
                "  <h4>Affected Symbols:</h4>",
                "  <ul>",
            ])
            
            for symbol in error_context.affected_symbols:
                html_parts.append(f"    <li>{symbol.name} ({symbol.symbol_type}) - {symbol.visibility}</li>")
            
            html_parts.extend([
                "  </ul>",
                "</div>"
            ])
        
        return "\n".join(html_parts)
    
    def _build_suggestions_section(self) -> str:
        """Build the suggestions section of the HTML report"""
        html_parts = []
        
        for i, suggestion in enumerate(self.suggestions):
            confidence_percent = suggestion.confidence_score * 100
            
            html_parts.extend([
                f"<div class='suggestion-item'>",
                f"  <h3>Suggestion {i+1}: {suggestion.suggestion_type.value.replace('_', ' ').title()}</h3>",
                f"  <p><strong>File:</strong> {suggestion.target_file}</p>",
                f"  <p><strong>Lines:</strong> {suggestion.line_range[0]}-{suggestion.line_range[1]}</p>",
                f"  <p><strong>Confidence:</strong> {confidence_percent:.1f}%</p>",
                f"  <div class='confidence-bar'><div class='confidence-fill' style='width: {confidence_percent}%'></div></div>",
                f"  <p><strong>Explanation:</strong> {suggestion.explanation}</p>",
                
                # Code diff
                "  <h4>Proposed Changes:</h4>",
                "  <div class='diff-view'>",
                "    <div class='diff-before'>",
                "      <h5>Before:</h5>",
                f"      <pre><code class='language-rust'>{suggestion.original_code or '(new code)'}</code></pre>",
                "    </div>",
                "    <div class='diff-after'>",
                "      <h5>After:</h5>",
                f"      <pre><code class='language-rust'>{suggestion.suggested_code}</code></pre>",
                "    </div>",
                "  </div>",
            ])
            
            # Imports needed
            if suggestion.imports_needed:
                html_parts.extend([
                    "  <h4>Required Imports:</h4>",
                    "  <ul>",
                ])
                for import_stmt in suggestion.imports_needed:
                    html_parts.append(f"    <li><code>use {import_stmt};</code></li>")
                html_parts.append("  </ul>")
            
            html_parts.append("</div>")
        
        return "\n".join(html_parts)
    
    def _build_fixes_section(self, results: Dict[str, Any]) -> str:
        """Build the applied fixes section"""
        html_parts = [
            f"<div class='summary'>",
            f"  <h3>Fix Summary</h3>",
            f"  <p>Applied: {len(results.get('applied', []))}</p>",
            f"  <p>Skipped: {len(results.get('skipped', []))}</p>",
            f"  <p>Failed: {len(results.get('failed', []))}</p>",
            f"</div>"
        ]
        
        # Applied fixes
        if results.get('applied'):
            html_parts.append("<h3>Successfully Applied Fixes</h3>")
            for i, suggestion in enumerate(results['applied']):
                html_parts.extend([
                    f"<div class='fix-item'>",
                    f"  <h4>Fix {i+1}: {suggestion.suggestion_type.value.replace('_', ' ').title()}</h4>",
                    f"  <p><strong>File:</strong> {suggestion.target_file}</p>",
                    f"  <p><strong>Explanation:</strong> {suggestion.explanation}</p>",
                    f"</div>"
                ])
        
        # Failed fixes
        if results.get('failed'):
            html_parts.append("<h3>Failed Fixes</h3>")
            for i, suggestion in enumerate(results['failed']):
                html_parts.extend([
                    f"<div class='error-item'>",
                    f"  <h4>Failed Fix {i+1}: {suggestion.suggestion_type.value.replace('_', ' ').title()}</h4>",
                    f"  <p><strong>File:</strong> {suggestion.target_file}</p>",
                    f"  <p><strong>Reason:</strong> Fix application failed</p>",
                    f"</div>"
                ])
        
        return "\n".join(html_parts)
    
    def _build_project_section(self) -> str:
        """Build the project structure section"""
        html_parts = [
            "<h3>Project Overview</h3>",
            f"<p><strong>Total Files:</strong> {len(self.project_analyzer.file_map)}</p>",
            f"<p><strong>Total Symbols:</strong> {sum(len(symbols) for symbols in self.project_analyzer.symbol_table.values())}</p>",
            
            "<h3>File Structure</h3>",
            "<div class='file-tree'>",
            self._build_file_tree(),
            "</div>",
            
            "<h3>Symbol Distribution</h3>",
            "<div class='stats-grid'>",
        ]
        
        # Symbol type distribution
        symbol_counts = {}
        for symbols in self.project_analyzer.symbol_table.values():
            for symbol in symbols:
                symbol_counts[symbol.symbol_type] = symbol_counts.get(symbol.symbol_type, 0) + 1
        
        for symbol_type, count in symbol_counts.items():
            html_parts.append(f"<div class='stat-card'><h3>{count}</h3><p>{symbol_type.title()}s</p></div>")
        
        html_parts.extend([
            "</div>",
            
            "<h3>Dependency Graph</h3>",
            "<div class='file-tree'>",
        ])
        
        # Dependency relationships
        for module, deps in self.project_analyzer.dependency_graph.items():
            if deps:
                html_parts.append(f"<div><strong>{module}</strong> depends on:</div>")
                html_parts.append("<ul>")
                for dep in deps:
                    html_parts.append(f"<li>{dep}</li>")
                html_parts.append("</ul>")
        
        html_parts.append("</div>")
        
        return "\n".join(html_parts)
    
    def _build_file_tree(self) -> str:
        """Build a visual file tree"""
        # Group files by directory
        file_tree = {}
        for file_path in self.project_analyzer.file_map.keys():
            parts = file_path.relative_to(self.project_root).parts
            current = file_tree
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            current[parts[-1]] = None  # File marker
        
        return self._render_tree_html(file_tree)
    
    def _render_tree_html(self, tree: Dict, level: int = 0) -> str:
        """Render file tree as HTML"""
        html_parts = []
        if level == 0:
            html_parts.append("<ul>")
        
        for name, subtree in tree.items():
            if subtree is None:  # File
                html_parts.append(f"<li>📄 {name}</li>")
            else:  # Directory
                html_parts.extend([
                    f"<li class='expandable' onclick='toggleExpand(this)'>📁 {name}",
                    "<ul class='hidden'>",
                    self._render_tree_html(subtree, level + 1),
                    "</ul>",
                    "</li>"
                ])
        
        if level == 0:
            html_parts.append("</ul>")
        
        return "\n".join(html_parts)
    
    def _get_interactive_js(self) -> str:
        """Get JavaScript for interactive features"""
        return """
        function showTab(tabName) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Remove active class from all buttons
            document.querySelectorAll('.tab-button').forEach(button => {
                button.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
        }
        
        function toggleExpand(element) {
            element.classList.toggle('expanded');
            const ul = element.querySelector('ul');
            if (ul) {
                ul.classList.toggle('hidden');
            }
        }
        
        // Initialize syntax highlighting
        document.addEventListener('DOMContentLoaded', function() {
            Prism.highlightAll();
        });
        """
    
    def _generate_enhanced_visualizations(self, results: Dict[str, Any]) -> None:
        """Generate enhanced visualizations"""
        viz_dir = self.output_dir / "visualizations"
        viz_dir.mkdir(exist_ok=True)
        
        # Error distribution by type
        self._plot_error_distribution(viz_dir)
        
        # Suggestion confidence distribution
        self._plot_confidence_distribution(viz_dir)
        
        # Fix success rate
        self._plot_fix_success_rate(viz_dir, results)
        
        # Project complexity metrics
        self._plot_project_metrics(viz_dir)
        
        # Dependency graph visualization
        self._plot_dependency_graph(viz_dir)
    
    def _plot_error_distribution(self, viz_dir: Path) -> None:
        """Plot error distribution by type"""
        error_codes = [ctx.error_code for ctx in self.error_contexts if ctx.error_code]
        error_counts = Counter(error_codes)
        
        plt.figure(figsize=(12, 8))
        codes = list(error_counts.keys())
        counts = list(error_counts.values())
        
        bars = plt.bar(codes, counts, color='lightcoral')
        plt.title('Error Distribution by Error Code', fontsize=16)
        plt.xlabel('Error Code', fontsize=12)
        plt.ylabel('Count', fontsize=12)
        plt.xticks(rotation=45)
        
        # Add count labels
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
            f'{int(height)}', ha='center', va='bottom')
        plt.tight_layout()
        plt.savefig(viz_dir / 'error_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_confidence_distribution(self, viz_dir: Path) -> None:
        """Plot suggestion confidence distribution"""
        confidences = [s.confidence_score for s in self.suggestions]
        
        plt.figure(figsize=(10, 6))
        plt.hist(confidences, bins=20, color='skyblue', alpha=0.7, edgecolor='black')
        plt.title('Suggestion Confidence Distribution', fontsize=16)
        plt.xlabel('Confidence Score', fontsize=12)
        plt.ylabel('Number of Suggestions', fontsize=12)
        plt.axvline(x=0.8, color='red', linestyle='--', label='High Confidence Threshold')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(viz_dir / 'confidence_distribution.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_fix_success_rate(self, viz_dir: Path, results: Dict[str, Any]) -> None:
        """Plot fix success rate"""
        categories = ['Applied', 'Skipped', 'Failed']
        counts = [
            len(results.get('applied', [])),
            len(results.get('skipped', [])),
            len(results.get('failed', []))
        ]
        colors = ['#27ae60', '#f39c12', '#e74c3c']
        
        plt.figure(figsize=(8, 8))
        wedges, texts, autotexts = plt.pie(counts, labels=categories, colors=colors, 
                                          autopct='%1.1f%%', startangle=90)
        plt.title('Fix Application Results', fontsize=16)
        
        # Enhance text
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
        
        plt.tight_layout()
        plt.savefig(viz_dir / 'fix_success_rate.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_project_metrics(self, viz_dir: Path) -> None:
        """Plot project complexity metrics"""
        # Calculate metrics
        file_sizes = []
        symbol_counts = []
        dependency_counts = []
        
        for file_path, file_info in self.project_analyzer.file_map.items():
            try:
                file_sizes.append(file_path.stat().st_size)
                symbol_counts.append(len(file_info.symbols))
                dependency_counts.append(len(file_info.dependencies))
            except:
                continue
        
        # Create subplot
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
        
        # File size distribution
        ax1.hist(file_sizes, bins=20, color='lightblue', alpha=0.7)
        ax1.set_title('File Size Distribution (bytes)')
        ax1.set_xlabel('File Size')
        ax1.set_ylabel('Count')
        
        # Symbols per file
        ax2.hist(symbol_counts, bins=20, color='lightgreen', alpha=0.7)
        ax2.set_title('Symbols per File Distribution')
        ax2.set_xlabel('Number of Symbols')
        ax2.set_ylabel('Count')
        
        # Dependencies per file
        ax3.hist(dependency_counts, bins=20, color='lightyellow', alpha=0.7)
        ax3.set_title('Dependencies per File Distribution')
        ax3.set_xlabel('Number of Dependencies')
        ax3.set_ylabel('Count')
        
        # Symbol type distribution
        symbol_types = {}
        for symbols in self.project_analyzer.symbol_table.values():
            for symbol in symbols:
                symbol_types[symbol.symbol_type] = symbol_types.get(symbol.symbol_type, 0) + 1
        
        ax4.bar(symbol_types.keys(), symbol_types.values(), color='lightcoral')
        ax4.set_title('Symbol Type Distribution')
        ax4.set_xlabel('Symbol Type')
        ax4.set_ylabel('Count')
        ax4.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig(viz_dir / 'project_metrics.png', dpi=300, bbox_inches='tight')
        plt.close()
    
    def _plot_dependency_graph(self, viz_dir: Path) -> None:
        """Plot dependency graph visualization"""
        try:
            import networkx as nx
            
            # Create directed graph
            G = nx.DiGraph()
            
            # Add nodes and edges
            for module, deps in self.project_analyzer.dependency_graph.items():
                G.add_node(module)
                for dep in deps:
                    G.add_edge(module, dep)
            
            # Create visualization
            plt.figure(figsize=(16, 12))
            pos = nx.spring_layout(G, k=1, iterations=50)
            
            # Draw nodes
            nx.draw_networkx_nodes(G, pos, node_color='lightblue', 
                                 node_size=1000, alpha=0.7)
            
            # Draw edges
            nx.draw_networkx_edges(G, pos, edge_color='gray', 
                                 arrows=True, arrowsize=20, alpha=0.5)
            
            # Draw labels
            nx.draw_networkx_labels(G, pos, font_size=8, font_weight='bold')
            
            plt.title('Project Dependency Graph', fontsize=16)
            plt.axis('off')
            plt.tight_layout()
            plt.savefig(viz_dir / 'dependency_graph.png', dpi=300, bbox_inches='tight')
            plt.close()
            
        except ImportError:
            logging.warning("NetworkX not available, skipping dependency graph visualization")
    
    def _generate_diff_report(self, results: Dict[str, Any]) -> None:
        """Generate diff report for applied changes"""
        if not results.get('applied'):
            return
        
        diff_report = []
        for suggestion in results['applied']:
            diff_entry = {
                'file': str(suggestion.target_file),
                'suggestion_type': suggestion.suggestion_type.value,
                'line_range': suggestion.line_range,
                'original_code': suggestion.original_code,
                'suggested_code': suggestion.suggested_code,
                'explanation': suggestion.explanation,
                'confidence_score': suggestion.confidence_score
            }
            diff_report.append(diff_entry)
        
        # Save diff report
        diff_path = self.output_dir / "applied_changes.json"
        with open(diff_path, 'w', encoding='utf-8') as f:
            json.dump(diff_report, f, indent=2, default=str)
        
        logging.info(f"Diff report saved to {diff_path}")
    
    # Helper methods for report generation
    def _group_errors_by_code(self) -> Dict[str, int]:
        """Group errors by error code"""
        error_codes = {}
        for ctx in self.error_contexts:
            code = ctx.error_code or 'Unknown'
            error_codes[code] = error_codes.get(code, 0) + 1
        return error_codes
    
    def _group_errors_by_file(self) -> Dict[str, int]:
        """Group errors by file"""
        error_files = {}
        for ctx in self.error_contexts:
            file_path = str(ctx.error_location.file_path)
            error_files[file_path] = error_files.get(file_path, 0) + 1
        return error_files
    
    def _group_suggestions_by_type(self) -> Dict[str, int]:
        """Group suggestions by type"""
        suggestion_types = {}
        for suggestion in self.suggestions:
            stype = suggestion.suggestion_type.value
            suggestion_types[stype] = suggestion_types.get(stype, 0) + 1
        return suggestion_types
    
    def _analyze_confidence_distribution(self) -> Dict[str, int]:
        """Analyze confidence score distribution"""
        distribution = {'low': 0, 'medium': 0, 'high': 0}
        for suggestion in self.suggestions:
            if suggestion.confidence_score < 0.5:
                distribution['low'] += 1
            elif suggestion.confidence_score < 0.8:
                distribution['medium'] += 1
            else:
                distribution['high'] += 1
        return distribution
    
    def _serialize_error_context(self, ctx: ErrorContext) -> Dict[str, Any]:
        """Serialize error context for JSON output"""
        return {
            'error_location': {
                'file_path': str(ctx.error_location.file_path),
                'line': ctx.error_location.line,
                'column': ctx.error_location.column
            },
            'error_code': ctx.error_code,
            'message': ctx.message,
            'surrounding_code': ctx.surrounding_code,
            'affected_symbols': [
                {
                    'name': s.name,
                    'symbol_type': s.symbol_type,
                    'visibility': s.visibility,
                    'location': {
                        'file_path': str(s.location.file_path),
                        'line': s.location.line,
                        'column': s.location.column
                    }
                } for s in ctx.affected_symbols
            ],
            'dependency_chain': ctx.dependency_chain
        }
    
    def _serialize_suggestion(self, suggestion: CodeSuggestion) -> Dict[str, Any]:
        """Serialize suggestion for JSON output"""
        return {
            'suggestion_type': suggestion.suggestion_type.value,
            'target_file': str(suggestion.target_file),
            'line_range': suggestion.line_range,
            'original_code': suggestion.original_code,
            'suggested_code': suggestion.suggested_code,
            'confidence_score': suggestion.confidence_score,
            'explanation': suggestion.explanation,
            'imports_needed': suggestion.imports_needed
        }

def main():
    """Enhanced main function with comprehensive CLI"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Enhanced Rust Error Analyzer with AI-powered suggestions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis
  python enhanced_analyzer.py error.log /path/to/project
  
  # Interactive mode with custom confidence threshold
  python enhanced_analyzer.py error.log /path/to/project --interactive --confidence 0.7
  
  # Batch mode with high confidence only
  python enhanced_analyzer.py error.log /path/to/project --batch --confidence 0.9
  
  # Analysis only (no fixes applied)
  python enhanced_analyzer.py error.log /path/to/project --analyze-only
        """
    )
    
    parser.add_argument('log_file', help='Path to the Rust compiler error log')
    parser.add_argument('project_root', help='Path to the Rust project root directory')
    parser.add_argument('--output-dir', '-o', default='enhanced_output',
                        help='Output directory for reports (default: enhanced_output)')
    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Run in interactive mode (default)')
    parser.add_argument('--batch', '-b', action='store_true',
                        help='Run in batch mode (non-interactive)')
    parser.add_argument('--confidence', '-c', type=float, default=0.8,
                        help='Confidence threshold for batch mode (default: 0.8)')
    parser.add_argument('--analyze-only', action='store_true',
                        help='Only analyze errors, do not apply fixes')
    parser.add_argument('--no-ai', action='store_true',
                        help='Disable AI-powered suggestions')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("enhanced_analyzer.log"),
            logging.StreamHandler()
        ]
    )
    
    # Validate inputs
    if not os.path.exists(args.log_file):
        logging.error(f"Log file not found: {args.log_file}")
        return 1
    
    if not os.path.exists(args.project_root):
        logging.error(f"Project root not found: {args.project_root}")
        return 1
    
    # Disable AI if requested or if no API key
    if args.no_ai:
        global api_key
        api_key = None
        logging.info("AI suggestions disabled by user request")
    
    try:
        # Create analyzer
        analyzer = EnhancedRustErrorAnalyzer(
            log_file=args.log_file,
            project_root=args.project_root,
            output_dir=args.output_dir
        )
        
        if args.analyze_only:
            # Analysis only mode
            logging.info("Running in analysis-only mode")
            analyzer.project_analyzer.analyze_project()
            analyzer._parse_enhanced_error_log()
            analyzer._generate_all_suggestions()
            
            # Generate reports without applying fixes
            results = {
                'applied': [],
                'skipped': analyzer.suggestions,
                'failed': [],
                'total_suggestions': len(analyzer.suggestions)
            }
            analyzer._generate_enhanced_reports(results)
            
            print(f"\nAnalysis complete!")
            print(f"Found {len(analyzer.error_contexts)} errors")
            print(f"Generated {len(analyzer.suggestions)} suggestions")
            print(f"Reports saved to {args.output_dir}")
            
        else:
            # Full analysis and fix mode
            interactive_mode = args.interactive or not args.batch
            results = analyzer.analyze_and_fix(
                interactive=interactive_mode,
                confidence_threshold=args.confidence
            )
            
            # Print summary
            print(f"\n{'='*60}")
            print(f"ENHANCED RUST ERROR ANALYSIS COMPLETE")
            print(f"{'='*60}")
            print(f"Errors found: {len(analyzer.error_contexts)}")
            print(f"Suggestions generated: {len(analyzer.suggestions)}")
            print(f"Fixes applied: {len(results.get('applied', []))}")
            print(f"Fixes skipped: {len(results.get('skipped', []))}")
            print(f"Fixes failed: {len(results.get('failed', []))}")
            print(f"Success rate: {len(results.get('applied', [])) / max(1, len(analyzer.suggestions)) * 100:.1f}%")
            print(f"\nReports saved to: {args.output_dir}")
            print(f"Interactive report: {args.output_dir}/interactive_report.html")
            print(f"JSON report: {args.output_dir}/enhanced_analysis_report.json")
            print(f"Visualizations: {args.output_dir}/visualizations/")
            
            # Suggest next steps
            if results.get('failed'):
                print(f"\n⚠️  Some fixes failed to apply. Check the logs for details.")
            
            if results.get('applied'):
                print(f"\n✅ Successfully applied {len(results['applied'])} fixes!")
                print(f"💡 Run 'cargo check' to verify the fixes work correctly.")
                print(f"💡 Consider running 'cargo test' to ensure no regressions.")
            
            if len(results.get('skipped', [])) > len(results.get('applied', [])):
                print(f"\n💭 Many suggestions were skipped. Consider:")
                print(f"   - Lowering the confidence threshold with --confidence")
                print(f"   - Running in interactive mode to review suggestions manually")
        
        return 0
        
    except KeyboardInterrupt:
        logging.info("Analysis interrupted by user")
        return 1
    except Exception as e:
        logging.error(f"Analysis failed: {e}", exc_info=True)
        return 1

class CLIProgressReporter:
    """Enhanced CLI progress reporting"""
    
    def __init__(self):
        self.current_step = 0
        self.total_steps = 5
        self.step_names = [
            "Analyzing project structure",
            "Parsing error log", 
            "Generating suggestions",
            "Applying fixes",
            "Generating reports"
        ]
    
    def start_step(self, step_name: str):
        """Start a new step"""
        self.current_step += 1
        print(f"\n[{self.current_step}/{self.total_steps}] {step_name}...")
    
    def update_progress(self, message: str):
        """Update progress within current step"""
        print(f"  → {message}")
    
    def complete_step(self, message: str = "Complete"):
        """Complete current step"""
        print(f"  ✅ {message}")

class ConfigManager:
    """Manage configuration for the enhanced analyzer"""
    
    def __init__(self, config_path: str = "analyzer_config.json"):
        self.config_path = config_path
        self.config = self._load_default_config()
        self._load_config()
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration"""
        return {
            "analysis": {
                "max_context_lines": 10,
                "max_suggestions_per_error": 3,
                "confidence_threshold": 0.8,
                "enable_ai_suggestions": True
            },
            "fix_application": {
                "create_backups": True,
                "validate_after_fix": True,
                "max_retries": 3,
                "format_after_fix": True
            },
            "reporting": {
                "generate_html": True,
                "generate_json": True,
                "generate_visualizations": True,
                "include_code_snippets": True
            },
            "ai": {
                "model": "gemini-1.5-flash",
                "max_tokens": 2048,
                "temperature": 0.1,
                "timeout_seconds": 30
            }
        }
    
    def _load_config(self):
        """Load configuration from file if it exists"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                self._merge_config(self.config, user_config)
                logging.info(f"Loaded configuration from {self.config_path}")
            except Exception as e:
                logging.warning(f"Failed to load config file: {e}")
    
    def _merge_config(self, base: Dict, override: Dict):
        """Recursively merge configuration dictionaries"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            logging.info(f"Configuration saved to {self.config_path}")
        except Exception as e:
            logging.error(f"Failed to save config: {e}")
    
    def get(self, key_path: str, default=None):
        """Get configuration value using dot notation"""
        keys = key_path.split('.')
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

class PerformanceProfiler:
    """Profile performance of the analysis process"""
    
    def __init__(self):
        self.timings = {}
        self.memory_usage = {}
        self.start_times = {}
    
    def start_timing(self, operation: str):
        """Start timing an operation"""
        self.start_times[operation] = time.time()
    
    def end_timing(self, operation: str):
        """End timing an operation"""
        if operation in self.start_times:
            duration = time.time() - self.start_times[operation]
            self.timings[operation] = duration
            del self.start_times[operation]
            return duration
        return 0
    
    def record_memory_usage(self, operation: str):
        """Record current memory usage"""
        try:
            import psutil
            process = psutil.Process()
            memory_mb = process.memory_info().rss / 1024 / 1024
            self.memory_usage[operation] = memory_mb
        except ImportError:
            logging.warning("psutil not available for memory profiling")
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get performance report"""
        return {
            "timings": self.timings,
            "memory_usage": self.memory_usage,
            "total_time": sum(self.timings.values()),
            "peak_memory": max(self.memory_usage.values()) if self.memory_usage else 0
        }

# Integration with the original analyzer
class LegacyAnalyzerBridge:
    """Bridge to integrate with the original RustErrorLogAnalyzer"""
    
    def __init__(self, original_analyzer: 'RustErrorLogAnalyzer'):
        self.original = original_analyzer
        self.enhanced = None
    
    def enhance_analysis(self, project_root: str) -> 'EnhancedRustErrorAnalyzer':
        """Enhance the original analyzer with new capabilities"""
        # Create enhanced analyzer
        self.enhanced = EnhancedRustErrorAnalyzer(
            log_file=self.original.log_file,
            project_root=project_root,
            output_dir=self.original.output_dir
        )
        
        # Transfer existing error data
        self._transfer_error_data()
        
        return self.enhanced
    
    def _transfer_error_data(self):
        """Transfer error data from original to enhanced analyzer"""
        # Convert original error format to enhanced format
        for file_path, errors in self.original.errors_by_file.items():
            for error in errors:
                error_context = ErrorContext(
                    error_location=FileLocation(
                        file_path=Path(error['file']),
                        line=int(error['line']),
                        column=int(error.get('column', 0))
                    ),
                    error_code=error.get('code'),
                    message=error['message'],
                    surrounding_code=[],  # Will be populated later
                    affected_symbols=[],  # Will be populated later
                    dependency_chain=[]   # Will be populated later
                )
                self.enhanced.error_contexts.append(error_context)

# Utility functions for the enhanced analyzer
def validate_rust_project(project_root: Path) -> bool:
    """Validate that the given path is a Rust project"""
    cargo_toml = project_root / "Cargo.toml"
    src_dir = project_root / "src"
    
    if not cargo_toml.exists():
        logging.error(f"No Cargo.toml found in {project_root}")
        return False
    
    if not src_dir.exists():
        logging.error(f"No src directory found in {project_root}")
        return False
    
    return True

def setup_environment():
    """Setup the environment for the enhanced analyzer"""
    # Check for required dependencies
    required_packages = ['matplotlib', 'pandas', 'tqdm']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        logging.warning(f"Missing optional packages: {', '.join(missing_packages)}")
        logging.warning("Some features may be limited. Install with: pip install " + " ".join(missing_packages))
    
    # Check for Rust toolchain
    try:
        result = subprocess.run(['rustc', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            logging.info(f"Rust toolchain detected: {result.stdout.strip()}")
        else:
            logging.warning("Rust toolchain not detected")
    except FileNotFoundError:
        logging.warning("Rust toolchain not found in PATH")

def create_sample_config():
    """Create a sample configuration file"""
    config_manager = ConfigManager()
    config_manager.save_config()
    print(f"Sample configuration created: {config_manager.config_path}")
    print("Edit this file to customize the analyzer behavior.")

if __name__ == "__main__":
    # Setup environment
    setup_environment()
    
    # Check for special commands
    if len(sys.argv) > 1 and sys.argv[1] == '--create-config':
        create_sample_config()
        sys.exit(0)
    
    # Run main analysis
    sys.exit(main())