import re
import json
import logging
import os
import threading
import concurrent.futures
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Tuple, Set, Any
import requests
import time
from pathlib import Path
import google.generativeai as genai
import pandas as pd
import matplotlib.pyplot as plt
from tqdm import tqdm
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging with custom formatting
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("./../error.log"),
        logging.StreamHandler()
    ]
)

# Configure Gemini API (requires API key to be set as environment variable)
api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    logging.warning("GEMINI_API_KEY not found in environment variables. Gemini API will not be available.")
else:
    genai.configure(api_key=api_key)

# Cache for Gemini responses to avoid repeated API calls
suggestion_cache = {}
suggestion_cache_lock = threading.Lock()

class RustErrorPattern:
    """Defines patterns for different types of Rust errors"""
    
    # Main error pattern
    MAIN_ERROR = re.compile(
        r"error\[(?P<code>E\d+)\]:\s+(?P<msg>.+?)"
        r"(?=\s+-->\s+|\Z)", 
        re.DOTALL
    )
    # Pattern for file location information
    FILE_LOCATION = re.compile(
        r"-->\s+(?P<file>[\w/\\.-]+):(?P<line>\d+):(?P<col>\d+)"
    )
     # Pattern for errors without a code
    SIMPLE_ERROR = re.compile(
        r"error:\s+(?P<msg>.+?)"
        r"(?=\s+-->\s+|\Z)",
        re.DOTALL
    )
    
    # Pattern for additional help messages
    HELP_MSG = re.compile(r"=\s+(?:help|note):\s+(?P<help_msg>.+?)(?=\n\s*\S+:\d+:\d+|\n\s*=|\Z)", re.DOTALL)
    
    # Pattern for suggested fixes
    SUGGESTION = re.compile(r"=\s+(?:help|note|suggestion):\s+(?P<suggestion>.+?)(?=\n\s*\S+:\d+:\d+|\n\s*=|\Z)", re.DOTALL)
    
    # Pattern for code snippets
    CODE_SNIPPET = re.compile(
        r"\n\s*(?P<line_num>\d+) \|\s+(?P<code>.+?)(?=\n\s*\d+ \||\n\s*\||\Z)",
        re.DOTALL
    )
    
    # Pattern for error pointers
    ERROR_POINTER = re.compile(r"\n\s*\|\s+(?P<pointer>\^+.*)(?=\n|\Z)")

class ErrorCategory:
    """Predefined categories for common Rust errors"""
    
    CATEGORIES = {
        # Type system errors
        "E0308": "Type Mismatch",
        "E0282": "Type Inference",
        "E0277": "Trait Bound",
        "E0038": "Trait Implementation",
        "E0271": "Type Mismatch",
        
        # Ownership errors
        "E0382": "Ownership",
        "E0505": "Ownership",
        "E0507": "Ownership",
        "E0499": "Ownership",
        
        # Borrowing errors
        "E0502": "Borrowing",
        "E0503": "Borrowing",
        "E0506": "Borrowing",
        
        # Lifetime errors
        "E0106": "Lifetime",
        "E0495": "Lifetime",
        "E0310": "Lifetime",
        
        # Module system errors
        "E0433": "Module System",
        "E0412": "Module System",
        "E0432": "Module System",
        
        # Macro errors
        "E0658": "Macro",
        "E0424": "Macro",
        
        # Pattern matching errors
        "E0004": "Pattern Matching",
        "E0005": "Pattern Matching",
        "E0008": "Pattern Matching",
        
        # Undefined/missing items
        "E0425": "Undefined Item",
        "E0422": "Undefined Item",
        "E0603": "Privacy Violation",
        "E0407": "Missing Item",
        
        # Syntax errors
        "E0423": "Syntax",
        "E0658": "Syntax",
        
        # Constant evaluation
        "E0080": "Constant Evaluation",
        "E0133": "Constant Evaluation",
        
        # Miscellaneous
        "E0601": "Main Function",
        "E0428": "Duplicate Definition",
        "E0408": "Variable Shadowing",
    }
    
    @classmethod
    def get(cls, error_code: str) -> str:
        """Get the category for an error code"""
        return cls.CATEGORIES.get(error_code, "General")
    
    @classmethod
    def get_all_categories(cls) -> Set[str]:
        """Get all available categories"""
        return set(cls.CATEGORIES.values())

# Add this class before the GeminiClient class
class RustErrorLogAnalyzer:
    def __init__(self):
        self.errors = []
        self.warnings = []
        
    def parse_log(self, log_content):
        # Basic implementation to parse Rust compiler errors
        lines = log_content.split('\n')
        # Process the lines to extract errors and warnings
        # This is a simplified implementation
        for i, line in enumerate(lines):
            if 'error' in line.lower():
                self.errors.append(line)
            elif 'warning' in line.lower():
                self.warnings.append(line)
        return self.errors, self.warnings
    
    def get_errors(self):
        return self.errors
    
    def get_warnings(self):
        return self.warnings

class GeminiClient:
    def __init__(self, analyzer: RustErrorLogAnalyzer):
        """Initialize the Gemini client"""
        self.models = {}
        try:
            self.models["gemini-2.5-flash"] = genai.GenerativeModel("gemini-1.5-flash")
            logging.info("Gemini API initialized successfully")
        except Exception as e:
            logging.error(f"Failed to initialize Gemini API: {e}")
    
    def get_suggestion(self, error_code: Optional[str], error_message: str, 
                       code_snippet: Optional[str] = None) -> str:
        """Get a suggestion for fixing a Rust error"""
        cache_key = f"{error_code}:{error_message[:100]}"
        
        with suggestion_cache_lock:
            if cache_key in suggestion_cache:
                return suggestion_cache[cache_key]
        
        if not self.models.get("gemini-1.5-flash"):
            return "AI suggestion unavailable. Check your Gemini API key."
        
        # Build a detailed prompt for better results
        prompt_parts = [
            "As a Rust expert, help fix this compiler error:\n\n",
            f"Error code: {error_code or 'Unknown'}\n",
            f"Error message: {error_message}\n",
        ]
        
        if code_snippet:
            prompt_parts.append(f"Code context:\n```rust\n{code_snippet}\n```\n")
            
        prompt_parts.append("Provide a clear, specific solution that addresses the root cause. Include a code example if possible.")
        
        prompt = "".join(prompt_parts)
        
        try:
            response = self.models["gemini-1.5-flash"].generate_content(prompt)
            suggestion = response.text.strip()
            
            # Cache the response
            with suggestion_cache_lock:
                suggestion_cache[cache_key] = suggestion
                
            return suggestion
        except Exception as e:
            logging.error(f"Error getting Gemini suggestion: {e}")
            return f"AI suggestion unavailable: {str(e)}"

class RustErrorLogAnalyzer:
    """Advanced analyzer for Rust compiler error logs"""
    
    def __init__(self, log_file: str, output_dir: str = "output", 
                 max_workers: int = 4, use_ai: bool = True):
        """
        Initialize the analyzer
        
        Args:
            log_file: Path to the Rust error log file
            output_dir: Directory to save output files
            max_workers: Maximum number of worker threads for parallel processing
            use_ai: Whether to use AI for suggestions
        """
        self.log_file = log_file
        self.output_dir = output_dir
        self.max_workers = max_workers
        self.use_ai = use_ai
        
        # Collections for different views of the errors
        self.errors_by_file = defaultdict(list)
        self.errors_by_type = defaultdict(list)
        self.errors_by_category = defaultdict(list)
        self.errors_by_severity = defaultdict(list)
        self.error_count = 0
        self.warning_count = 0
        self.note_count = 0
        
        # In the RustErrorLogAnalyzer.__init__ method, around line 254
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize Gemini client if AI is enabled
        self.gemini = GeminiClient(self) if use_ai else None
        
        # Performance metrics
        self.start_time = 0
        self.end_time = 0
        
    def parse_log(self) -> None:
        """Parse the log file and extract errors"""
        logging.info(f"Starting to parse log file: {self.log_file}")
        self.start_time = time.time()
        
        try:
            # Read the entire log file
            with open(self.log_file, 'r', encoding='utf-8') as file:
                log_content = file.read()
            
            # Extract all errors
            all_errors = self._extract_errors(log_content)
            total_errors = len(all_errors)
            logging.info(f"Found {total_errors} error entries in the log")
            
            # Process errors in parallel if there are many
            if total_errors > 10 and self.max_workers > 1:
                self._process_errors_parallel(all_errors)
            else:
                self._process_errors_sequential(all_errors)
                
            self.end_time = time.time()
            duration = self.end_time - self.start_time
            logging.info(f"Log parsing completed in {duration:.2f} seconds")
            
        except Exception as e:
            logging.error(f"Error reading or parsing log file: {e}", exc_info=True)
    
    def _extract_errors(self, log_content: str) -> List[Dict[str, Any]]:
        """
        Extract all errors from the log content
        
        Args:
            log_content: The content of the log file
            
        Returns:
            List of dictionaries containing error information
        """
        all_errors = []
        
        # Find all errors with error codes
        for match in RustErrorPattern.MAIN_ERROR.finditer(log_content):
            error_dict = match.groupdict()
            error_dict['_match_start'] = match.start()
            error_dict['_match_end'] = match.end()
            
            # Find the file location that follows this error
            start_pos = match.end()
            end_pos = min(start_pos + 500, len(log_content))  # Look ahead a reasonable amount
            file_match = RustErrorPattern.FILE_LOCATION.search(log_content, start_pos, end_pos)
            if file_match:
                error_dict.update(file_match.groupdict())
            
            error_dict['level'] = 'error'
            all_errors.append(error_dict)
        
        # Find all errors without error codes
        for match in RustErrorPattern.SIMPLE_ERROR.finditer(log_content):
            # Skip if this position is already covered by a main error
            if any(match.start() >= e.get('_match_start', 0) and 
                match.end() <= e.get('_match_end', float('inf')) 
                for e in all_errors):
                continue
                
            error_dict = match.groupdict()
            error_dict['code'] = None
            error_dict['level'] = 'error'
            error_dict['_match_start'] = match.start()
            error_dict['_match_end'] = match.end()
            
            # Find the file location that follows this error
            start_pos = match.end()
            end_pos = min(start_pos + 500, len(log_content))  # Look ahead a reasonable amount
            file_match = RustErrorPattern.FILE_LOCATION.search(log_content, start_pos, end_pos)
            if file_match:
                error_dict.update(file_match.groupdict())
                
            all_errors.append(error_dict)
        
        # Extract additional context like help messages, code snippets
        for error in all_errors:
            # Find the section of log content that contains this error's details
            error_start = error['_match_start']
            
            # Find the end of this error section (start of next error or end of file)
            next_error_start = float('inf')
            for e in all_errors:
                if e['_match_start'] > error_start and e['_match_start'] < next_error_start:
                    next_error_start = e['_match_start']
            
            if next_error_start == float('inf'):
                next_error_start = len(log_content)
            
            error_section = log_content[error_start:next_error_start]
            
            # Extract help messages
            help_match = RustErrorPattern.HELP_MSG.search(error_section)
            if help_match:
                error['help_msg'] = help_match.group('help_msg').strip()
            
            # Extract suggestions
            suggestion_match = RustErrorPattern.SUGGESTION.search(error_section)
            if suggestion_match:
                error['rust_suggestion'] = suggestion_match.group('suggestion').strip()
            
            # Extract code snippets
            code_matches = list(RustErrorPattern.CODE_SNIPPET.finditer(error_section))
            if code_matches:
                code_lines = [match.groupdict() for match in code_matches]
                error['code_snippet'] = "\n".join(
                    f"{d['line_num']}: {d['code'].strip()}" for d in code_lines
                )
            
            # Extract error pointers
            pointer_match = RustErrorPattern.ERROR_POINTER.search(error_section)
            if pointer_match:
                error['pointer'] = pointer_match.group('pointer').strip()
            
            # Clean up the main message if needed
            if 'msg' in error:
                error['msg'] = error['msg'].strip()
        
        # Update counts for summary
        self.error_count = len([e for e in all_errors if e['level'] == 'error'])
        self.warning_count = len([e for e in all_errors if e['level'] == 'warning'])
        self.note_count = len([e for e in all_errors if e['level'] == 'note'])
        
        return all_errors
    
    def _process_errors_parallel(self, errors: List[Dict[str, Any]]) -> None:
        """
        Process errors in parallel using a thread pool
        
        Args:
            errors: List of errors to process
        """
        logging.info(f"Processing {len(errors)} errors in parallel with {self.max_workers} workers")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all error processing tasks
            futures = [executor.submit(self._process_single_error, error) for error in errors]
            
            # Create a progress bar
            with tqdm(total=len(futures), desc="Processing errors") as pbar:
                # Process completed futures as they finish
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            file_path, error_code, category, level = result
                            # No need to lock since defaultdict is thread-safe for reading
                            logging.debug(f"Processed error: {file_path} - {error_code}")
                    except Exception as e:
                        logging.error(f"Error in parallel processing: {e}")
                    finally:
                        pbar.update(1)
    
    def _process_errors_sequential(self, errors: List[Dict[str, Any]]) -> None:
        """
        Process errors sequentially
        
        Args:
            errors: List of errors to process
        """
        logging.info(f"Processing {len(errors)} errors sequentially")
        
        for error in tqdm(errors, desc="Processing errors"):
            self._process_single_error(error)
    
    def _process_single_error(self, error: Dict[str, Any]) -> Optional[Tuple[str, str, str, str]]:
        """
        Process a single error and update the appropriate collections
        
        Args:
            error: The error to process
            
        Returns:
            A tuple of (file_path, error_code, category, level) if successful
        """
        try:
            file_path = error['file']
            line_number = error['line']
            error_code = error.get('code') or 'Unknown'
            message = error['msg']
            level = error['level']
            category = ErrorCategory.get(error_code)
            
            # Get AI suggestion if enabled
            suggestion = ""
            if self.use_ai and level == 'error':
                code_snippet = error.get('code_snippet', '')
                suggestion = self.gemini.get_suggestion(error_code, message, code_snippet)
            elif error.get('rust_suggestion'):
                suggestion = f"Rust suggests: {error['rust_suggestion']}"
            
            error_entry = {
                'file': file_path,
                'line': line_number,
                'column': error.get('col', '0'),
                'level': level,
                'code': error_code,
                'message': message,
                'help': error.get('help_msg', ''),
                'rust_suggestion': error.get('rust_suggestion', ''),
                'code_snippet': error.get('code_snippet', ''),
                'ai_suggestion': suggestion
            }
            
            # Update all collections
            self.errors_by_file[file_path].append(error_entry)
            self.errors_by_type[error_code].append(error_entry)
            self.errors_by_category[category].append(error_entry)
            self.errors_by_severity[level].append(error_entry)
            
            return file_path, error_code, category, level
            
        except Exception as e:
            logging.error(f"Error processing error entry: {e}", exc_info=True)
            return None
    
    def get_rust_doc_link(self, error_code: str) -> str:
        """
        Get a link to the Rust documentation for an error code
        
        Args:
            error_code: The error code to look up
            
        Returns:
            URL to the Rust documentation for the error code
        """
        if error_code == "Unknown" or not error_code or not error_code.startswith('E'):
            return ""
        
        return f"https://doc.rust-lang.org/error_codes/{error_code}.html"
    
    def save_json_report(self, output_file: str = "error_report.json") -> None:
        """
        Save the error report to a JSON file
        
        Args:
            output_file: The name of the output file
        """
        output_path = os.path.join(self.output_dir, output_file)
        
        report = {
            "summary": {
                "total_errors": self.error_count,
                "total_warnings": self.warning_count,
                "total_notes": self.note_count,
                "files_with_errors": len(self.errors_by_file),
                "unique_error_types": len(self.errors_by_type),
                "error_categories": {
                    category: len(errors) 
                    for category, errors in self.errors_by_category.items()
                },
                "processing_time_seconds": self.end_time - self.start_time
            },
            "errors_by_file": dict(self.errors_by_file),
            "errors_by_type": dict(self.errors_by_type),
            "errors_by_category": dict(self.errors_by_category),
            "errors_by_severity": dict(self.errors_by_severity)
        }
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            logging.info(f"Error report saved to {output_path}")
        except Exception as e:
            logging.error(f"Failed to save JSON report: {e}")
    
    def save_html_report(self, output_file: str = "error_report.html") -> None:
        """
        Save the error report as an HTML file
        
        Args:
            output_file: The name of the output file
        """
        output_path = os.path.join(self.output_dir, output_file)
        
        try:
            # Create basic HTML structure
            html_content = [
                "<!DOCTYPE html>",
                "<html lang='en'>",
                "<head>",
                "  <meta charset='UTF-8'>",
                "  <meta name='viewport' content='width=device-width, initial-scale=1.0'>",
                "  <title>Rust Error Analysis Report</title>",
                "  <style>",
                "    body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }",
                "    h1, h2, h3 { color: #333; }",
                "    .container { max-width: 1200px; margin: 0 auto; }",
                "    .summary { background-color: #f8f9fa; border-radius: 5px; padding: 15px; margin-bottom: 20px; }",
                "    .error { background-color: #fff; border-left: 4px solid #dc3545; padding: 10px; margin-bottom: 10px; }",
                "    .warning { background-color: #fff; border-left: 4px solid #ffc107; padding: 10px; margin-bottom: 10px; }",
                "    .note { background-color: #fff; border-left: 4px solid #17a2b8; padding: 10px; margin-bottom: 10px; }",
                "    .suggestion { background-color: #f8f9fa; border-radius: 5px; padding: 10px; margin-top: 10px; }",
                "    code { font-family: 'Courier New', monospace; background-color: #f8f9fa; padding: 2px 4px; border-radius: 3px; }",
                "    pre { background-color: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }",
                "    .tabs { display: flex; border-bottom: 1px solid #dee2e6; margin-bottom: 15px; }",
                "    .tab { padding: 10px 15px; cursor: pointer; }",
                "    .tab.active { border-bottom: 2px solid #007bff; color: #007bff; }",
                "    .tab-content { display: none; }",
                "    .tab-content.active { display: block; }",
                "    .chart { width: 100%; height: 300px; margin: 20px 0; }",
                "  </style>",
                "</head>",
                "<body>",
                "  <div class='container'>",
                f"    <h1>Rust Error Analysis Report</h1>",
                f"    <p>Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}</p>"
            ]
            
            # Add summary section
            html_content.extend([
                "    <div class='summary'>",
                "      <h2>Summary</h2>",
                f"      <p><strong>Total Errors:</strong> {self.error_count}</p>",
                f"      <p><strong>Total Warnings:</strong> {self.warning_count}</p>",
                f"      <p><strong>Total Notes:</strong> {self.note_count}</p>",
                f"      <p><strong>Files with Issues:</strong> {len(self.errors_by_file)}</p>",
                f"      <p><strong>Unique Error Types:</strong> {len(self.errors_by_type)}</p>",
                "    </div>"
            ])
            
            # Add tabs for different views
            html_content.extend([
                "    <div class='tabs'>",
                "      <div class='tab active' onclick='switchTab(\"files\")'>By File</div>",
                "      <div class='tab' onclick='switchTab(\"types\")'>By Error Type</div>",
                "      <div class='tab' onclick='switchTab(\"categories\")'>By Category</div>",
                "    </div>"
            ])
            
            # Add file view
            html_content.append("    <div id='files' class='tab-content active'>")
            html_content.append("      <h2>Errors by File</h2>")
            
            for file_path, errors in self.errors_by_file.items():
                html_content.append(f"      <h3>{file_path} ({len(errors)} issues)</h3>")
                for err in errors:
                    level_class = "error" if err['level'] == 'error' else ("warning" if err['level'] == 'warning' else "note")
                    html_content.append(f"      <div class='{level_class}'>")
                    html_content.append(f"        <p><strong>Line {err['line']}:{err['column']}</strong> - {err['level'].upper()}")
                    if err['code'] != "Unknown":
                        doc_link = self.get_rust_doc_link(err['code'])
                        html_content.append(f" [{err['code']}]")
                        if doc_link:
                            html_content.append(f" <a href='{doc_link}' target='_blank'>(Rust Docs)</a>")
                    html_content.append("</p>")
                    html_content.append(f"        <p>{err['message']}</p>")
                    
                    if err.get('code_snippet'):
                        html_content.append("        <pre><code>")
                        html_content.append(err['code_snippet'].replace("<", "&lt;").replace(">", "&gt;"))
                        html_content.append("</code></pre>")
                    
                    if err.get('help'):
                        html_content.append(f"        <p><em>Help: {err['help']}</em></p>")
                    
                    if err.get('rust_suggestion'):
                        html_content.append(f"        <div class='suggestion'><strong>Rust suggests:</strong> {err['rust_suggestion']}</div>")
                    
                    if err.get('ai_suggestion'):
                        html_content.append(f"        <div class='suggestion'><strong>AI suggests:</strong> {err['ai_suggestion']}</div>")
                    
                    html_content.append("      </div>")
            
            html_content.append("    </div>")
            
            # Add type view
            html_content.append("    <div id='types' class='tab-content'>")
            html_content.append("      <h2>Errors by Type</h2>")
            
            for error_code, errors in self.errors_by_type.items():
                doc_link = self.get_rust_doc_link(error_code)
                html_content.append(f"      <h3>Error [{error_code}]")
                if doc_link:
                    html_content.append(f" <a href='{doc_link}' target='_blank'>(Rust Docs)</a>")
                html_content.append(f" - {len(errors)} occurrences</h3>")
                
                for err in errors:
                    level_class = "error" if err['level'] == 'error' else ("warning" if err['level'] == 'warning' else "note")
                    html_content.append(f"      <div class='{level_class}'>")
                    html_content.append(f"        <p><strong>{err['file']}:{err['line']}</strong> - {err['level'].upper()}</p>")
                    html_content.append(f"        <p>{err['message']}</p>")
                    
                    # Include other details as in the file view
                    if err.get('code_snippet'):
                        html_content.append("        <pre><code>")
                        html_content.append(err['code_snippet'].replace("<", "&lt;").replace(">", "&gt;"))
                        html_content.append("</code></pre>")
                    
                    if err.get('ai_suggestion'):
                        html_content.append(f"        <div class='suggestion'><strong>AI suggests:</strong> {err['ai_suggestion']}</div>")
                    
                    html_content.append("      </div>")
            
            html_content.append("    </div>")
            
            # Add category view
            html_content.append("    <div id='categories' class='tab-content'>")
            html_content.append("      <h2>Errors by Category</h2>")
            
            for category, errors in self.errors_by_category.items():
                html_content.append(f"      <h3>{category} ({len(errors)} issues)</h3>")
                
                for err in errors:
                    level_class = "error" if err['level'] == 'error' else ("warning" if err['level'] == 'warning' else "note")
                    html_content.append(f"      <div class='{level_class}'>")
                    html_content.append(f"        <p><strong>{err['file']}:{err['line']}</strong> - {err['level'].upper()}")
                    if err['code'] != "Unknown":
                        html_content.append(f" [{err['code']}]")
                    html_content.append("</p>")
                    html_content.append(f"        <p>{err['message']}</p>")
                    
                    if err.get('ai_suggestion'):
                        html_content.append(f"        <div class='suggestion'><strong>Solution:</strong> {err['ai_suggestion']}</div>")
                    
                    html_content.append("      </div>")
            
            html_content.append("    </div>")
            
            # Add JavaScript for tab switching
            html_content.extend([
                "  </div>",
                "  <script>",
                "    function switchTab(tabId) {",
                "      // Hide all tabs",
                "      document.querySelectorAll('.tab-content').forEach(tab => {",
                "        tab.classList.remove('active');",
                "      });",
                "      document.querySelectorAll('.tab').forEach(tab => {",
                "        tab.classList.remove('active');",
                "      });",
                "",
                "      // Show selected tab",
                "      document.getElementById(tabId).classList.add('active');",
                "      document.querySelector(`.tab[onclick=\"switchTab('${tabId}')\"]`).classList.add('active');",
                "    }",
                "  </script>",
                "</body>",
                "</html>"
            ])
            
            # Write the HTML to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(html_content))
                
            logging.info(f"HTML report saved to {output_path}")
            
        except Exception as e:
            logging.error(f"Failed to save HTML report: {e}")
    
    def generate_visualizations(self) -> None:
        """Generate visualizations of the error data"""
        try:
            # Create directory for visualizations
            viz_dir = os.path.join(self.output_dir, "visualizations")
            os.makedirs(viz_dir, exist_ok=True)
            
            # 1. Error count by category
            self._plot_error_by_category(viz_dir)
            
            # 2. Error count by file
            self._plot_error_by_file(viz_dir)
            
            # 3. Error type distribution
            self._plot_error_by_type(viz_dir)
            
            logging.info(f"Visualizations saved to {viz_dir}")
            
        except Exception as e:
            logging.error(f"Error generating visualizations: {e}")
    
    def _plot_error_by_category(self, viz_dir: str) -> None:
        """
        Plot errors by category
        
        Args:
            viz_dir: Directory to save the plot
        """
        plt.figure(figsize=(10, 6))
        categories = list(self.errors_by_category.keys())
        counts = [len(errors) for errors in self.errors_by_category.values()]
    
        # Sort by count
        sorted_data = sorted(zip(categories, counts), key=lambda x: x[1], reverse=True)
        categories = [item[0] for item in sorted_data]
        counts = [item[1] for item in sorted_data]        
                # Plot
        bars = plt.bar(categories, counts, color='skyblue')
        plt.title('Error Count by Category', fontsize=15)
        plt.xlabel('Category', fontsize=12)
        plt.ylabel('Number of Errors', fontsize=12)
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        # Add count labels on top of bars
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    f'{height:.0f}', ha='center', va='bottom')
        
        # Save the plot
        plt.savefig(os.path.join(viz_dir, 'errors_by_category.png'), dpi=300)
        plt.close()
    
    def _plot_error_by_file(self, viz_dir: str) -> None:
        """
        Plot errors by file
        
        Args:
            viz_dir: Directory to save the plot
        """
        plt.figure(figsize=(12, 8))
        
        # Get top 15 files by error count
        files = list(self.errors_by_file.keys())
        counts = [len(errors) for errors in self.errors_by_file.values()]
        
        # Sort by count and take top 15
        sorted_data = sorted(zip(files, counts), key=lambda x: x[1], reverse=True)
        if len(sorted_data) > 15:
            sorted_data = sorted_data[:15]
            
        files = [os.path.basename(item[0]) for item in sorted_data]  # Use basename for cleaner display
        counts = [item[1] for item in sorted_data]
        
        # Plot horizontal bar chart for better readability with long filenames
        bars = plt.barh(files, counts, color='lightgreen')
        plt.title('Top Files by Error Count', fontsize=15)
        plt.xlabel('Number of Errors', fontsize=12)
        plt.ylabel('File Name', fontsize=12)
        plt.tight_layout()
        
        # Add count labels
        for bar in bars:
            width = bar.get_width()
            plt.text(width + 0.3, bar.get_y() + bar.get_height()/2.,
                    f'{width:.0f}', ha='left', va='center')
        
        # Save the plot
        plt.savefig(os.path.join(viz_dir, 'errors_by_file.png'), dpi=300)
        plt.close()
    
    def _plot_error_by_type(self, viz_dir: str) -> None:
        """
        Plot errors by error type/code
        
        Args:
            viz_dir: Directory to save the plot
        """
        plt.figure(figsize=(10, 8))
        
        # Get top 10 error types
        error_types = list(self.errors_by_type.keys())
        counts = [len(errors) for errors in self.errors_by_type.values()]
        
        # Sort by count and take top 10
        sorted_data = sorted(zip(error_types, counts), key=lambda x: x[1], reverse=True)
        if len(sorted_data) > 10:
            sorted_data = sorted_data[:10]
            
        error_types = [item[0] for item in sorted_data]
        counts = [item[1] for item in sorted_data]
        
        # Create pie chart
        plt.pie(counts, labels=error_types, autopct='%1.1f%%', 
                startangle=90, shadow=True, explode=[0.05] * len(counts))
        plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
        plt.title('Distribution of Error Types', fontsize=15)
        plt.tight_layout()
        
        # Save the plot
        plt.savefig(os.path.join(viz_dir, 'errors_by_type.png'), dpi=300)
        plt.close()
        
        # Also create a bar chart for error severity
        self._plot_error_by_severity(viz_dir)
    
    def _plot_error_by_severity(self, viz_dir: str) -> None:
        """
        Plot errors by severity level
        
        Args:
            viz_dir: Directory to save the plot
        """
        plt.figure(figsize=(8, 6))
        
        # Get severity counts
        severities = ['error', 'warning', 'note']
        counts = [len(self.errors_by_severity.get(sev, [])) for sev in severities]
        
        # Define colors for each severity
        colors = ['#dc3545', '#ffc107', '#17a2b8']
        
        # Plot
        bars = plt.bar(severities, counts, color=colors)
        plt.title('Issues by Severity Level', fontsize=15)
        plt.xlabel('Severity', fontsize=12)
        plt.ylabel('Count', fontsize=12)
        
        # Add count labels
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    f'{height:.0f}', ha='center', va='bottom')
        
        # Save the plot
        plt.savefig(os.path.join(viz_dir, 'errors_by_severity.png'), dpi=300)
        plt.close()


def main():
    """Main entry point for the Rust error analyzer"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze Rust compiler error logs')
    parser.add_argument('log_file', help='Path to the Rust error log file')
    parser.add_argument('--output-dir', '-o', default='output', 
                        help='Directory to save output files (default: output)')
    parser.add_argument('--workers', '-w', type=int, default=4,
                        help='Number of worker threads for parallel processing (default: 4)')
    parser.add_argument('--no-ai', action='store_true',
                        help='Disable AI-powered suggestions')
    parser.add_argument('--no-viz', action='store_true',
                        help='Skip generating visualizations')
    
    args = parser.parse_args()
    
    # Create analyzer
    analyzer = RustErrorLogAnalyzer(
        log_file=args.log_file,
        output_dir=args.output_dir,
        max_workers=args.workers,
        use_ai=not args.no_ai
    )
    
    # Parse log and generate reports
    analyzer.parse_log()
    analyzer.save_json_report()
    analyzer.save_html_report()
    
    # Generate visualizations if not disabled
    if not args.no_viz:
        analyzer.generate_visualizations()
    
    print(f"Analysis complete. Reports saved to {args.output_dir}")


if __name__ == "__main__":
    main()