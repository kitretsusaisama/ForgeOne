#!/usr/bin/env python3
"""
Directory Tree Walker - Production Ready Version

A robust tool for visualizing directory structures with file details.
Supports filtering, depth limits, and various output formats.
"""

import os
import sys
import argparse
import logging
from pathlib import Path
from typing import Optional, Set, List, Tuple
from dataclasses import dataclass


@dataclass
class Config:
    """Configuration for the directory walker."""
    max_depth: Optional[int] = None
    show_hidden: bool = False
    show_size: bool = True
    show_lines: bool = True
    exclude_patterns: Set[str] = None
    include_patterns: Set[str] = None
    follow_symlinks: bool = False
    output_file: Optional[str] = None
    
    def __post_init__(self):
        if self.exclude_patterns is None:
            self.exclude_patterns = {'.git', '__pycache__', '.pytest_cache', 'node_modules', '.DS_Store'}
        if self.include_patterns is None:
            self.include_patterns = set()


class DirectoryWalker:
    """Production-ready directory tree walker with comprehensive error handling."""
    
    def __init__(self, config: Config):
        self.config = config
        self.logger = self._setup_logger()
        self.stats = {'dirs': 0, 'files': 0, 'errors': 0}
        self.output_file = None
        self._setup_output_file()
    
    def _setup_logger(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            formatter = logging.Formatter('%(levelname)s: %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _setup_output_file(self) -> None:
        """Set up output file if specified."""
        if self.config.output_file:
            try:
                self.output_file = open(self.config.output_file, 'w', encoding='utf-8')
                self.logger.info(f"Output will be written to: {self.config.output_file}")
            except (OSError, IOError) as e:
                self.logger.error(f"Cannot open output file {self.config.output_file}: {e}")
                sys.exit(1)
    
    def _print(self, message: str) -> None:
        """Print message to stdout and/or output file."""
        print(message)
        if self.output_file:
            self.output_file.write(message + '\n')
            self.output_file.flush()  # Ensure immediate write
    
    def _close_output_file(self) -> None:
        """Close output file if open."""
        if self.output_file:
            self.output_file.close()
            self.logger.info(f"Output written to: {self.config.output_file}")
    
    def _should_skip_item(self, name: str, path: Path) -> bool:
        """Determine if an item should be skipped based on configuration."""
        # Skip hidden files/directories if not configured to show them
        if not self.config.show_hidden and name.startswith('.'):
            return True
        
        # Skip excluded patterns
        if name in self.config.exclude_patterns:
            return True
        
        # If include patterns are specified, only include matching items
        if self.config.include_patterns:
            return not any(pattern in name for pattern in self.config.include_patterns)
        
        return False
    
    def _get_file_details(self, path: Path) -> str:
        """Get file size and line count with proper error handling."""
        details = []
        
        try:
            if self.config.show_size:
                size = path.stat().st_size
                details.append(self._format_size(size))
            
            if self.config.show_lines and path.is_file():
                lines = self._count_lines(path)
                if lines is not None:
                    details.append(f"{lines} lines")
            
        except (OSError, IOError) as e:
            self.logger.warning(f"Cannot access {path}: {e}")
            self.stats['errors'] += 1
            return "N/A"
        
        return ", ".join(details) if details else "N/A"
    
    def _format_size(self, size: int) -> str:
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f}{unit}" if unit != 'B' else f"{size}B"
            size /= 1024.0
        return f"{size:.1f}PB"
    
    def _count_lines(self, path: Path) -> Optional[int]:
        """Count lines in a text file with proper encoding handling."""
        try:
            # Try different encodings
            encodings = ['utf-8', 'latin-1', 'cp1252', 'ascii']
            
            for encoding in encodings:
                try:
                    with open(path, 'r', encoding=encoding, errors='ignore') as f:
                        return sum(1 for _ in f)
                except UnicodeDecodeError:
                    continue
            
            # If all encodings fail, try binary mode
            with open(path, 'rb') as f:
                return sum(1 for _ in f)
                
        except (OSError, IOError, PermissionError):
            return None
    
    def _get_directory_items(self, path: Path) -> List[Tuple[str, Path]]:
        """Get sorted directory items with error handling."""
        try:
            items = []
            for item in path.iterdir():
                if not self._should_skip_item(item.name, item):
                    items.append((item.name, item))
            
            return sorted(items, key=lambda x: (x[1].is_file(), x[0].lower()))
        
        except (OSError, PermissionError) as e:
            self.logger.warning(f"Cannot read directory {path}: {e}")
            self.stats['errors'] += 1
            return []
    
    def walk_directory(self, root: Path, prefix: str = "", depth: int = 0) -> None:
        """Walk directory tree and print structure."""
        # Check depth limit
        if self.config.max_depth is not None and depth > self.config.max_depth:
            return
        
        # Resolve path and check if it exists
        try:
            root = root.resolve()
            if not root.exists():
                self.logger.error(f"Path does not exist: {root}")
                return
            
            if not root.is_dir():
                self.logger.error(f"Path is not a directory: {root}")
                return
                
        except (OSError, RuntimeError) as e:
            self.logger.error(f"Cannot resolve path {root}: {e}")
            return
        
        # Get directory items
        items = self._get_directory_items(root)
        
        for i, (name, path) in enumerate(items):
            is_last = i == len(items) - 1
            connector = "└── " if is_last else "├── "
            
            try:
                if path.is_dir() and (self.config.follow_symlinks or not path.is_symlink()):
                    self._print(f"{prefix}{connector}[dir] {name}/")
                    self.stats['dirs'] += 1
                    
                    # Recursively walk subdirectory
                    new_prefix = prefix + ("    " if is_last else "│   ")
                    self.walk_directory(path, new_prefix, depth + 1)
                
                elif path.is_file() or (path.is_symlink() and self.config.follow_symlinks):
                    details = self._get_file_details(path)
                    suffix = " -> " + str(path.readlink()) if path.is_symlink() else ""
                    self._print(f"{prefix}{connector}[file] {name} ({details}){suffix}")
                    self.stats['files'] += 1
                
                elif path.is_symlink():
                    target = path.readlink() if path.is_symlink() else ""
                    self._print(f"{prefix}{connector}[symlink] {name} -> {target}")
                
            except (OSError, PermissionError) as e:
                self.logger.warning(f"Cannot access {path}: {e}")
                self._print(f"{prefix}{connector}[error] {name} (access denied)")
                self.stats['errors'] += 1
    
    def print_stats(self) -> None:
        """Print summary statistics."""
        print(f"\nSummary: {self.stats['dirs']} directories, {self.stats['files']} files", file=sys.stderr)
        if self.stats['errors'] > 0:
            print(f"Errors encountered: {self.stats['errors']}", file=sys.stderr)


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="Display directory tree structure with file details",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/directory
  %(prog)s . --max-depth 3 --show-hidden
  %(prog)s src/ --exclude __pycache__ --exclude .git
  %(prog)s . --output tree_output.txt
  %(prog)s /project --output project_structure.txt --stats
        """
    )
    
    parser.add_argument(
        'path',
        nargs='?',
        default='.',
        help='Directory path to walk (default: current directory)'
    )
    
    parser.add_argument(
        '--max-depth',
        type=int,
        metavar='N',
        help='Maximum depth to traverse'
    )
    
    parser.add_argument(
        '--show-hidden',
        action='store_true',
        help='Show hidden files and directories'
    )
    
    parser.add_argument(
        '--no-size',
        action='store_true',
        help='Don\'t show file sizes'
    )
    
    parser.add_argument(
        '--no-lines',
        action='store_true',
        help='Don\'t show line counts'
    )
    
    parser.add_argument(
        '--exclude',
        action='append',
        default=[],
        metavar='PATTERN',
        help='Exclude files/directories matching pattern (can be used multiple times)'
    )
    
    parser.add_argument(
        '--include',
        action='append',
        default=[],
        metavar='PATTERN',
        help='Only include files/directories matching pattern (can be used multiple times)'
    )
    
    parser.add_argument(
        '--follow-symlinks',
        action='store_true',
        help='Follow symbolic links'
    )
    
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress warning messages'
    )
    
    parser.add_argument(
        '--stats',
        action='store_true',
        help='Show summary statistics'
    )
    
    parser.add_argument(
        '-o', '--output',
        metavar='FILE',
        help='Output to file instead of stdout (also displays on screen)'
    )
    
    return parser


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Configure logging
    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)
    
    # Create configuration
    config = Config(
        max_depth=args.max_depth,
        show_hidden=args.show_hidden,
        show_size=not args.no_size,
        show_lines=not args.no_lines,
        exclude_patterns=set(args.exclude) if args.exclude else None,
        include_patterns=set(args.include) if args.include else None,
        follow_symlinks=args.follow_symlinks,
        output_file=args.output
    )
    
    # Create walker and run
    walker = DirectoryWalker(config)
    
    try:
        root_path = Path(args.path)
        walker._print(f"{root_path.resolve()}/")
        walker.walk_directory(root_path)
        
        if args.stats:
            walker.print_stats()
            
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        walker._close_output_file()


if __name__ == "__main__":
    main()

# # Output to file while also showing on screen
# python tree_walker.py . --output tree_structure.txt

# # Short form
# python tree_walker.py . -o directory_tree.txt

# # With additional options
# python tree_walker.py /project --output project_structure.txt --stats --max-depth 3

# # Complex example with filtering
# python tree_walker.py src/ --exclude __pycache__ --exclude .git --output clean_structure.txt