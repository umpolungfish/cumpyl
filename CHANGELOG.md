# Changelog

All notable changes to the Cumpyl framework will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - 2025-08-21

### Added
- **Interactive Terminal Hex Viewer**: Complete TUI-based hex viewer using Textual framework
  - Vim-like navigation controls (j/k/g/G for scrolling)
  - Real-time search functionality for hex bytes and strings with n/N navigation
  - Color-coded annotations showing sections (blue), strings (green), entropy (yellow), and obfuscation suggestions (red)
  - Live annotation information display with 'a' command
  - Performance-optimized rendering with configurable display limits
  - Integration with existing analysis plugins and obfuscation suggestion system
- Added Textual framework dependency to requirements.in
- Extended HexViewer class with textual display methods and navigation state tracking
- New InteractiveHexViewerApp with complete keyboard binding system
- HexSearchDialog modal interface for hex/string search operations
- Enhanced menu system integration for seamless TUI hex viewer launching

### Changed
- Updated interactive menu system to include Terminal hex viewer as option 3
- Enhanced hex viewer menu with dual-mode options (Terminal TUI + HTML)
- Updated documentation (README.md, CLAUDE.md) to highlight new TUI capabilities
- Improved hex viewer architecture to support both HTML and terminal output modes

## [0.3.1] - 2025-08-19

### Fixed
- Fixed syntax error in `menu_system.py` where a docstring had a stray backslash
- Fixed escaped quote issues throughout `menu_system.py` that were causing syntax errors
- Fixed import issues in `cumpyl.py` where `ReportGenerator` was referenced before assignment due to local variable naming conflicts
- Fixed filename generation issue where output files were named with full paths instead of just the basename
- Fixed hex viewer interactive mode to properly require both `--hex-view` and `--hex-view-interactive` flags

### Changed
- Updated menu system to correctly generate commands for hex viewer interactive mode
- Improved error handling and code structure in the main cumpyl.py file
- Enhanced batch processing to work correctly with analyze_sections operation

## [0.3.0] - 2025-08-18

### Added
- Complete architectural transformation with advanced configuration system
- YAML-based configuration with predefined analysis profiles (malware_analysis, forensics, research)
- Enterprise plugin architecture with dynamic plugin discovery
- Structured reporting system with multi-format output (JSON, YAML, XML, HTML)
- Batch processing engine with multi-threaded processing capabilities
- Comprehensive testing framework with unit and integration tests
- Interactive hex viewer with browser-based interface and hover tooltips
- Rich console interface with color-coded output and progress indicators

### Changed
- Complete rewrite of the framework from a simple encoding tool to a comprehensive binary analysis platform
- Improved plugin system with standardized interfaces and dependency management
- Enhanced reporting capabilities with metadata enrichment and batch reporting
- Upgraded batch processing with directory crawling and operation chaining
- Modernized development setup with uv package manager support

[Unreleased]: https://github.com/umpolungfish/cumpyl/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/umpolungfish/cumpyl/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/umpolungfish/cumpyl/releases/tag/v0.3.0