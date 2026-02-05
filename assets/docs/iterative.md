ct a module [1/2/3/h/q] (1): q
Thank you for using Cumpyl Framework!
(cumpyl) [developer@LANDITUDE cumpyl]$ uv run cumpyl.py --start-menu
╭───────────────────────────────────────────────────────────── Welcome ──────────────────────────────────────────────────────────────╮
│                                                                                                                                    │
│  CUMPYL FRAMEWORK v0.3.0                                                                                                           │
│  Advanced Binary Analysis & Rewriting Platform                                                                                     │
│  Modular Menu System                                                                                                               │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭──────────────────────────────────────────────────────── Cumpyl Start Menu ─────────────────────────────────────────────────────────╮
│                                                                                                                                    │
│   1           Build-a-Binary               Binary editor and obfuscator                                                            │
│   2           Lucky Strikes                Binary Packers and compression tools                                                    │
│   3           Silly String                 Payload and string obfuscation tools                                                    │
│   h           Help                         Show detailed help and examples                                                         │
│   q           Quit                         Exit the framework                                                                      │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

Select a module [1/2/3/h/q] (1): 1
╭────────────────────────────────────────────────────────── Build-a-Binary ──────────────────────────────────────────────────────────╮
│                                                                                                                                    │
│  BUILD-A-BINARY MODULE                                                                                                             │
│  Binary Analysis & Obfuscation Tools                                                                                               │
│  Part of Cumpyl Framework                                                                                                          │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🎯 Target File Selection                                                                                                           │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
📁 Found binary files in current directory:
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Index    ┃ File Path                          ┃ Size         ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ 0        │ ilvlmp.exe                         │ 4.3 MB       │
│ 1        │ ca_iter_packed_4_mxpkonlyteerz.exe │ 10.8 MB      │
│ 2        │ ilovelamp.exe                      │ 545.2 KB     │
│ 3        │ mxpkmnogogo.exe                    │ 560.2 KB     │
│ 4        │ ca_iter_packed_2_mxpkonlyteerz.exe │ 2.7 MB       │
│ 5        │ ca_quick_packed_ilvlmp.exe         │ 8.5 MB       │
│ 6        │ c2_communicator.exe                │ 169.4 KB     │
│ 7        │ ilvlmp_iter3.exe                   │ 4.3 MB       │
│ 8        │ not_a_mess.exe                     │ 466.3 KB     │
│ 9        │ monogogo_win_exploit_silent.exe    │ 279.7 KB     │
│ 10       │ gojotb.exe                         │ 10.0 MB      │
│ 11       │ ca_iter_packed_mxpkonlyteerz.exe   │ 21.5 MB      │
│ 12       │ mxpkonlyteerz.exe                  │ 687.2 KB     │
│ 13       │ ca_iter_packed_1_mxpkonlyteerz.exe │ 1.3 MB       │
│ 14       │ ca_iter_packed_3_mxpkonlyteerz.exe │ 5.4 MB       │
└──────────┴────────────────────────────────────┴──────────────┘

Select file by index, or enter custom path (0):
✅ Target selected: ilvlmp.exe
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🎯 Target: ilvlmp.exe                                                                                                              │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────── 🛠️ Build-a-Binary Menu ───────────────────────────────────────────────────────╮
│                                                                                                                                    │
│   1           Quick Analysis               Fast section analysis and obfuscation suggestions                                       │
│   2           Deep Analysis                Comprehensive plugin-based analysis with reporting                                      │
│   3           Interactive Hex Viewer       Explore binary with interactive hex dump                                                │
│   4           Encoding Operations          Obfuscate specific sections with various encodings                                      │
│   5           Generate Reports             Create detailed analysis reports in multiple formats                                    │
│   6           Change Target                Select a different binary file                                                          │
│   b           Back                         Return to main start menu                                                               │
│   h           Help                         Show detailed help and examples                                                         │
│   q           Quit                         Exit the framework                                                                      │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

Select an option [1/2/3/4/5/6/b/h/q] (1): 3
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🔧 Interactive Hex Viewer Options                                                                                                  │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Option   ┃ Description                    ┃ Command/Action                                                    ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1        │ Basic Hex View (HTML)          │ cumpyl ilvlmp.exe --hex-view                                      │
│ 2        │ Interactive Section Selection  │ cumpyl ilvlmp.exe --hex-view --hex-view-interactive               │
│          │ (HTML)                         │                                                                   │
│ 3        │ Interactive Terminal Hex       │ Launch TUI hex viewer with navigation                             │
│          │ Viewer                         │                                                                   │
│ 4        │ Hex + Full Analysis            │ cumpyl ilvlmp.exe --hex-view --run-analysis --suggest-obfuscation │
│ 5        │ Custom Range (specify offset)  │ Custom command builder                                            │
│ 6        │ View Specific Section          │ Custom section selector                                           │
│ 7        │ Large File View (8KB)          │ cumpyl ilvlmp.exe --hex-view --hex-view-bytes 8192                │
│ b        │ Back to Main Menu              │                                                                   │
└──────────┴────────────────────────────────┴───────────────────────────────────────────────────────────────────┘

Select hex viewer option [1/2/3/4/5/6/7/b] (3): 4

🚀 Executing: cumpyl ilvlmp.exe --hex-view --run-analysis --suggest-obfuscation
────────────────────────────────────────────────────────────────────────────────
<frozen runpy>:128: RuntimeWarning: 'cumpyl_package.cumpyl' found in sys.modules after import of package 'cumpyl_package', but prior to execution of 'cumpyl_package.cumpyl'; this may result in unpredictable behaviour
[+] Successfully loaded ilvlmp.exe
[*] Discovered 22 plugin(s): analysis_utils, packer_plugin, config_manager, performance, format_strategies, cgo_packer_plugin, test_utils, plugin_registry, format_utils, transmuter_plugin, test_go_packer_plugin, string_extraction, entropy_analysis, crypto_utils, consolidated_utils, go_packer_plugin, doc_utils, exceptions, analysis, base_plugin, transform, logging_config
[DEBUG] Looking for factory functions in analysis_utils
[DEBUG] Found function: analyze_binary_sections
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[-] No valid plugin class or factory function found in analysis_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis_utils: No valid plugin class or factory function found in analysis_utils
[DEBUG] Looking for factory functions in packer_plugin
[DEBUG] Found function: calculate_entropy
[DEBUG] Found function: create_integrity_hash
[DEBUG] Found function: decrypt_bytes_aesgcm
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: encrypt_bytes_aesgcm
[DEBUG] Found function: get_plugin
[DEBUG] Checking factory function: get_plugin
[DEBUG] Factory function get_plugin returned instance: <class 'packer_plugin.PackerPlugin'>
[DEBUG] Factory function get_plugin is valid
[DEBUG] Looking for factory functions in config_manager
[-] No valid plugin class or factory function found in config_manager
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin config_manager: No valid plugin class or factory function found in config_manager
[DEBUG] Looking for factory functions in performance
[DEBUG] Found function: _get_memory_usage
[DEBUG] Found function: dataclass
[DEBUG] Found function: monitor_performance
[DEBUG] Found function: wraps
[-] No valid plugin class or factory function found in performance
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin performance: No valid plugin class or factory function found in performance
[DEBUG] Looking for factory functions in format_strategies
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in format_strategies
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_strategies: No valid plugin class or factory function found in format_strategies
[-] Failed to load plugin cgo_packer_plugin: attempted relative import with no known parent package
[DEBUG] Looking for factory functions in test_utils
[-] No valid plugin class or factory function found in test_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_utils: No valid plugin class or factory function found in test_utils
[DEBUG] Looking for factory functions in plugin_registry
[DEBUG] Found function: get_packer_plugin
[DEBUG] Found function: get_packer_transform_plugin
[-] No valid plugin class or factory function found in plugin_registry
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin plugin_registry: No valid plugin class or factory function found in plugin_registry
[DEBUG] Looking for factory functions in format_utils
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: section_permissions_from_program_headers
[-] No valid plugin class or factory function found in format_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_utils: No valid plugin class or factory function found in format_utils
[DEBUG] Looking for factory functions in test_go_packer_plugin
[DEBUG] Found function: get_analysis_plugin
[-] No valid plugin class or factory function found in test_go_packer_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_go_packer_plugin: No valid plugin class or factory function found in test_go_packer_plugin
[DEBUG] Looking for factory functions in crypto_utils
[DEBUG] Found function: default_backend
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: generate_metadata_key
[DEBUG] Found function: load_and_derive_key
[DEBUG] Found function: retry
[DEBUG] Found function: safe_hash
[-] No valid plugin class or factory function found in crypto_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin crypto_utils: No valid plugin class or factory function found in crypto_utils
[DEBUG] Looking for factory functions in consolidated_utils
[DEBUG] Found function: detect_format_enhanced
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: lru_cache
[-] No valid plugin class or factory function found in consolidated_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin consolidated_utils: No valid plugin class or factory function found in consolidated_utils
{"timestamp": "2025-08-30 15:05:28", "level": "INFO", "module": "plugin_registry", "message": "Registered analysis plugin: go_packer_plugin", "filename": "plugin_registry.py", "lineno": 21, "process_id": 201881, "thread_id": 139824962135936}
[DEBUG] Looking for factory functions in doc_utils
[DEBUG] Found function: documented_method
[-] No valid plugin class or factory function found in doc_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin doc_utils: No valid plugin class or factory function found in doc_utils
[DEBUG] Looking for factory functions in exceptions
[-] No valid plugin class or factory function found in exceptions
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin exceptions: No valid plugin class or factory function found in exceptions
[DEBUG] Looking for factory functions in analysis
[DEBUG] Found function: analyze_sections_for_packing
[DEBUG] Found function: find_go_build_id
[DEBUG] Found function: is_executable_section
[-] No valid plugin class or factory function found in analysis
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis: No valid plugin class or factory function found in analysis
[DEBUG] Looking for factory functions in base_plugin
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in base_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin base_plugin: No valid plugin class or factory function found in base_plugin
[DEBUG] Looking for factory functions in transform
[DEBUG] Found function: apply_transformation_plan
[DEBUG] Found function: create_transformation_plan
[DEBUG] Found function: generate_dry_run_report
[DEBUG] Found function: get_transformation_summary
[DEBUG] Found function: safe_hash
[DEBUG] Found function: validate
[DEBUG] Found function: validate_binary_object
[DEBUG] Found function: validate_transformation_plan
[DEBUG] Found function: validate_transformation_plan_schema
[-] No valid plugin class or factory function found in transform
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin transform: No valid plugin class or factory function found in transform
[DEBUG] Looking for factory functions in logging_config
[DEBUG] Found function: setup_logging
[-] No valid plugin class or factory function found in logging_config
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin logging_config: No valid plugin class or factory function found in logging_config
[+] Loaded 5 plugin(s)
[*] Running plugin analysis phase...
{"timestamp": "2025-08-30 15:05:30", "level": "ERROR", "module": "go_packer_plugin", "message": "Analysis failed: character U+fffffff3 is not in range [U+0000; U+10ffff]", "filename": "go_packer_plugin.py", "lineno": 223, "process_id": 201881, "thread_id": 139824962135936}
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Plugin Analysis Results                                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
✓ entropy_analysis: Analysis completed
✓ string_extraction: Analysis completed
✓ packer: Analysis completed
✓ transmuter: Analysis completed
❌ go_binary_analyzer: Analysis failed: character U+fffffff3 is not in range [U+0000; U+10ffff]
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                                                    │
│  Obfuscation Suggestions for ilvlmp.exe                                                                                            │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
⠋ Analyzing binary sections...
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Advanced Tier (Large, High-Impact Sections)                                                                                        │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┓
┃ Section ┃ Type           ┃ Size    ┃ Address ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━┩
│ .rdata  │ Read-only Data │ 4.02 KB │ 0xa000  │
└─────────┴────────────────┴─────────┴─────────┘

cumpyl ilvlmp.exe --encode-section .rdata --encoding base64 -o obfuscated_ilvlmp.exe

╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Best for heavy obfuscation. Large capacity for complex encoding.                                                       │
│ Encoding Options: base64, compressed_base64, hex                                                                                   │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Intermediate Tier (Medium-Size Data Sections)                                                                                      │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┓
┃ Section ┃ Type                ┃ Size      ┃ Address ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━┩
│ /19     │ Resource/Debug Data │ 321.72 KB │ 0x14000 │
│ /81     │ Resource/Debug Data │ 68.18 KB  │ 0x76000 │
│ /45     │ Resource/Debug Data │ 32.32 KB  │ 0x6a000 │
│ /31     │ Resource/Debug Data │ 16.03 KB  │ 0x65000 │
│ /57     │ Resource/Debug Data │ 6.20 KB   │ 0x73000 │
│ /92     │ Resource/Debug Data │ 3.59 KB   │ 0x88000 │
│ /70     │ Resource/Debug Data │ 2.31 KB   │ 0x75000 │
│ /4      │ Resource/Debug Data │ 1.77 KB   │ 0x13000 │
│ .data   │ Data                │ 272 bytes │ 0x9000  │
│ .bss    │ Data                │ 0 bytes   │ 0xe000  │
└─────────┴─────────────────────┴───────────┴─────────┘

cumpyl ilvlmp.exe --encode-section /19 --encoding base64 -o obfuscated_ilvlmp.exe
cumpyl ilvlmp.exe --encode-section /81 --encoding base64 -o obfuscated_ilvlmp.exe
cumpyl ilvlmp.exe --encode-section /45 --encoding base64 -o obfuscated_ilvlmp.exe
cumpyl ilvlmp.exe --encode-section /31 --encoding base64 -o obfuscated_ilvlmp.exe
cumpyl ilvlmp.exe --encode-section /57 --encoding base64 -o obfuscated_ilvlmp.exe
cumpyl ilvlmp.exe --encode-section /92 --encoding base64 -o obfuscated_ilvlmp.exe
cumpyl ilvlmp.exe --encode-section /70 --encoding base64 -o obfuscated_ilvlmp.exe
cumpyl ilvlmp.exe --encode-section /4 --encoding base64 -o obfuscated_ilvlmp.exe
cumpyl ilvlmp.exe --encode-section .data --encoding base64 -o obfuscated_ilvlmp.exe
cumpyl ilvlmp.exe --encode-section .bss --encoding base64 -o obfuscated_ilvlmp.exe

╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Good for moderate obfuscation. Balanced size and safety.                                                               │
│ Encoding Options: base64, compressed_base64                                                                                        │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Basic Tier (Small, Low-Impact Sections)                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┓
┃ Section ┃ Type                  ┃ Size    ┃ Address ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━┩
│ .pdata  │ Exception Data        │ 1.28 KB │ 0xc000  │
│ .xdata  │ Exception Unwind Data │ 1.20 KB │ 0xd000  │
└─────────┴───────────────────────┴─────────┴─────────┘

cumpyl ilvlmp.exe --encode-section .pdata --encoding hex -o obfuscated_ilvlmp.exe
cumpyl ilvlmp.exe --encode-section .xdata --encoding hex -o obfuscated_ilvlmp.exe

╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Suitable for light obfuscation. Small sections, minimal impact.                                                        │
│ Encoding Options: hex, octal                                                                                                       │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Avoid (Critical Sections)                                                                                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Section ┃ Type            ┃ Size      ┃ Address  ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━┩
│ .cpload │ Unknown         │ 2.13 MB   │ 0x226000 │
│ .cpload │ Unknown         │ 1.07 MB   │ 0x114000 │
│ .cpload │ Unknown         │ 545.22 KB │ 0x8a000  │
│ .text   │ Executable Code │ 28.57 KB  │ 0x1000   │
│ .idata  │ Import Data     │ 2.73 KB   │ 0xf000   │
│ .reloc  │ Relocation Data │ 144 bytes │ 0x12000  │
│ .CRT    │ Unknown         │ 104 bytes │ 0x10000  │
│ .stub   │ Unknown         │ 22 bytes  │ 0x89000  │
│ .stub   │ Unknown         │ 22 bytes  │ 0x113000 │
│ .stub   │ Unknown         │ 22 bytes  │ 0x225000 │
│ .tls    │ Unknown         │ 16 bytes  │ 0x11000  │
└─────────┴─────────────────┴───────────┴──────────┘
╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Critical for program execution. Avoid obfuscation.                                                                     │
│ DO NOT OBFUSCATE                                                                                                                   │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Overall Recommendations                                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
 Best section:  /19 (Resource/Debug Data)
 Size:          329437 bytes
 Command:       cumpyl ilvlmp.exe --encode-section /19 --encoding compressed_base64 -o obfuscated_ilvlmp.exe
╭───────────────────────────────────────────────────────────── WARNING ──────────────────────────────────────────────────────────────╮
│ Obfuscating executable sections (.text) will break the program. Use with extreme caution.                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
[*] Generating interactive hex view with integrated analysis...
Traceback (most recent call last):
  File "<frozen runpy>", line 198, in _run_module_as_main
  File "<frozen runpy>", line 88, in _run_code
  File "/home/developer/cumpyl/cumpyl_package/cumpyl.py", line 1341, in <module>
    main()
    ~~~~^^
  File "/home/developer/cumpyl/cumpyl_package/cumpyl.py", line 1106, in main
    report_generator.generate_report(hex_report_data, 'html', hex_output_file)
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/developer/cumpyl/cumpyl_package/reporting.py", line 525, in generate_report
    report_content = formatter.format(data)
  File "/home/developer/cumpyl/cumpyl_package/reporting.py", line 94, in format
    html = self._generate_html_report(data)
  File "/home/developer/cumpyl/cumpyl_package/reporting.py", line 112, in _generate_html_report
    hex_viewer_js = hex_viewer.get_javascript()
                    ^^^^^^^^^^^^^^^^^^^^^^^^^
AttributeError: 'HexViewer' object has no attribute 'get_javascript'
────────────────────────────────────────────────────────────────────────────────
❌ Command failed with return code: 1

Press Enter to continue ():
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🎯 Target: ilvlmp.exe                                                                                                              │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────── 🛠️ Build-a-Binary Menu ───────────────────────────────────────────────────────╮
│                                                                                                                                    │
│   1           Quick Analysis               Fast section analysis and obfuscation suggestions                                       │
│   2           Deep Analysis                Comprehensive plugin-based analysis with reporting                                      │
│   3           Interactive Hex Viewer       Explore binary with interactive hex dump                                                │
│   4           Encoding Operations          Obfuscate specific sections with various encodings                                      │
│   5           Generate Reports             Create detailed analysis reports in multiple formats                                    │
│   6           Change Target                Select a different binary file                                                          │
│   b           Back                         Return to main start menu                                                               │
│   h           Help                         Show detailed help and examples                                                         │
│   q           Quit                         Exit the framework                                                                      │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

Select an option [1/2/3/4/5/6/b/h/q] (1): 2
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🧪 Deep Analysis Options                                                                                                           │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Option   ┃ Description                         ┃ Command Preview                                                                   ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1        │ Plugin Analysis Only                │ cumpyl ilvlmp.exe --run-analysis                                                  │
│ 2        │ Analysis + HTML Report              │ cumpyl ilvlmp.exe --run-analysis --report-format html --report-output             │
│          │                                     │ analysis.html                                                                     │
│ 3        │ Analysis + JSON Report              │ cumpyl ilvlmp.exe --run-analysis --report-format json --report-output             │
│          │                                     │ analysis.json                                                                     │
│ 4        │ Full Workflow + Hex View            │ cumpyl ilvlmp.exe --run-analysis --suggest-obfuscation --hex-view                 │
│ 5        │ Malware Analysis Profile            │ cumpyl ilvlmp.exe --profile malware_analysis --run-analysis                       │
│ 6        │ Forensics Profile                   │ cumpyl ilvlmp.exe --profile forensics --run-analysis                              │
│ b        │ Back to Main Menu                   │                                                                                   │
└──────────┴─────────────────────────────────────┴───────────────────────────────────────────────────────────────────────────────────┘

Select deep analysis option [1/2/3/4/5/6/b] (4): 6

🚀 Executing: cumpyl ilvlmp.exe --profile forensics --run-analysis
────────────────────────────────────────────────────────────────────────────────
<frozen runpy>:128: RuntimeWarning: 'cumpyl_package.cumpyl' found in sys.modules after import of package 'cumpyl_package', but prior to execution of 'cumpyl_package.cumpyl'; this may result in unpredictable behaviour
[*] Using profile: forensics
[+] Successfully loaded ilvlmp.exe
[*] Discovered 22 plugin(s): analysis_utils, packer_plugin, config_manager, performance, format_strategies, cgo_packer_plugin, test_utils, plugin_registry, format_utils, transmuter_plugin, test_go_packer_plugin, string_extraction, entropy_analysis, crypto_utils, consolidated_utils, go_packer_plugin, doc_utils, exceptions, analysis, base_plugin, transform, logging_config
[DEBUG] Looking for factory functions in analysis_utils
[DEBUG] Found function: analyze_binary_sections
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[-] No valid plugin class or factory function found in analysis_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis_utils: No valid plugin class or factory function found in analysis_utils
[DEBUG] Looking for factory functions in packer_plugin
[DEBUG] Found function: calculate_entropy
[DEBUG] Found function: create_integrity_hash
[DEBUG] Found function: decrypt_bytes_aesgcm
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: encrypt_bytes_aesgcm
[DEBUG] Found function: get_plugin
[DEBUG] Checking factory function: get_plugin
[DEBUG] Factory function get_plugin returned instance: <class 'packer_plugin.PackerPlugin'>
[DEBUG] Factory function get_plugin is valid
[DEBUG] Looking for factory functions in config_manager
[-] No valid plugin class or factory function found in config_manager
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin config_manager: No valid plugin class or factory function found in config_manager
[DEBUG] Looking for factory functions in performance
[DEBUG] Found function: _get_memory_usage
[DEBUG] Found function: dataclass
[DEBUG] Found function: monitor_performance
[DEBUG] Found function: wraps
[-] No valid plugin class or factory function found in performance
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin performance: No valid plugin class or factory function found in performance
[DEBUG] Looking for factory functions in format_strategies
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in format_strategies
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_strategies: No valid plugin class or factory function found in format_strategies
[-] Failed to load plugin cgo_packer_plugin: attempted relative import with no known parent package
[DEBUG] Looking for factory functions in test_utils
[-] No valid plugin class or factory function found in test_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_utils: No valid plugin class or factory function found in test_utils
[DEBUG] Looking for factory functions in plugin_registry
[DEBUG] Found function: get_packer_plugin
[DEBUG] Found function: get_packer_transform_plugin
[-] No valid plugin class or factory function found in plugin_registry
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin plugin_registry: No valid plugin class or factory function found in plugin_registry
[DEBUG] Looking for factory functions in format_utils
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: section_permissions_from_program_headers
[-] No valid plugin class or factory function found in format_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_utils: No valid plugin class or factory function found in format_utils
[DEBUG] Looking for factory functions in test_go_packer_plugin
[DEBUG] Found function: get_analysis_plugin
[-] No valid plugin class or factory function found in test_go_packer_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_go_packer_plugin: No valid plugin class or factory function found in test_go_packer_plugin
[DEBUG] Looking for factory functions in crypto_utils
[DEBUG] Found function: default_backend
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: generate_metadata_key
[DEBUG] Found function: load_and_derive_key
[DEBUG] Found function: retry
[DEBUG] Found function: safe_hash
[-] No valid plugin class or factory function found in crypto_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin crypto_utils: No valid plugin class or factory function found in crypto_utils
[DEBUG] Looking for factory functions in consolidated_utils
[DEBUG] Found function: detect_format_enhanced
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: lru_cache
[-] No valid plugin class or factory function found in consolidated_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin consolidated_utils: No valid plugin class or factory function found in consolidated_utils
{"timestamp": "2025-08-30 15:05:53", "level": "INFO", "module": "plugin_registry", "message": "Registered analysis plugin: go_packer_plugin", "filename": "plugin_registry.py", "lineno": 21, "process_id": 201893, "thread_id": 140391816804224}
[DEBUG] Looking for factory functions in doc_utils
[DEBUG] Found function: documented_method
[-] No valid plugin class or factory function found in doc_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin doc_utils: No valid plugin class or factory function found in doc_utils
[DEBUG] Looking for factory functions in exceptions
[-] No valid plugin class or factory function found in exceptions
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin exceptions: No valid plugin class or factory function found in exceptions
[DEBUG] Looking for factory functions in analysis
[DEBUG] Found function: analyze_sections_for_packing
[DEBUG] Found function: find_go_build_id
[DEBUG] Found function: is_executable_section
[-] No valid plugin class or factory function found in analysis
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis: No valid plugin class or factory function found in analysis
[DEBUG] Looking for factory functions in base_plugin
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in base_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin base_plugin: No valid plugin class or factory function found in base_plugin
[DEBUG] Looking for factory functions in transform
[DEBUG] Found function: apply_transformation_plan
[DEBUG] Found function: create_transformation_plan
[DEBUG] Found function: generate_dry_run_report
[DEBUG] Found function: get_transformation_summary
[DEBUG] Found function: safe_hash
[DEBUG] Found function: validate
[DEBUG] Found function: validate_binary_object
[DEBUG] Found function: validate_transformation_plan
[DEBUG] Found function: validate_transformation_plan_schema
[-] No valid plugin class or factory function found in transform
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin transform: No valid plugin class or factory function found in transform
[DEBUG] Looking for factory functions in logging_config
[DEBUG] Found function: setup_logging
[-] No valid plugin class or factory function found in logging_config
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin logging_config: No valid plugin class or factory function found in logging_config
[+] Loaded 5 plugin(s)
[*] Running plugin analysis phase...
{"timestamp": "2025-08-30 15:05:55", "level": "ERROR", "module": "go_packer_plugin", "message": "Analysis failed: character U+fffffff3 is not in range [U+0000; U+10ffff]", "filename": "go_packer_plugin.py", "lineno": 223, "process_id": 201893, "thread_id": 140391816804224}
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Plugin Analysis Results                                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
✓ entropy_analysis: Analysis completed
✓ string_extraction: Analysis completed
✓ packer: Analysis completed
✓ transmuter: Analysis completed
❌ go_binary_analyzer: Analysis failed: character U+fffffff3 is not in range [U+0000; U+10ffff]
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Entropy Analysis Results                                                                                                           │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
⚠️  Potential packing detected
  High entropy sections: .cpload, .cpload, .cpload
  .text: Normal entropy (6.254)
  .data: Normal entropy (1.765)
  .rdata: Normal entropy (5.22)
  .pdata: Normal entropy (4.276)
  .xdata: Normal entropy (4.366)
  .idata: Normal entropy (4.189)
  .CRT: Normal entropy (1.212)
  .tls: Low entropy (0.0)
  .reloc: Normal entropy (4.0)
  /4: Normal entropy (1.93)
  /19: Normal entropy (6.041)
  /31: Normal entropy (4.708)
  /45: Normal entropy (5.467)
  /57: Normal entropy (4.592)
  /70: Normal entropy (4.751)
  /81: Normal entropy (2.669)
  /92: Normal entropy (1.816)
  .stub: Normal entropy (3.356)
  .cpload: High entropy (8.0)
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ String Extraction Results                                                                                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
  .text: 377 strings extracted
  .rdata: 86 strings extracted
  .idata: 76 strings extracted
  /19: 10273 strings extracted
  /45: 597 strings extracted
  /70: 164 strings extracted
  /81: 22 strings extracted
  .cpload: 26697 strings extracted
🔍 Interesting strings found:
  .rdata: LoadLibraryA (Score: 5.0)
  .rdata: ShellExecuteEx failed with error: %lu (Score: 5.0)
  .rdata: Requesting administrator privileges... (Score: 4.0)
  .rdata: Installer process found with PID: %lu. Injecting D... (Score: 4.0)
  .rdata: DLL injection attempted. Monitoring stopped. (Score: 4.0)
🔧 API functions detected:
  GetProcAddress, !IID_IExternalConnection, IID_IExternalConnection, accept, LoadLibraryA, VirtualAllocEx, VirtualProtect,
OpenProcess, ShellExecuteExA, OpenProcessToken
🌐 Network indicators:
  .cpload: !"_~B.xx (domains)
  .cpload: M.ff (domains)
  .cpload: dY.sc,P (domains)
  .cpload: )BS.zl (domains)
  .cpload: TK.sh (domains)

============================================================
FORENSICS ANALYSIS REPORT
============================================================
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Entropy Analysis                                                                                                                   │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
⚠️  POTENTIAL PACKING DETECTED
  High entropy sections: .cpload, .cpload, .cpload

Section Entropy Analysis:
  .text: 6.254 (Normal)
  .data: 1.765 (Normal)
  .rdata: 5.22 (Normal)
  .pdata: 4.276 (Normal)
  .xdata: 4.366 (Normal)
  .idata: 4.189 (Normal)
  .CRT: 1.212 (Normal)
  .tls: 0.0 (Low - repetitive data)
  .reloc: 4.0 (Normal)
  /4: 1.93 (Normal)
  /19: 6.041 (Normal)
  /31: 4.708 (Normal)
  /45: 5.467 (Normal)
  /57: 4.592 (Normal)
  /70: 4.751 (Normal)
  /81: 2.669 (Normal)
  /92: 1.816 (Normal)
  .stub: 3.356 (Normal)
  .cpload: 8.0 (High - possible encryption/packing)
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ String Extraction                                                                                                                  │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Total strings extracted: 58258

🔍 Interesting Strings:
  .rdata: LoadLibraryA (5.0)
  .rdata: ShellExecuteEx failed with error: %lu (5.0)
  .rdata: Requesting administrator privileges... (4.0)
  .rdata: Installer process found with PID: %lu. Injecting DLL... (4.0)
  .rdata: DLL injection attempted. Monitoring stopped. (4.0)
  .idata: CreateToolhelp32Snapshot (6.0)
  .idata: DeleteCriticalSection (6.0)
  .idata: InitializeCriticalSection (6.0)
  .idata: SetUnhandledExceptionFilter (6.0)
  .idata: OpenProcessToken (5.0)

🔧 API Functions:
  GetProcAddress, !IID_IExternalConnection, IID_IExternalConnection, accept, LoadLibraryA, VirtualAllocEx, VirtualProtect,
OpenProcess, ShellExecuteExA, OpenProcessToken, ShellExecuteEx failed with error: %lu, WriteProcessMemory

🌐 Network Indicators:
  .cpload: !"_~B.xx (domains)
  .cpload: M.ff (domains)
  .cpload: dY.sc,P (domains)
  .cpload: )BS.zl (domains)
  .cpload: TK.sh (domains)
  .cpload: 3.nz (domains)
  .cpload: B.bi (domains)
  .cpload: K.av</ (domains)
  .cpload: C.ew (domains)
  .cpload: eT.ri (domains)

🔒 Security-Related Strings:
  /19: key_dtor_list (passwords)
  /19: $__mingwthr_run_key_dtors (passwords)
  /19: ___w64_mingwthr_remove_key_dtor (passwords)
  /19: ___w64_mingwthr_add_key_dtor (passwords)
────────────────────────────────────────────────────────────────────────────────
✅ Command completed successfully!

Press Enter to continue ():
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🎯 Target: ilvlmp.exe                                                                                                              │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────── 🛠️ Build-a-Binary Menu ───────────────────────────────────────────────────────╮
│                                                                                                                                    │
│   1           Quick Analysis               Fast section analysis and obfuscation suggestions                                       │
│   2           Deep Analysis                Comprehensive plugin-based analysis with reporting                                      │
│   3           Interactive Hex Viewer       Explore binary with interactive hex dump                                                │
│   4           Encoding Operations          Obfuscate specific sections with various encodings                                      │
│   5           Generate Reports             Create detailed analysis reports in multiple formats                                    │
│   6           Change Target                Select a different binary file                                                          │
│   b           Back                         Return to main start menu                                                               │
│   h           Help                         Show detailed help and examples                                                         │
│   q           Quit                         Exit the framework                                                                      │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

Select an option [1/2/3/4/5/6/b/h/q] (1): 6
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🎯 Target File Selection                                                                                                           │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
📁 Found binary files in current directory:
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┓
┃ Index    ┃ File Path                          ┃ Size         ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━┩
│ 0        │ ilvlmp.exe                         │ 4.3 MB       │
│ 1        │ ca_iter_packed_4_mxpkonlyteerz.exe │ 10.8 MB      │
│ 2        │ ilovelamp.exe                      │ 545.2 KB     │
│ 3        │ mxpkmnogogo.exe                    │ 560.2 KB     │
│ 4        │ ca_iter_packed_2_mxpkonlyteerz.exe │ 2.7 MB       │
│ 5        │ ca_quick_packed_ilvlmp.exe         │ 8.5 MB       │
│ 6        │ c2_communicator.exe                │ 169.4 KB     │
│ 7        │ ilvlmp_iter3.exe                   │ 4.3 MB       │
│ 8        │ not_a_mess.exe                     │ 466.3 KB     │
│ 9        │ monogogo_win_exploit_silent.exe    │ 279.7 KB     │
│ 10       │ gojotb.exe                         │ 10.0 MB      │
│ 11       │ ca_iter_packed_mxpkonlyteerz.exe   │ 21.5 MB      │
│ 12       │ mxpkonlyteerz.exe                  │ 687.2 KB     │
│ 13       │ ca_iter_packed_1_mxpkonlyteerz.exe │ 1.3 MB       │
│ 14       │ ca_iter_packed_3_mxpkonlyteerz.exe │ 5.4 MB       │
└──────────┴────────────────────────────────────┴──────────────┘

Select file by index, or enter custom path (0): 1
✅ Target selected: ca_iter_packed_4_mxpkonlyteerz.exe
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🎯 Target: ca_iter_packed_4_mxpkonlyteerz.exe                                                                                      │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────── 🛠️ Build-a-Binary Menu ───────────────────────────────────────────────────────╮
│                                                                                                                                    │
│   1           Quick Analysis               Fast section analysis and obfuscation suggestions                                       │
│   2           Deep Analysis                Comprehensive plugin-based analysis with reporting                                      │
│   3           Interactive Hex Viewer       Explore binary with interactive hex dump                                                │
│   4           Encoding Operations          Obfuscate specific sections with various encodings                                      │
│   5           Generate Reports             Create detailed analysis reports in multiple formats                                    │
│   6           Change Target                Select a different binary file                                                          │
│   b           Back                         Return to main start menu                                                               │
│   h           Help                         Show detailed help and examples                                                         │
│   q           Quit                         Exit the framework                                                                      │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

Select an option [1/2/3/4/5/6/b/h/q] (1): 2
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🧪 Deep Analysis Options                                                                                                           │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Option   ┃ Description                         ┃ Command Preview                                                                   ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1        │ Plugin Analysis Only                │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis                          │
│ 2        │ Analysis + HTML Report              │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis --report-format html     │
│          │                                     │ --report-output analysis.html                                                     │
│ 3        │ Analysis + JSON Report              │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis --report-format json     │
│          │                                     │ --report-output analysis.json                                                     │
│ 4        │ Full Workflow + Hex View            │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis --suggest-obfuscation    │
│          │                                     │ --hex-view                                                                        │
│ 5        │ Malware Analysis Profile            │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --profile malware_analysis              │
│          │                                     │ --run-analysis                                                                    │
│ 6        │ Forensics Profile                   │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --profile forensics --run-analysis      │
│ b        │ Back to Main Menu                   │                                                                                   │
└──────────┴─────────────────────────────────────┴───────────────────────────────────────────────────────────────────────────────────┘

Select deep analysis option [1/2/3/4/5/6/b] (4): 6

🚀 Executing: cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --profile forensics --run-analysis
────────────────────────────────────────────────────────────────────────────────
<frozen runpy>:128: RuntimeWarning: 'cumpyl_package.cumpyl' found in sys.modules after import of package 'cumpyl_package', but prior to execution of 'cumpyl_package.cumpyl'; this may result in unpredictable behaviour
[*] Using profile: forensics
[+] Successfully loaded ca_iter_packed_4_mxpkonlyteerz.exe
[*] Discovered 22 plugin(s): analysis_utils, packer_plugin, config_manager, performance, format_strategies, cgo_packer_plugin, test_utils, plugin_registry, format_utils, transmuter_plugin, test_go_packer_plugin, string_extraction, entropy_analysis, crypto_utils, consolidated_utils, go_packer_plugin, doc_utils, exceptions, analysis, base_plugin, transform, logging_config
[DEBUG] Looking for factory functions in analysis_utils
[DEBUG] Found function: analyze_binary_sections
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[-] No valid plugin class or factory function found in analysis_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis_utils: No valid plugin class or factory function found in analysis_utils
[DEBUG] Looking for factory functions in packer_plugin
[DEBUG] Found function: calculate_entropy
[DEBUG] Found function: create_integrity_hash
[DEBUG] Found function: decrypt_bytes_aesgcm
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: encrypt_bytes_aesgcm
[DEBUG] Found function: get_plugin
[DEBUG] Checking factory function: get_plugin
[DEBUG] Factory function get_plugin returned instance: <class 'packer_plugin.PackerPlugin'>
[DEBUG] Factory function get_plugin is valid
[DEBUG] Looking for factory functions in config_manager
[-] No valid plugin class or factory function found in config_manager
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin config_manager: No valid plugin class or factory function found in config_manager
[DEBUG] Looking for factory functions in performance
[DEBUG] Found function: _get_memory_usage
[DEBUG] Found function: dataclass
[DEBUG] Found function: monitor_performance
[DEBUG] Found function: wraps
[-] No valid plugin class or factory function found in performance
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin performance: No valid plugin class or factory function found in performance
[DEBUG] Looking for factory functions in format_strategies
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in format_strategies
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_strategies: No valid plugin class or factory function found in format_strategies
[-] Failed to load plugin cgo_packer_plugin: attempted relative import with no known parent package
[DEBUG] Looking for factory functions in test_utils
[-] No valid plugin class or factory function found in test_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_utils: No valid plugin class or factory function found in test_utils
[DEBUG] Looking for factory functions in plugin_registry
[DEBUG] Found function: get_packer_plugin
[DEBUG] Found function: get_packer_transform_plugin
[-] No valid plugin class or factory function found in plugin_registry
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin plugin_registry: No valid plugin class or factory function found in plugin_registry
[DEBUG] Looking for factory functions in format_utils
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: section_permissions_from_program_headers
[-] No valid plugin class or factory function found in format_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_utils: No valid plugin class or factory function found in format_utils
[DEBUG] Looking for factory functions in test_go_packer_plugin
[DEBUG] Found function: get_analysis_plugin
[-] No valid plugin class or factory function found in test_go_packer_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_go_packer_plugin: No valid plugin class or factory function found in test_go_packer_plugin
[DEBUG] Looking for factory functions in crypto_utils
[DEBUG] Found function: default_backend
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: generate_metadata_key
[DEBUG] Found function: load_and_derive_key
[DEBUG] Found function: retry
[DEBUG] Found function: safe_hash
[-] No valid plugin class or factory function found in crypto_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin crypto_utils: No valid plugin class or factory function found in crypto_utils
[DEBUG] Looking for factory functions in consolidated_utils
[DEBUG] Found function: detect_format_enhanced
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: lru_cache
[-] No valid plugin class or factory function found in consolidated_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin consolidated_utils: No valid plugin class or factory function found in consolidated_utils
{"timestamp": "2025-08-30 15:06:18", "level": "INFO", "module": "plugin_registry", "message": "Registered analysis plugin: go_packer_plugin", "filename": "plugin_registry.py", "lineno": 21, "process_id": 201901, "thread_id": 140079316682624}
[DEBUG] Looking for factory functions in doc_utils
[DEBUG] Found function: documented_method
[-] No valid plugin class or factory function found in doc_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin doc_utils: No valid plugin class or factory function found in doc_utils
[DEBUG] Looking for factory functions in exceptions
[-] No valid plugin class or factory function found in exceptions
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin exceptions: No valid plugin class or factory function found in exceptions
[DEBUG] Looking for factory functions in analysis
[DEBUG] Found function: analyze_sections_for_packing
[DEBUG] Found function: find_go_build_id
[DEBUG] Found function: is_executable_section
[-] No valid plugin class or factory function found in analysis
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis: No valid plugin class or factory function found in analysis
[DEBUG] Looking for factory functions in base_plugin
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in base_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin base_plugin: No valid plugin class or factory function found in base_plugin
[DEBUG] Looking for factory functions in transform
[DEBUG] Found function: apply_transformation_plan
[DEBUG] Found function: create_transformation_plan
[DEBUG] Found function: generate_dry_run_report
[DEBUG] Found function: get_transformation_summary
[DEBUG] Found function: safe_hash
[DEBUG] Found function: validate
[DEBUG] Found function: validate_binary_object
[DEBUG] Found function: validate_transformation_plan
[DEBUG] Found function: validate_transformation_plan_schema
[-] No valid plugin class or factory function found in transform
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin transform: No valid plugin class or factory function found in transform
[DEBUG] Looking for factory functions in logging_config
[DEBUG] Found function: setup_logging
[-] No valid plugin class or factory function found in logging_config
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin logging_config: No valid plugin class or factory function found in logging_config
[+] Loaded 5 plugin(s)
[*] Running plugin analysis phase...
{"timestamp": "2025-08-30 15:06:24", "level": "ERROR", "module": "go_packer_plugin", "message": "Analysis failed: character U+ffffff98 is not in range [U+0000; U+10ffff]", "filename": "go_packer_plugin.py", "lineno": 223, "process_id": 201901, "thread_id": 140079316682624}
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Plugin Analysis Results                                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
✓ entropy_analysis: Analysis completed
✓ string_extraction: Analysis completed
✓ packer: Analysis completed
✓ transmuter: Analysis completed
❌ go_binary_analyzer: Analysis failed: character U+ffffff98 is not in range [U+0000; U+10ffff]
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Entropy Analysis Results                                                                                                           │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
⚠️  Potential packing detected
  High entropy sections: .cpload, .cpload, .cpload, .cpload, .cpload
  .text: Normal entropy (6.298)
  .data: Low entropy (0.118)
  .rdata: Normal entropy (5.626)
  .pdata: Normal entropy (5.428)
  .xdata: Normal entropy (5.55)
  .idata: Normal entropy (4.524)
  .CRT: Normal entropy (1.506)
  .tls: Low entropy (0.0)
  .reloc: Normal entropy (5.34)
  .stub: Normal entropy (3.356)
  .cpload: High entropy (8.0)
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ String Extraction Results                                                                                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
  .text: 1658 strings extracted
  .rdata: 180 strings extracted
  .idata: 114 strings extracted
  .cpload: 67272 strings extracted
🔍 Interesting strings found:
  .rdata: Hello from implant!SpamFilter.exeAntivirus.exeMalw... (Score: 7.0)
  .rdata: src/main.rs (Score: 6.0)
  .rdata: library\alloc\src\raw_vec\mod.rs (Score: 6.0)
  .rdata: library\alloc\src\string.rs (Score: 6.0)
  .rdata: library\alloc\src\fmt.rs (Score: 6.0)
🔧 API functions detected:
  WriteProcessMemory, HeapAlloc, CreateFileMappingA, LoadLibraryA, GetProcAddress, OpenProcessToken, OpenProcess, WSAStartup,
closesocket, send
🌐 Network indicators:
  .rdata: src/main.rs (domains)
  .rdata: 127.0.0.1 (ip_addresses)
  .rdata: library\alloc\src\raw_vec\mod.rs (domains)
  .rdata: library\alloc\src\string.rs (domains)
  .rdata: library\alloc\src\fmt.rs (domains)

============================================================
FORENSICS ANALYSIS REPORT
============================================================
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Entropy Analysis                                                                                                                   │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
⚠️  POTENTIAL PACKING DETECTED
  High entropy sections: .cpload, .cpload, .cpload, .cpload, .cpload

Section Entropy Analysis:
  .text: 6.298 (Normal)
  .data: 0.118 (Low - repetitive data)
  .rdata: 5.626 (Normal)
  .pdata: 5.428 (Normal)
  .xdata: 5.55 (Normal)
  .idata: 4.524 (Normal)
  .CRT: 1.506 (Normal)
  .tls: 0.0 (Low - repetitive data)
  .reloc: 5.34 (Normal)
  .stub: 3.356 (Normal)
  .cpload: 8.0 (High - possible encryption/packing)
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ String Extraction                                                                                                                  │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Total strings extracted: 132200

🔍 Interesting Strings:
  .rdata: Hello from implant!SpamFilter.exeAntivirus.exeMalwarebytes.e... (7.0)
  .rdata: src/main.rs (6.0)
  .rdata: library\alloc\src\raw_vec\mod.rs (6.0)
  .rdata: library\alloc\src\string.rs (6.0)
  .rdata: library\alloc\src\fmt.rs (6.0)
  .rdata: RefCell already borrowedcalled `Option::unwrap()` on a `None... (6.0)
  .rdata: library\core\src\slice\memchr.rs (6.0)
  .rdata: library\core\src\slice\sort\shared\smallsort.rs (6.0)
  .rdata: library\core\src\str\mod.rs (6.0)
  .rdata: library\core\src\str\pattern.rs (6.0)

🔧 API Functions:
  WriteProcessMemory, HeapAlloc, CreateFileMappingA, LoadLibraryA, GetProcAddress, OpenProcessToken, OpenProcess, WSAStartup,
closesocket, send, socket, VirtualProtect, CreateFileW, VirtualAllocEx, connect

🌐 Network Indicators:
  .rdata: src/main.rs (domains)
  .rdata: 127.0.0.1 (ip_addresses)
  .rdata: library\alloc\src\raw_vec\mod.rs (domains)
  .rdata: library\alloc\src\string.rs (domains)
  .rdata: library\alloc\src\fmt.rs (domains)
  .rdata: RefCell already borrowedcalled `Option::unwrap()` on a `None` valuelibrary\core\src\panicking.rs (domains)
  .rdata: library\core\src\slice\memchr.rs (domains)
  .rdata: library\core\src\slice\sort\shared\smallsort.rs (domains)
  .rdata: library\core\src\str\mod.rs (domains)
  .rdata: library\core\src\str\pattern.rs (domains)
────────────────────────────────────────────────────────────────────────────────
✅ Command completed successfully!

Press Enter to continue ():
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🎯 Target: ca_iter_packed_4_mxpkonlyteerz.exe                                                                                      │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────── 🛠️ Build-a-Binary Menu ───────────────────────────────────────────────────────╮
│                                                                                                                                    │
│   1           Quick Analysis               Fast section analysis and obfuscation suggestions                                       │
│   2           Deep Analysis                Comprehensive plugin-based analysis with reporting                                      │
│   3           Interactive Hex Viewer       Explore binary with interactive hex dump                                                │
│   4           Encoding Operations          Obfuscate specific sections with various encodings                                      │
│   5           Generate Reports             Create detailed analysis reports in multiple formats                                    │
│   6           Change Target                Select a different binary file                                                          │
│   b           Back                         Return to main start menu                                                               │
│   h           Help                         Show detailed help and examples                                                         │
│   q           Quit                         Exit the framework                                                                      │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

Select an option [1/2/3/4/5/6/b/h/q] (1): 2
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🧪 Deep Analysis Options                                                                                                           │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Option   ┃ Description                         ┃ Command Preview                                                                   ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1        │ Plugin Analysis Only                │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis                          │
│ 2        │ Analysis + HTML Report              │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis --report-format html     │
│          │                                     │ --report-output analysis.html                                                     │
│ 3        │ Analysis + JSON Report              │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis --report-format json     │
│          │                                     │ --report-output analysis.json                                                     │
│ 4        │ Full Workflow + Hex View            │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis --suggest-obfuscation    │
│          │                                     │ --hex-view                                                                        │
│ 5        │ Malware Analysis Profile            │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --profile malware_analysis              │
│          │                                     │ --run-analysis                                                                    │
│ 6        │ Forensics Profile                   │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --profile forensics --run-analysis      │
│ b        │ Back to Main Menu                   │                                                                                   │
└──────────┴─────────────────────────────────────┴───────────────────────────────────────────────────────────────────────────────────┘

Select deep analysis option [1/2/3/4/5/6/b] (4): 1

🚀 Executing: cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis
────────────────────────────────────────────────────────────────────────────────
<frozen runpy>:128: RuntimeWarning: 'cumpyl_package.cumpyl' found in sys.modules after import of package 'cumpyl_package', but prior to execution of 'cumpyl_package.cumpyl'; this may result in unpredictable behaviour
[+] Successfully loaded ca_iter_packed_4_mxpkonlyteerz.exe
[*] Discovered 22 plugin(s): analysis_utils, packer_plugin, config_manager, performance, format_strategies, cgo_packer_plugin, test_utils, plugin_registry, format_utils, transmuter_plugin, test_go_packer_plugin, string_extraction, entropy_analysis, crypto_utils, consolidated_utils, go_packer_plugin, doc_utils, exceptions, analysis, base_plugin, transform, logging_config
[DEBUG] Looking for factory functions in analysis_utils
[DEBUG] Found function: analyze_binary_sections
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[-] No valid plugin class or factory function found in analysis_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis_utils: No valid plugin class or factory function found in analysis_utils
[DEBUG] Looking for factory functions in packer_plugin
[DEBUG] Found function: calculate_entropy
[DEBUG] Found function: create_integrity_hash
[DEBUG] Found function: decrypt_bytes_aesgcm
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: encrypt_bytes_aesgcm
[DEBUG] Found function: get_plugin
[DEBUG] Checking factory function: get_plugin
[DEBUG] Factory function get_plugin returned instance: <class 'packer_plugin.PackerPlugin'>
[DEBUG] Factory function get_plugin is valid
[DEBUG] Looking for factory functions in config_manager
[-] No valid plugin class or factory function found in config_manager
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin config_manager: No valid plugin class or factory function found in config_manager
[DEBUG] Looking for factory functions in performance
[DEBUG] Found function: _get_memory_usage
[DEBUG] Found function: dataclass
[DEBUG] Found function: monitor_performance
[DEBUG] Found function: wraps
[-] No valid plugin class or factory function found in performance
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin performance: No valid plugin class or factory function found in performance
[DEBUG] Looking for factory functions in format_strategies
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in format_strategies
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_strategies: No valid plugin class or factory function found in format_strategies
[-] Failed to load plugin cgo_packer_plugin: attempted relative import with no known parent package
[DEBUG] Looking for factory functions in test_utils
[-] No valid plugin class or factory function found in test_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_utils: No valid plugin class or factory function found in test_utils
[DEBUG] Looking for factory functions in plugin_registry
[DEBUG] Found function: get_packer_plugin
[DEBUG] Found function: get_packer_transform_plugin
[-] No valid plugin class or factory function found in plugin_registry
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin plugin_registry: No valid plugin class or factory function found in plugin_registry
[DEBUG] Looking for factory functions in format_utils
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: section_permissions_from_program_headers
[-] No valid plugin class or factory function found in format_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_utils: No valid plugin class or factory function found in format_utils
[DEBUG] Looking for factory functions in test_go_packer_plugin
[DEBUG] Found function: get_analysis_plugin
[-] No valid plugin class or factory function found in test_go_packer_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_go_packer_plugin: No valid plugin class or factory function found in test_go_packer_plugin
[DEBUG] Looking for factory functions in crypto_utils
[DEBUG] Found function: default_backend
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: generate_metadata_key
[DEBUG] Found function: load_and_derive_key
[DEBUG] Found function: retry
[DEBUG] Found function: safe_hash
[-] No valid plugin class or factory function found in crypto_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin crypto_utils: No valid plugin class or factory function found in crypto_utils
[DEBUG] Looking for factory functions in consolidated_utils
[DEBUG] Found function: detect_format_enhanced
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: lru_cache
[-] No valid plugin class or factory function found in consolidated_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin consolidated_utils: No valid plugin class or factory function found in consolidated_utils
{"timestamp": "2025-08-30 15:07:10", "level": "INFO", "module": "plugin_registry", "message": "Registered analysis plugin: go_packer_plugin", "filename": "plugin_registry.py", "lineno": 21, "process_id": 201916, "thread_id": 140688702011264}
[DEBUG] Looking for factory functions in doc_utils
[DEBUG] Found function: documented_method
[-] No valid plugin class or factory function found in doc_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin doc_utils: No valid plugin class or factory function found in doc_utils
[DEBUG] Looking for factory functions in exceptions
[-] No valid plugin class or factory function found in exceptions
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin exceptions: No valid plugin class or factory function found in exceptions
[DEBUG] Looking for factory functions in analysis
[DEBUG] Found function: analyze_sections_for_packing
[DEBUG] Found function: find_go_build_id
[DEBUG] Found function: is_executable_section
[-] No valid plugin class or factory function found in analysis
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis: No valid plugin class or factory function found in analysis
[DEBUG] Looking for factory functions in base_plugin
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in base_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin base_plugin: No valid plugin class or factory function found in base_plugin
[DEBUG] Looking for factory functions in transform
[DEBUG] Found function: apply_transformation_plan
[DEBUG] Found function: create_transformation_plan
[DEBUG] Found function: generate_dry_run_report
[DEBUG] Found function: get_transformation_summary
[DEBUG] Found function: safe_hash
[DEBUG] Found function: validate
[DEBUG] Found function: validate_binary_object
[DEBUG] Found function: validate_transformation_plan
[DEBUG] Found function: validate_transformation_plan_schema
[-] No valid plugin class or factory function found in transform
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin transform: No valid plugin class or factory function found in transform
[DEBUG] Looking for factory functions in logging_config
[DEBUG] Found function: setup_logging
[-] No valid plugin class or factory function found in logging_config
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin logging_config: No valid plugin class or factory function found in logging_config
[+] Loaded 5 plugin(s)
[*] Running plugin analysis phase...
{"timestamp": "2025-08-30 15:07:15", "level": "ERROR", "module": "go_packer_plugin", "message": "Analysis failed: character U+ffffff98 is not in range [U+0000; U+10ffff]", "filename": "go_packer_plugin.py", "lineno": 223, "process_id": 201916, "thread_id": 140688702011264}
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Plugin Analysis Results                                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
✓ entropy_analysis: Analysis completed
✓ string_extraction: Analysis completed
✓ packer: Analysis completed
✓ transmuter: Analysis completed
❌ go_binary_analyzer: Analysis failed: character U+ffffff98 is not in range [U+0000; U+10ffff]
────────────────────────────────────────────────────────────────────────────────
✅ Command completed successfully!

Press Enter to continue ():
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🎯 Target: ca_iter_packed_4_mxpkonlyteerz.exe                                                                                      │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────── 🛠️ Build-a-Binary Menu ───────────────────────────────────────────────────────╮
│                                                                                                                                    │
│   1           Quick Analysis               Fast section analysis and obfuscation suggestions                                       │
│   2           Deep Analysis                Comprehensive plugin-based analysis with reporting                                      │
│   3           Interactive Hex Viewer       Explore binary with interactive hex dump                                                │
│   4           Encoding Operations          Obfuscate specific sections with various encodings                                      │
│   5           Generate Reports             Create detailed analysis reports in multiple formats                                    │
│   6           Change Target                Select a different binary file                                                          │
│   b           Back                         Return to main start menu                                                               │
│   h           Help                         Show detailed help and examples                                                         │
│   q           Quit                         Exit the framework                                                                      │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

Select an option [1/2/3/4/5/6/b/h/q] (1): 2
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🧪 Deep Analysis Options                                                                                                           │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Option   ┃ Description                         ┃ Command Preview                                                                   ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1        │ Plugin Analysis Only                │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis                          │
│ 2        │ Analysis + HTML Report              │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis --report-format html     │
│          │                                     │ --report-output analysis.html                                                     │
│ 3        │ Analysis + JSON Report              │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis --report-format json     │
│          │                                     │ --report-output analysis.json                                                     │
│ 4        │ Full Workflow + Hex View            │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis --suggest-obfuscation    │
│          │                                     │ --hex-view                                                                        │
│ 5        │ Malware Analysis Profile            │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --profile malware_analysis              │
│          │                                     │ --run-analysis                                                                    │
│ 6        │ Forensics Profile                   │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --profile forensics --run-analysis      │
│ b        │ Back to Main Menu                   │                                                                                   │
└──────────┴─────────────────────────────────────┴───────────────────────────────────────────────────────────────────────────────────┘

Select deep analysis option [1/2/3/4/5/6/b] (4): 2

🚀 Executing: cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis --report-format html --report-output analysis.html
────────────────────────────────────────────────────────────────────────────────
<frozen runpy>:128: RuntimeWarning: 'cumpyl_package.cumpyl' found in sys.modules after import of package 'cumpyl_package', but prior to execution of 'cumpyl_package.cumpyl'; this may result in unpredictable behaviour
[+] Successfully loaded ca_iter_packed_4_mxpkonlyteerz.exe
[*] Discovered 22 plugin(s): analysis_utils, packer_plugin, config_manager, performance, format_strategies, cgo_packer_plugin, test_utils, plugin_registry, format_utils, transmuter_plugin, test_go_packer_plugin, string_extraction, entropy_analysis, crypto_utils, consolidated_utils, go_packer_plugin, doc_utils, exceptions, analysis, base_plugin, transform, logging_config
[DEBUG] Looking for factory functions in analysis_utils
[DEBUG] Found function: analyze_binary_sections
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[-] No valid plugin class or factory function found in analysis_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis_utils: No valid plugin class or factory function found in analysis_utils
[DEBUG] Looking for factory functions in packer_plugin
[DEBUG] Found function: calculate_entropy
[DEBUG] Found function: create_integrity_hash
[DEBUG] Found function: decrypt_bytes_aesgcm
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: encrypt_bytes_aesgcm
[DEBUG] Found function: get_plugin
[DEBUG] Checking factory function: get_plugin
[DEBUG] Factory function get_plugin returned instance: <class 'packer_plugin.PackerPlugin'>
[DEBUG] Factory function get_plugin is valid
[DEBUG] Looking for factory functions in config_manager
[-] No valid plugin class or factory function found in config_manager
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin config_manager: No valid plugin class or factory function found in config_manager
[DEBUG] Looking for factory functions in performance
[DEBUG] Found function: _get_memory_usage
[DEBUG] Found function: dataclass
[DEBUG] Found function: monitor_performance
[DEBUG] Found function: wraps
[-] No valid plugin class or factory function found in performance
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin performance: No valid plugin class or factory function found in performance
[DEBUG] Looking for factory functions in format_strategies
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in format_strategies
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_strategies: No valid plugin class or factory function found in format_strategies
[-] Failed to load plugin cgo_packer_plugin: attempted relative import with no known parent package
[DEBUG] Looking for factory functions in test_utils
[-] No valid plugin class or factory function found in test_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_utils: No valid plugin class or factory function found in test_utils
[DEBUG] Looking for factory functions in plugin_registry
[DEBUG] Found function: get_packer_plugin
[DEBUG] Found function: get_packer_transform_plugin
[-] No valid plugin class or factory function found in plugin_registry
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin plugin_registry: No valid plugin class or factory function found in plugin_registry
[DEBUG] Looking for factory functions in format_utils
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: section_permissions_from_program_headers
[-] No valid plugin class or factory function found in format_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_utils: No valid plugin class or factory function found in format_utils
[DEBUG] Looking for factory functions in test_go_packer_plugin
[DEBUG] Found function: get_analysis_plugin
[-] No valid plugin class or factory function found in test_go_packer_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_go_packer_plugin: No valid plugin class or factory function found in test_go_packer_plugin
[DEBUG] Looking for factory functions in crypto_utils
[DEBUG] Found function: default_backend
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: generate_metadata_key
[DEBUG] Found function: load_and_derive_key
[DEBUG] Found function: retry
[DEBUG] Found function: safe_hash
[-] No valid plugin class or factory function found in crypto_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin crypto_utils: No valid plugin class or factory function found in crypto_utils
[DEBUG] Looking for factory functions in consolidated_utils
[DEBUG] Found function: detect_format_enhanced
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: lru_cache
[-] No valid plugin class or factory function found in consolidated_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin consolidated_utils: No valid plugin class or factory function found in consolidated_utils
{"timestamp": "2025-08-30 15:07:34", "level": "INFO", "module": "plugin_registry", "message": "Registered analysis plugin: go_packer_plugin", "filename": "plugin_registry.py", "lineno": 21, "process_id": 201927, "thread_id": 140672716437376}
[DEBUG] Looking for factory functions in doc_utils
[DEBUG] Found function: documented_method
[-] No valid plugin class or factory function found in doc_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin doc_utils: No valid plugin class or factory function found in doc_utils
[DEBUG] Looking for factory functions in exceptions
[-] No valid plugin class or factory function found in exceptions
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin exceptions: No valid plugin class or factory function found in exceptions
[DEBUG] Looking for factory functions in analysis
[DEBUG] Found function: analyze_sections_for_packing
[DEBUG] Found function: find_go_build_id
[DEBUG] Found function: is_executable_section
[-] No valid plugin class or factory function found in analysis
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis: No valid plugin class or factory function found in analysis
[DEBUG] Looking for factory functions in base_plugin
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in base_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin base_plugin: No valid plugin class or factory function found in base_plugin
[DEBUG] Looking for factory functions in transform
[DEBUG] Found function: apply_transformation_plan
[DEBUG] Found function: create_transformation_plan
[DEBUG] Found function: generate_dry_run_report
[DEBUG] Found function: get_transformation_summary
[DEBUG] Found function: safe_hash
[DEBUG] Found function: validate
[DEBUG] Found function: validate_binary_object
[DEBUG] Found function: validate_transformation_plan
[DEBUG] Found function: validate_transformation_plan_schema
[-] No valid plugin class or factory function found in transform
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin transform: No valid plugin class or factory function found in transform
[DEBUG] Looking for factory functions in logging_config
[DEBUG] Found function: setup_logging
[-] No valid plugin class or factory function found in logging_config
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin logging_config: No valid plugin class or factory function found in logging_config
[+] Loaded 5 plugin(s)
[*] Running plugin analysis phase...
{"timestamp": "2025-08-30 15:07:40", "level": "ERROR", "module": "go_packer_plugin", "message": "Analysis failed: character U+ffffff98 is not in range [U+0000; U+10ffff]", "filename": "go_packer_plugin.py", "lineno": 223, "process_id": 201927, "thread_id": 140672716437376}
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Plugin Analysis Results                                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
✓ entropy_analysis: Analysis completed
✓ string_extraction: Analysis completed
✓ packer: Analysis completed
✓ transmuter: Analysis completed
❌ go_binary_analyzer: Analysis failed: character U+ffffff98 is not in range [U+0000; U+10ffff]
[+] Report saved to: analysis.html
────────────────────────────────────────────────────────────────────────────────
✅ Command completed successfully!

Press Enter to continue ():
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🎯 Target: ca_iter_packed_4_mxpkonlyteerz.exe                                                                                      │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────── 🛠️ Build-a-Binary Menu ───────────────────────────────────────────────────────╮
│                                                                                                                                    │
│   1           Quick Analysis               Fast section analysis and obfuscation suggestions                                       │
│   2           Deep Analysis                Comprehensive plugin-based analysis with reporting                                      │
│   3           Interactive Hex Viewer       Explore binary with interactive hex dump                                                │
│   4           Encoding Operations          Obfuscate specific sections with various encodings                                      │
│   5           Generate Reports             Create detailed analysis reports in multiple formats                                    │
│   6           Change Target                Select a different binary file                                                          │
│   b           Back                         Return to main start menu                                                               │
│   h           Help                         Show detailed help and examples                                                         │
│   q           Quit                         Exit the framework                                                                      │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

Select an option [1/2/3/4/5/6/b/h/q] (1): 2
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🧪 Deep Analysis Options                                                                                                           │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Option   ┃ Description                         ┃ Command Preview                                                                   ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1        │ Plugin Analysis Only                │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis                          │
│ 2        │ Analysis + HTML Report              │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis --report-format html     │
│          │                                     │ --report-output analysis.html                                                     │
│ 3        │ Analysis + JSON Report              │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis --report-format json     │
│          │                                     │ --report-output analysis.json                                                     │
│ 4        │ Full Workflow + Hex View            │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis --suggest-obfuscation    │
│          │                                     │ --hex-view                                                                        │
│ 5        │ Malware Analysis Profile            │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --profile malware_analysis              │
│          │                                     │ --run-analysis                                                                    │
│ 6        │ Forensics Profile                   │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --profile forensics --run-analysis      │
│ b        │ Back to Main Menu                   │                                                                                   │
└──────────┴─────────────────────────────────────┴───────────────────────────────────────────────────────────────────────────────────┘

Select deep analysis option [1/2/3/4/5/6/b] (4): 4

🚀 Executing: cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis --suggest-obfuscation --hex-view
────────────────────────────────────────────────────────────────────────────────
<frozen runpy>:128: RuntimeWarning: 'cumpyl_package.cumpyl' found in sys.modules after import of package 'cumpyl_package', but prior to execution of 'cumpyl_package.cumpyl'; this may result in unpredictable behaviour
[+] Successfully loaded ca_iter_packed_4_mxpkonlyteerz.exe
[*] Discovered 22 plugin(s): analysis_utils, packer_plugin, config_manager, performance, format_strategies, cgo_packer_plugin, test_utils, plugin_registry, format_utils, transmuter_plugin, test_go_packer_plugin, string_extraction, entropy_analysis, crypto_utils, consolidated_utils, go_packer_plugin, doc_utils, exceptions, analysis, base_plugin, transform, logging_config
[DEBUG] Looking for factory functions in analysis_utils
[DEBUG] Found function: analyze_binary_sections
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[-] No valid plugin class or factory function found in analysis_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis_utils: No valid plugin class or factory function found in analysis_utils
[DEBUG] Looking for factory functions in packer_plugin
[DEBUG] Found function: calculate_entropy
[DEBUG] Found function: create_integrity_hash
[DEBUG] Found function: decrypt_bytes_aesgcm
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: encrypt_bytes_aesgcm
[DEBUG] Found function: get_plugin
[DEBUG] Checking factory function: get_plugin
[DEBUG] Factory function get_plugin returned instance: <class 'packer_plugin.PackerPlugin'>
[DEBUG] Factory function get_plugin is valid
[DEBUG] Looking for factory functions in config_manager
[-] No valid plugin class or factory function found in config_manager
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin config_manager: No valid plugin class or factory function found in config_manager
[DEBUG] Looking for factory functions in performance
[DEBUG] Found function: _get_memory_usage
[DEBUG] Found function: dataclass
[DEBUG] Found function: monitor_performance
[DEBUG] Found function: wraps
[-] No valid plugin class or factory function found in performance
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin performance: No valid plugin class or factory function found in performance
[DEBUG] Looking for factory functions in format_strategies
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in format_strategies
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_strategies: No valid plugin class or factory function found in format_strategies
[-] Failed to load plugin cgo_packer_plugin: attempted relative import with no known parent package
[DEBUG] Looking for factory functions in test_utils
[-] No valid plugin class or factory function found in test_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_utils: No valid plugin class or factory function found in test_utils
[DEBUG] Looking for factory functions in plugin_registry
[DEBUG] Found function: get_packer_plugin
[DEBUG] Found function: get_packer_transform_plugin
[-] No valid plugin class or factory function found in plugin_registry
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin plugin_registry: No valid plugin class or factory function found in plugin_registry
[DEBUG] Looking for factory functions in format_utils
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: section_permissions_from_program_headers
[-] No valid plugin class or factory function found in format_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_utils: No valid plugin class or factory function found in format_utils
[DEBUG] Looking for factory functions in test_go_packer_plugin
[DEBUG] Found function: get_analysis_plugin
[-] No valid plugin class or factory function found in test_go_packer_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_go_packer_plugin: No valid plugin class or factory function found in test_go_packer_plugin
[DEBUG] Looking for factory functions in crypto_utils
[DEBUG] Found function: default_backend
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: generate_metadata_key
[DEBUG] Found function: load_and_derive_key
[DEBUG] Found function: retry
[DEBUG] Found function: safe_hash
[-] No valid plugin class or factory function found in crypto_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin crypto_utils: No valid plugin class or factory function found in crypto_utils
[DEBUG] Looking for factory functions in consolidated_utils
[DEBUG] Found function: detect_format_enhanced
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: lru_cache
[-] No valid plugin class or factory function found in consolidated_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin consolidated_utils: No valid plugin class or factory function found in consolidated_utils
{"timestamp": "2025-08-30 15:07:50", "level": "INFO", "module": "plugin_registry", "message": "Registered analysis plugin: go_packer_plugin", "filename": "plugin_registry.py", "lineno": 21, "process_id": 201936, "thread_id": 140403669002112}
[DEBUG] Looking for factory functions in doc_utils
[DEBUG] Found function: documented_method
[-] No valid plugin class or factory function found in doc_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin doc_utils: No valid plugin class or factory function found in doc_utils
[DEBUG] Looking for factory functions in exceptions
[-] No valid plugin class or factory function found in exceptions
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin exceptions: No valid plugin class or factory function found in exceptions
[DEBUG] Looking for factory functions in analysis
[DEBUG] Found function: analyze_sections_for_packing
[DEBUG] Found function: find_go_build_id
[DEBUG] Found function: is_executable_section
[-] No valid plugin class or factory function found in analysis
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis: No valid plugin class or factory function found in analysis
[DEBUG] Looking for factory functions in base_plugin
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in base_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin base_plugin: No valid plugin class or factory function found in base_plugin
[DEBUG] Looking for factory functions in transform
[DEBUG] Found function: apply_transformation_plan
[DEBUG] Found function: create_transformation_plan
[DEBUG] Found function: generate_dry_run_report
[DEBUG] Found function: get_transformation_summary
[DEBUG] Found function: safe_hash
[DEBUG] Found function: validate
[DEBUG] Found function: validate_binary_object
[DEBUG] Found function: validate_transformation_plan
[DEBUG] Found function: validate_transformation_plan_schema
[-] No valid plugin class or factory function found in transform
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin transform: No valid plugin class or factory function found in transform
[DEBUG] Looking for factory functions in logging_config
[DEBUG] Found function: setup_logging
[-] No valid plugin class or factory function found in logging_config
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin logging_config: No valid plugin class or factory function found in logging_config
[+] Loaded 5 plugin(s)
[*] Running plugin analysis phase...
{"timestamp": "2025-08-30 15:07:56", "level": "ERROR", "module": "go_packer_plugin", "message": "Analysis failed: character U+ffffff98 is not in range [U+0000; U+10ffff]", "filename": "go_packer_plugin.py", "lineno": 223, "process_id": 201936, "thread_id": 140403669002112}
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Plugin Analysis Results                                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
✓ entropy_analysis: Analysis completed
✓ string_extraction: Analysis completed
✓ packer: Analysis completed
✓ transmuter: Analysis completed
❌ go_binary_analyzer: Analysis failed: character U+ffffff98 is not in range [U+0000; U+10ffff]
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                                                    │
│  Obfuscation Suggestions for ca_iter_packed_4_mxpkonlyteerz.exe                                                                    │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
⠴ Analyzing binary sections...
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Advanced Tier (Large, High-Impact Sections)                                                                                        │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┓
┃ Section ┃ Type           ┃ Size     ┃ Address ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━┩
│ .rdata  │ Read-only Data │ 26.08 KB │ 0x37000 │
└─────────┴────────────────┴──────────┴─────────┘

cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .rdata --encoding base64 -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe

╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Best for heavy obfuscation. Large capacity for complex encoding.                                                       │
│ Encoding Options: base64, compressed_base64, hex                                                                                   │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Intermediate Tier (Medium-Size Data Sections)                                                                                      │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━┳━━━━━━━━━┳━━━━━━━━━┓
┃ Section ┃ Type ┃ Size    ┃ Address ┃
┡━━━━━━━━━╇━━━━━━╇━━━━━━━━━╇━━━━━━━━━┩
│ .data   │ Data │ 2.34 KB │ 0x36000 │
│ .bss    │ Data │ 0 bytes │ 0x43000 │
└─────────┴──────┴─────────┴─────────┘

cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .data --encoding base64 -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe
cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .bss --encoding base64 -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe

╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Good for moderate obfuscation. Balanced size and safety.                                                               │
│ Encoding Options: base64, compressed_base64                                                                                        │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Basic Tier (Small, Low-Impact Sections)                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┓
┃ Section ┃ Type                  ┃ Size    ┃ Address ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━┩
│ .xdata  │ Exception Unwind Data │ 9.89 KB │ 0x40000 │
│ .pdata  │ Exception Data        │ 4.65 KB │ 0x3e000 │
└─────────┴───────────────────────┴─────────┴─────────┘

cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .xdata --encoding hex -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe
cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .pdata --encoding hex -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe

╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Suitable for light obfuscation. Small sections, minimal impact.                                                        │
│ Encoding Options: hex, octal                                                                                                       │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Avoid (Critical Sections)                                                                                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Section ┃ Type            ┃ Size      ┃ Address  ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━┩
│ .cpload │ Unknown         │ 5.38 MB   │ 0x558000 │
│ .cpload │ Unknown         │ 2.69 MB   │ 0x2a7000 │
│ .cpload │ Unknown         │ 1.34 MB   │ 0x14e000 │
│ .cpload │ Unknown         │ 687.22 KB │ 0xa1000  │
│ .cpload │ Unknown         │ 343.22 KB │ 0x4a000  │
│ .text   │ Executable Code │ 210.49 KB │ 0x1000   │
│ .idata  │ Import Data     │ 4.21 KB   │ 0x44000  │
│ .reloc  │ Relocation Data │ 892 bytes │ 0x48000  │
│ .CRT    │ Unknown         │ 112 bytes │ 0x46000  │
│ .stub   │ Unknown         │ 22 bytes  │ 0x49000  │
│ .stub   │ Unknown         │ 22 bytes  │ 0xa0000  │
│ .stub   │ Unknown         │ 22 bytes  │ 0x14d000 │
│ .stub   │ Unknown         │ 22 bytes  │ 0x2a6000 │
│ .stub   │ Unknown         │ 22 bytes  │ 0x557000 │
│ .tls    │ Unknown         │ 16 bytes  │ 0x47000  │
└─────────┴─────────────────┴───────────┴──────────┘
╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Critical for program execution. Avoid obfuscation.                                                                     │
│ DO NOT OBFUSCATE                                                                                                                   │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Overall Recommendations                                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
 Best section:  .rdata (Read-only Data)
 Size:          26704 bytes
 Command:       cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .rdata --encoding compressed_base64 -o
                obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe
╭───────────────────────────────────────────────────────────── WARNING ──────────────────────────────────────────────────────────────╮
│ Obfuscating executable sections (.text) will break the program. Use with extreme caution.                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
[*] Generating interactive hex view with integrated analysis...
[+] Report saved to: ca_iter_packed_4_mxpkonlyteerz_hex.html
[+] Interactive hex view with integrated analysis saved to: ca_iter_packed_4_mxpkonlyteerz_hex.html
────────────────────────────────────────────────────────────────────────────────
✅ Command completed successfully!

Press Enter to continue ():
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🎯 Target: ca_iter_packed_4_mxpkonlyteerz.exe                                                                                      │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────── 🛠️ Build-a-Binary Menu ───────────────────────────────────────────────────────╮
│                                                                                                                                    │
│   1           Quick Analysis               Fast section analysis and obfuscation suggestions                                       │
│   2           Deep Analysis                Comprehensive plugin-based analysis with reporting                                      │
│   3           Interactive Hex Viewer       Explore binary with interactive hex dump                                                │
│   4           Encoding Operations          Obfuscate specific sections with various encodings                                      │
│   5           Generate Reports             Create detailed analysis reports in multiple formats                                    │
│   6           Change Target                Select a different binary file                                                          │
│   b           Back                         Return to main start menu                                                               │
│   h           Help                         Show detailed help and examples                                                         │
│   q           Quit                         Exit the framework                                                                      │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

Select an option [1/2/3/4/5/6/b/h/q] (1): 2
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🧪 Deep Analysis Options                                                                                                           │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Option   ┃ Description                         ┃ Command Preview                                                                   ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1        │ Plugin Analysis Only                │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis                          │
│ 2        │ Analysis + HTML Report              │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis --report-format html     │
│          │                                     │ --report-output analysis.html                                                     │
│ 3        │ Analysis + JSON Report              │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis --report-format json     │
│          │                                     │ --report-output analysis.json                                                     │
│ 4        │ Full Workflow + Hex View            │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --run-analysis --suggest-obfuscation    │
│          │                                     │ --hex-view                                                                        │
│ 5        │ Malware Analysis Profile            │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --profile malware_analysis              │
│          │                                     │ --run-analysis                                                                    │
│ 6        │ Forensics Profile                   │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --profile forensics --run-analysis      │
│ b        │ Back to Main Menu                   │                                                                                   │
└──────────┴─────────────────────────────────────┴───────────────────────────────────────────────────────────────────────────────────┘

Select deep analysis option [1/2/3/4/5/6/b] (4): 5

🚀 Executing: cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --profile malware_analysis --run-analysis
────────────────────────────────────────────────────────────────────────────────
<frozen runpy>:128: RuntimeWarning: 'cumpyl_package.cumpyl' found in sys.modules after import of package 'cumpyl_package', but prior to execution of 'cumpyl_package.cumpyl'; this may result in unpredictable behaviour
[*] Using profile: malware_analysis
[+] Successfully loaded ca_iter_packed_4_mxpkonlyteerz.exe
[*] Discovered 22 plugin(s): analysis_utils, packer_plugin, config_manager, performance, format_strategies, cgo_packer_plugin, test_utils, plugin_registry, format_utils, transmuter_plugin, test_go_packer_plugin, string_extraction, entropy_analysis, crypto_utils, consolidated_utils, go_packer_plugin, doc_utils, exceptions, analysis, base_plugin, transform, logging_config
[DEBUG] Looking for factory functions in analysis_utils
[DEBUG] Found function: analyze_binary_sections
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[-] No valid plugin class or factory function found in analysis_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis_utils: No valid plugin class or factory function found in analysis_utils
[DEBUG] Looking for factory functions in packer_plugin
[DEBUG] Found function: calculate_entropy
[DEBUG] Found function: create_integrity_hash
[DEBUG] Found function: decrypt_bytes_aesgcm
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: encrypt_bytes_aesgcm
[DEBUG] Found function: get_plugin
[DEBUG] Checking factory function: get_plugin
[DEBUG] Factory function get_plugin returned instance: <class 'packer_plugin.PackerPlugin'>
[DEBUG] Factory function get_plugin is valid
[DEBUG] Looking for factory functions in config_manager
[-] No valid plugin class or factory function found in config_manager
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin config_manager: No valid plugin class or factory function found in config_manager
[DEBUG] Looking for factory functions in performance
[DEBUG] Found function: _get_memory_usage
[DEBUG] Found function: dataclass
[DEBUG] Found function: monitor_performance
[DEBUG] Found function: wraps
[-] No valid plugin class or factory function found in performance
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin performance: No valid plugin class or factory function found in performance
[DEBUG] Looking for factory functions in format_strategies
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in format_strategies
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_strategies: No valid plugin class or factory function found in format_strategies
[-] Failed to load plugin cgo_packer_plugin: attempted relative import with no known parent package
[DEBUG] Looking for factory functions in test_utils
[-] No valid plugin class or factory function found in test_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_utils: No valid plugin class or factory function found in test_utils
[DEBUG] Looking for factory functions in plugin_registry
[DEBUG] Found function: get_packer_plugin
[DEBUG] Found function: get_packer_transform_plugin
[-] No valid plugin class or factory function found in plugin_registry
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin plugin_registry: No valid plugin class or factory function found in plugin_registry
[DEBUG] Looking for factory functions in format_utils
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: section_permissions_from_program_headers
[-] No valid plugin class or factory function found in format_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_utils: No valid plugin class or factory function found in format_utils
[DEBUG] Looking for factory functions in test_go_packer_plugin
[DEBUG] Found function: get_analysis_plugin
[-] No valid plugin class or factory function found in test_go_packer_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_go_packer_plugin: No valid plugin class or factory function found in test_go_packer_plugin
[DEBUG] Looking for factory functions in crypto_utils
[DEBUG] Found function: default_backend
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: generate_metadata_key
[DEBUG] Found function: load_and_derive_key
[DEBUG] Found function: retry
[DEBUG] Found function: safe_hash
[-] No valid plugin class or factory function found in crypto_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin crypto_utils: No valid plugin class or factory function found in crypto_utils
[DEBUG] Looking for factory functions in consolidated_utils
[DEBUG] Found function: detect_format_enhanced
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: lru_cache
[-] No valid plugin class or factory function found in consolidated_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin consolidated_utils: No valid plugin class or factory function found in consolidated_utils
{"timestamp": "2025-08-30 15:08:28", "level": "INFO", "module": "plugin_registry", "message": "Registered analysis plugin: go_packer_plugin", "filename": "plugin_registry.py", "lineno": 21, "process_id": 201948, "thread_id": 140705469626240}
[DEBUG] Looking for factory functions in doc_utils
[DEBUG] Found function: documented_method
[-] No valid plugin class or factory function found in doc_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin doc_utils: No valid plugin class or factory function found in doc_utils
[DEBUG] Looking for factory functions in exceptions
[-] No valid plugin class or factory function found in exceptions
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin exceptions: No valid plugin class or factory function found in exceptions
[DEBUG] Looking for factory functions in analysis
[DEBUG] Found function: analyze_sections_for_packing
[DEBUG] Found function: find_go_build_id
[DEBUG] Found function: is_executable_section
[-] No valid plugin class or factory function found in analysis
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis: No valid plugin class or factory function found in analysis
[DEBUG] Looking for factory functions in base_plugin
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in base_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin base_plugin: No valid plugin class or factory function found in base_plugin
[DEBUG] Looking for factory functions in transform
[DEBUG] Found function: apply_transformation_plan
[DEBUG] Found function: create_transformation_plan
[DEBUG] Found function: generate_dry_run_report
[DEBUG] Found function: get_transformation_summary
[DEBUG] Found function: safe_hash
[DEBUG] Found function: validate
[DEBUG] Found function: validate_binary_object
[DEBUG] Found function: validate_transformation_plan
[DEBUG] Found function: validate_transformation_plan_schema
[-] No valid plugin class or factory function found in transform
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin transform: No valid plugin class or factory function found in transform
[DEBUG] Looking for factory functions in logging_config
[DEBUG] Found function: setup_logging
[-] No valid plugin class or factory function found in logging_config
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin logging_config: No valid plugin class or factory function found in logging_config
[+] Loaded 5 plugin(s)
[*] Running plugin analysis phase...
{"timestamp": "2025-08-30 15:08:34", "level": "ERROR", "module": "go_packer_plugin", "message": "Analysis failed: character U+ffffff98 is not in range [U+0000; U+10ffff]", "filename": "go_packer_plugin.py", "lineno": 223, "process_id": 201948, "thread_id": 140705469626240}
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Plugin Analysis Results                                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
✓ entropy_analysis: Analysis completed
✓ string_extraction: Analysis completed
✓ packer: Analysis completed
✓ transmuter: Analysis completed
❌ go_binary_analyzer: Analysis failed: character U+ffffff98 is not in range [U+0000; U+10ffff]
────────────────────────────────────────────────────────────────────────────────
✅ Command completed successfully!

Press Enter to continue ():
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🎯 Target: ca_iter_packed_4_mxpkonlyteerz.exe                                                                                      │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────── 🛠️ Build-a-Binary Menu ───────────────────────────────────────────────────────╮
│                                                                                                                                    │
│   1           Quick Analysis               Fast section analysis and obfuscation suggestions                                       │
│   2           Deep Analysis                Comprehensive plugin-based analysis with reporting                                      │
│   3           Interactive Hex Viewer       Explore binary with interactive hex dump                                                │
│   4           Encoding Operations          Obfuscate specific sections with various encodings                                      │
│   5           Generate Reports             Create detailed analysis reports in multiple formats                                    │
│   6           Change Target                Select a different binary file                                                          │
│   b           Back                         Return to main start menu                                                               │
│   h           Help                         Show detailed help and examples                                                         │
│   q           Quit                         Exit the framework                                                                      │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

Select an option [1/2/3/4/5/6/b/h/q] (1): 1
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🔍 Quick Analysis Options                                                                                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Option   ┃ Description                    ┃ Command Preview                                                                        ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1        │ Section Analysis Only          │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --analyze-sections                           │
│ 2        │ Obfuscation Suggestions        │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --suggest-obfuscation                        │
│ 3        │ Both Analysis + Suggestions    │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --analyze-sections --suggest-obfuscation     │
│ 4        │ With Basic Hex View            │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --analyze-sections --suggest-obfuscation     │
│          │                                │ --hex-view                                                                             │
│ b        │ Back to Main Menu              │                                                                                        │
└──────────┴────────────────────────────────┴────────────────────────────────────────────────────────────────────────────────────────┘

Select quick analysis option [1/2/3/4/b] (3): 1

🚀 Executing: cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --analyze-sections
────────────────────────────────────────────────────────────────────────────────
<frozen runpy>:128: RuntimeWarning: 'cumpyl_package.cumpyl' found in sys.modules after import of package 'cumpyl_package', but prior to execution of 'cumpyl_package.cumpyl'; this may result in unpredictable behaviour
[+] Successfully loaded ca_iter_packed_4_mxpkonlyteerz.exe
[*] Discovered 22 plugin(s): analysis_utils, packer_plugin, config_manager, performance, format_strategies, cgo_packer_plugin, test_utils, plugin_registry, format_utils, transmuter_plugin, test_go_packer_plugin, string_extraction, entropy_analysis, crypto_utils, consolidated_utils, go_packer_plugin, doc_utils, exceptions, analysis, base_plugin, transform, logging_config
[DEBUG] Looking for factory functions in analysis_utils
[DEBUG] Found function: analyze_binary_sections
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[-] No valid plugin class or factory function found in analysis_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis_utils: No valid plugin class or factory function found in analysis_utils
[DEBUG] Looking for factory functions in packer_plugin
[DEBUG] Found function: calculate_entropy
[DEBUG] Found function: create_integrity_hash
[DEBUG] Found function: decrypt_bytes_aesgcm
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: encrypt_bytes_aesgcm
[DEBUG] Found function: get_plugin
[DEBUG] Checking factory function: get_plugin
[DEBUG] Factory function get_plugin returned instance: <class 'packer_plugin.PackerPlugin'>
[DEBUG] Factory function get_plugin is valid
[DEBUG] Looking for factory functions in config_manager
[-] No valid plugin class or factory function found in config_manager
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin config_manager: No valid plugin class or factory function found in config_manager
[DEBUG] Looking for factory functions in performance
[DEBUG] Found function: _get_memory_usage
[DEBUG] Found function: dataclass
[DEBUG] Found function: monitor_performance
[DEBUG] Found function: wraps
[-] No valid plugin class or factory function found in performance
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin performance: No valid plugin class or factory function found in performance
[DEBUG] Looking for factory functions in format_strategies
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in format_strategies
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_strategies: No valid plugin class or factory function found in format_strategies
[-] Failed to load plugin cgo_packer_plugin: attempted relative import with no known parent package
[DEBUG] Looking for factory functions in test_utils
[-] No valid plugin class or factory function found in test_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_utils: No valid plugin class or factory function found in test_utils
[DEBUG] Looking for factory functions in plugin_registry
[DEBUG] Found function: get_packer_plugin
[DEBUG] Found function: get_packer_transform_plugin
[-] No valid plugin class or factory function found in plugin_registry
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin plugin_registry: No valid plugin class or factory function found in plugin_registry
[DEBUG] Looking for factory functions in format_utils
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: section_permissions_from_program_headers
[-] No valid plugin class or factory function found in format_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_utils: No valid plugin class or factory function found in format_utils
[DEBUG] Looking for factory functions in test_go_packer_plugin
[DEBUG] Found function: get_analysis_plugin
[-] No valid plugin class or factory function found in test_go_packer_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_go_packer_plugin: No valid plugin class or factory function found in test_go_packer_plugin
[DEBUG] Looking for factory functions in crypto_utils
[DEBUG] Found function: default_backend
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: generate_metadata_key
[DEBUG] Found function: load_and_derive_key
[DEBUG] Found function: retry
[DEBUG] Found function: safe_hash
[-] No valid plugin class or factory function found in crypto_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin crypto_utils: No valid plugin class or factory function found in crypto_utils
[DEBUG] Looking for factory functions in consolidated_utils
[DEBUG] Found function: detect_format_enhanced
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: lru_cache
[-] No valid plugin class or factory function found in consolidated_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin consolidated_utils: No valid plugin class or factory function found in consolidated_utils
{"timestamp": "2025-08-30 15:08:46", "level": "INFO", "module": "plugin_registry", "message": "Registered analysis plugin: go_packer_plugin", "filename": "plugin_registry.py", "lineno": 21, "process_id": 201965, "thread_id": 140719067699072}
[DEBUG] Looking for factory functions in doc_utils
[DEBUG] Found function: documented_method
[-] No valid plugin class or factory function found in doc_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin doc_utils: No valid plugin class or factory function found in doc_utils
[DEBUG] Looking for factory functions in exceptions
[-] No valid plugin class or factory function found in exceptions
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin exceptions: No valid plugin class or factory function found in exceptions
[DEBUG] Looking for factory functions in analysis
[DEBUG] Found function: analyze_sections_for_packing
[DEBUG] Found function: find_go_build_id
[DEBUG] Found function: is_executable_section
[-] No valid plugin class or factory function found in analysis
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis: No valid plugin class or factory function found in analysis
[DEBUG] Looking for factory functions in base_plugin
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in base_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin base_plugin: No valid plugin class or factory function found in base_plugin
[DEBUG] Looking for factory functions in transform
[DEBUG] Found function: apply_transformation_plan
[DEBUG] Found function: create_transformation_plan
[DEBUG] Found function: generate_dry_run_report
[DEBUG] Found function: get_transformation_summary
[DEBUG] Found function: safe_hash
[DEBUG] Found function: validate
[DEBUG] Found function: validate_binary_object
[DEBUG] Found function: validate_transformation_plan
[DEBUG] Found function: validate_transformation_plan_schema
[-] No valid plugin class or factory function found in transform
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin transform: No valid plugin class or factory function found in transform
[DEBUG] Looking for factory functions in logging_config
[DEBUG] Found function: setup_logging
[-] No valid plugin class or factory function found in logging_config
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin logging_config: No valid plugin class or factory function found in logging_config
[+] Loaded 5 plugin(s)

[*] Section Analysis for ca_iter_packed_4_mxpkonlyteerz.exe
============================================================
[*] Suggested sections for encoding:
    - Safe: .rdata, .rodata, .data (non-executable data sections)
    - Use with caution: .text, .code (executable sections - will break program)
    - Avoid: .idata, .reloc (critical for program loading)

Section: .text
  Type: Executable Code
  Safe for encoding: No - Will break program
  Size: 215544 bytes
  Virtual Address: 0x1000
  Characteristics: 0x60000060
  Content Preview: c3 66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 48 83 ec 28 48 8b 05 05 c8 03 00 31 c9 c7 00 01
  ASCII Preview: .ff...........@.H..(H......1....

Section: .data
  Type: Data
  Safe for encoding: Yes
  Size: 2400 bytes
  Virtual Address: 0x36000
  Characteristics: 0xc0000040
  Content Preview: 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 8d 00 40 01 00 00 00 01 00 00 00 00 00 00 00
  ASCII Preview: ...................@............

Section: .rdata
  Type: Read-only Data
  Safe for encoding: Yes
  Size: 26704 bytes
  Virtual Address: 0x37000
  Characteristics: 0x40000040
  Content Preview: 9e ae fc ff ab ae fc ff a4 ae fc ff 9e ae fc ff bf ae fc ff e5 ae fc ff f2 ae fc ff 1a af fc ff
  ASCII Preview: ................................

Section: .pdata
  Type: Exception Data
  Safe for encoding: Use with caution
  Size: 4764 bytes
  Virtual Address: 0x3e000
  Characteristics: 0x40000040
  Content Preview: 00 10 00 00 01 10 00 00 00 00 04 00 10 10 00 00 3e 11 00 00 04 00 04 00 40 11 00 00 89 11 00 00
  ASCII Preview: ................>.......@.......

Section: .xdata
  Type: Exception Unwind Data
  Safe for encoding: Use with caution
  Size: 10128 bytes
  Virtual Address: 0x40000
  Characteristics: 0x40000040
  Content Preview: 01 00 00 00 01 04 01 00 04 42 00 00 01 04 01 00 04 62 00 00 01 0f 08 00 0f 01 13 00 08 30 07 60
  ASCII Preview: .........B.......b...........0.`

Section: .bss
  Type: Data
  Safe for encoding: Yes
  Size: 0 bytes
  Virtual Address: 0x43000
  Characteristics: 0xc0000080
  Content: Empty

Section: .idata
  Type: Import Data
  Safe for encoding: No - Critical for loading
  Size: 4312 bytes
  Virtual Address: 0x44000
  Characteristics: 0xc0000040
  Content Preview: a0 40 04 00 00 00 00 00 00 00 00 00 b8 4e 04 00 30 44 04 00 b0 40 04 00 00 00 00 00 00 00 00 00
  ASCII Preview: .@...........N..0D...@..........

Section: .CRT
  Type: Unknown
  Safe for encoding: No
  Size: 112 bytes
  Virtual Address: 0x46000
  Characteristics: 0xc0000040
  Content Preview: 00 00 00 00 00 00 00 00 40 11 00 40 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  ASCII Preview: ........@..@....................

Section: .tls
  Type: Unknown
  Safe for encoding: No
  Size: 16 bytes
  Virtual Address: 0x47000
  Characteristics: 0xc0000040
  Content Preview: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  ASCII Preview: ................

Section: .reloc
  Type: Relocation Data
  Safe for encoding: No - Critical for loading
  Size: 892 bytes
  Virtual Address: 0x48000
  Characteristics: 0x42000040
  Content Preview: 00 50 03 00 0c 00 00 00 d8 a9 00 00 00 60 03 00 10 00 00 00 10 a0 20 a0 08 a9 40 a9 00 80 03 00
  ASCII Preview: .P...........`........ ...@.....

Section: .stub
  Type: Unknown
  Safe for encoding: No
  Size: 22 bytes
  Virtual Address: 0x49000
  Characteristics: 0x60000020
  Content Preview: f3 0f 1e fa 48 c7 c7 2a 00 00 00 48 c7 c0 3c 00 00 00 0f 05 eb fe
  ASCII Preview: ....H..*...H..<.......

Section: .cpload
  Type: Unknown
  Safe for encoding: No
  Size: 351456 bytes
  Virtual Address: 0x4a000
  Characteristics: 0x40000040
  Content Preview: 8a f3 0b 1c ac 5d 05 d4 dc 0f 42 2c 66 23 1b e3 c9 14 ec 38 90 2a 81 42 58 9b 0d 06 c8 b2 76 a7
  ASCII Preview: .....]....B,f#.....8.*.BX.....v.

Section: .stub
  Type: Unknown
  Safe for encoding: No
  Size: 22 bytes
  Virtual Address: 0xa0000
  Characteristics: 0x60000020
  Content Preview: f3 0f 1e fa 48 c7 c7 2a 00 00 00 48 c7 c0 3c 00 00 00 0f 05 eb fe
  ASCII Preview: ....H..*...H..<.......

Section: .cpload
  Type: Unknown
  Safe for encoding: No
  Size: 703712 bytes
  Virtual Address: 0xa1000
  Characteristics: 0x40000040
  Content Preview: 84 4d 29 8e f2 25 60 20 71 d0 36 8e 2d 4d b1 7e ec b2 9c 2a c3 41 1d f8 c3 10 a8 08 19 3a 29 75
  ASCII Preview: .M)..%` q.6.-M.~...*.A.......:)u

Section: .stub
  Type: Unknown
  Safe for encoding: No
  Size: 22 bytes
  Virtual Address: 0x14d000
  Characteristics: 0x60000020
  Content Preview: f3 0f 1e fa 48 c7 c7 2a 00 00 00 48 c7 c0 3c 00 00 00 0f 05 eb fe
  ASCII Preview: ....H..*...H..<.......

Section: .cpload
  Type: Unknown
  Safe for encoding: No
  Size: 1408224 bytes
  Virtual Address: 0x14e000
  Characteristics: 0x40000040
  Content Preview: 9e 25 78 aa b6 8c 5a 77 5b f5 b9 48 87 ae b6 1a 7b 01 b9 57 6a de 25 89 81 e9 71 2f f4 37 34 92
  ASCII Preview: .%x...Zw[..H....{..Wj.%...q/.74.

Section: .stub
  Type: Unknown
  Safe for encoding: No
  Size: 22 bytes
  Virtual Address: 0x2a6000
  Characteristics: 0x60000020
  Content Preview: f3 0f 1e fa 48 c7 c7 2a 00 00 00 48 c7 c0 3c 00 00 00 0f 05 eb fe
  ASCII Preview: ....H..*...H..<.......

Section: .cpload
  Type: Unknown
  Safe for encoding: No
  Size: 2817760 bytes
  Virtual Address: 0x2a7000
  Characteristics: 0x40000040
  Content Preview: 34 86 c3 e2 44 8b 97 c8 75 b2 75 95 1a c1 ea be f9 32 8a 49 e2 80 3d 2d db 15 38 54 c7 f3 f4 76
  ASCII Preview: 4...D...u.u......2.I..=-..8T...v

Section: .stub
  Type: Unknown
  Safe for encoding: No
  Size: 22 bytes
  Virtual Address: 0x557000
  Characteristics: 0x60000020
  Content Preview: f3 0f 1e fa 48 c7 c7 2a 00 00 00 48 c7 c0 3c 00 00 00 0f 05 eb fe
  ASCII Preview: ....H..*...H..<.......

Section: .cpload
  Type: Unknown
  Safe for encoding: No
  Size: 5636320 bytes
  Virtual Address: 0x558000
  Characteristics: 0x40000040
  Content Preview: 18 d5 2f 99 99 95 4b c9 61 fe f4 d1 65 ca 5e c5 0d 74 2c 9e 1c 97 4d af 67 a8 d7 94 68 9b 45 54
  ASCII Preview: ../...K.a...e.^..t,...M.g...h.ET

────────────────────────────────────────────────────────────────────────────────
✅ Command completed successfully!

Press Enter to continue ():
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🎯 Target: ca_iter_packed_4_mxpkonlyteerz.exe                                                                                      │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────── 🛠️ Build-a-Binary Menu ───────────────────────────────────────────────────────╮
│                                                                                                                                    │
│   1           Quick Analysis               Fast section analysis and obfuscation suggestions                                       │
│   2           Deep Analysis                Comprehensive plugin-based analysis with reporting                                      │
│   3           Interactive Hex Viewer       Explore binary with interactive hex dump                                                │
│   4           Encoding Operations          Obfuscate specific sections with various encodings                                      │
│   5           Generate Reports             Create detailed analysis reports in multiple formats                                    │
│   6           Change Target                Select a different binary file                                                          │
│   b           Back                         Return to main start menu                                                               │
│   h           Help                         Show detailed help and examples                                                         │
│   q           Quit                         Exit the framework                                                                      │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

Select an option [1/2/3/4/5/6/b/h/q] (1): 1
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🔍 Quick Analysis Options                                                                                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Option   ┃ Description                    ┃ Command Preview                                                                        ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1        │ Section Analysis Only          │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --analyze-sections                           │
│ 2        │ Obfuscation Suggestions        │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --suggest-obfuscation                        │
│ 3        │ Both Analysis + Suggestions    │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --analyze-sections --suggest-obfuscation     │
│ 4        │ With Basic Hex View            │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --analyze-sections --suggest-obfuscation     │
│          │                                │ --hex-view                                                                             │
│ b        │ Back to Main Menu              │                                                                                        │
└──────────┴────────────────────────────────┴────────────────────────────────────────────────────────────────────────────────────────┘

Select quick analysis option [1/2/3/4/b] (3): 2

🚀 Executing: cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --suggest-obfuscation
────────────────────────────────────────────────────────────────────────────────
<frozen runpy>:128: RuntimeWarning: 'cumpyl_package.cumpyl' found in sys.modules after import of package 'cumpyl_package', but prior to execution of 'cumpyl_package.cumpyl'; this may result in unpredictable behaviour
[+] Successfully loaded ca_iter_packed_4_mxpkonlyteerz.exe
[*] Discovered 22 plugin(s): analysis_utils, packer_plugin, config_manager, performance, format_strategies, cgo_packer_plugin, test_utils, plugin_registry, format_utils, transmuter_plugin, test_go_packer_plugin, string_extraction, entropy_analysis, crypto_utils, consolidated_utils, go_packer_plugin, doc_utils, exceptions, analysis, base_plugin, transform, logging_config
[DEBUG] Looking for factory functions in analysis_utils
[DEBUG] Found function: analyze_binary_sections
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[-] No valid plugin class or factory function found in analysis_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis_utils: No valid plugin class or factory function found in analysis_utils
[DEBUG] Looking for factory functions in packer_plugin
[DEBUG] Found function: calculate_entropy
[DEBUG] Found function: create_integrity_hash
[DEBUG] Found function: decrypt_bytes_aesgcm
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: encrypt_bytes_aesgcm
[DEBUG] Found function: get_plugin
[DEBUG] Checking factory function: get_plugin
[DEBUG] Factory function get_plugin returned instance: <class 'packer_plugin.PackerPlugin'>
[DEBUG] Factory function get_plugin is valid
[DEBUG] Looking for factory functions in config_manager
[-] No valid plugin class or factory function found in config_manager
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin config_manager: No valid plugin class or factory function found in config_manager
[DEBUG] Looking for factory functions in performance
[DEBUG] Found function: _get_memory_usage
[DEBUG] Found function: dataclass
[DEBUG] Found function: monitor_performance
[DEBUG] Found function: wraps
[-] No valid plugin class or factory function found in performance
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin performance: No valid plugin class or factory function found in performance
[DEBUG] Looking for factory functions in format_strategies
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in format_strategies
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_strategies: No valid plugin class or factory function found in format_strategies
[-] Failed to load plugin cgo_packer_plugin: attempted relative import with no known parent package
[DEBUG] Looking for factory functions in test_utils
[-] No valid plugin class or factory function found in test_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_utils: No valid plugin class or factory function found in test_utils
[DEBUG] Looking for factory functions in plugin_registry
[DEBUG] Found function: get_packer_plugin
[DEBUG] Found function: get_packer_transform_plugin
[-] No valid plugin class or factory function found in plugin_registry
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin plugin_registry: No valid plugin class or factory function found in plugin_registry
[DEBUG] Looking for factory functions in format_utils
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: section_permissions_from_program_headers
[-] No valid plugin class or factory function found in format_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_utils: No valid plugin class or factory function found in format_utils
[DEBUG] Looking for factory functions in test_go_packer_plugin
[DEBUG] Found function: get_analysis_plugin
[-] No valid plugin class or factory function found in test_go_packer_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_go_packer_plugin: No valid plugin class or factory function found in test_go_packer_plugin
[DEBUG] Looking for factory functions in crypto_utils
[DEBUG] Found function: default_backend
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: generate_metadata_key
[DEBUG] Found function: load_and_derive_key
[DEBUG] Found function: retry
[DEBUG] Found function: safe_hash
[-] No valid plugin class or factory function found in crypto_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin crypto_utils: No valid plugin class or factory function found in crypto_utils
[DEBUG] Looking for factory functions in consolidated_utils
[DEBUG] Found function: detect_format_enhanced
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: lru_cache
[-] No valid plugin class or factory function found in consolidated_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin consolidated_utils: No valid plugin class or factory function found in consolidated_utils
{"timestamp": "2025-08-30 15:08:56", "level": "INFO", "module": "plugin_registry", "message": "Registered analysis plugin: go_packer_plugin", "filename": "plugin_registry.py", "lineno": 21, "process_id": 201974, "thread_id": 140715832526720}
[DEBUG] Looking for factory functions in doc_utils
[DEBUG] Found function: documented_method
[-] No valid plugin class or factory function found in doc_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin doc_utils: No valid plugin class or factory function found in doc_utils
[DEBUG] Looking for factory functions in exceptions
[-] No valid plugin class or factory function found in exceptions
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin exceptions: No valid plugin class or factory function found in exceptions
[DEBUG] Looking for factory functions in analysis
[DEBUG] Found function: analyze_sections_for_packing
[DEBUG] Found function: find_go_build_id
[DEBUG] Found function: is_executable_section
[-] No valid plugin class or factory function found in analysis
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis: No valid plugin class or factory function found in analysis
[DEBUG] Looking for factory functions in base_plugin
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in base_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin base_plugin: No valid plugin class or factory function found in base_plugin
[DEBUG] Looking for factory functions in transform
[DEBUG] Found function: apply_transformation_plan
[DEBUG] Found function: create_transformation_plan
[DEBUG] Found function: generate_dry_run_report
[DEBUG] Found function: get_transformation_summary
[DEBUG] Found function: safe_hash
[DEBUG] Found function: validate
[DEBUG] Found function: validate_binary_object
[DEBUG] Found function: validate_transformation_plan
[DEBUG] Found function: validate_transformation_plan_schema
[-] No valid plugin class or factory function found in transform
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin transform: No valid plugin class or factory function found in transform
[DEBUG] Looking for factory functions in logging_config
[DEBUG] Found function: setup_logging
[-] No valid plugin class or factory function found in logging_config
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin logging_config: No valid plugin class or factory function found in logging_config
[+] Loaded 5 plugin(s)
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                                                    │
│  Obfuscation Suggestions for ca_iter_packed_4_mxpkonlyteerz.exe                                                                    │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
⠴ Analyzing binary sections...
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Advanced Tier (Large, High-Impact Sections)                                                                                        │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┓
┃ Section ┃ Type           ┃ Size     ┃ Address ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━┩
│ .rdata  │ Read-only Data │ 26.08 KB │ 0x37000 │
└─────────┴────────────────┴──────────┴─────────┘

cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .rdata --encoding base64 -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe

╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Best for heavy obfuscation. Large capacity for complex encoding.                                                       │
│ Encoding Options: base64, compressed_base64, hex                                                                                   │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Intermediate Tier (Medium-Size Data Sections)                                                                                      │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━┳━━━━━━━━━┳━━━━━━━━━┓
┃ Section ┃ Type ┃ Size    ┃ Address ┃
┡━━━━━━━━━╇━━━━━━╇━━━━━━━━━╇━━━━━━━━━┩
│ .data   │ Data │ 2.34 KB │ 0x36000 │
│ .bss    │ Data │ 0 bytes │ 0x43000 │
└─────────┴──────┴─────────┴─────────┘

cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .data --encoding base64 -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe
cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .bss --encoding base64 -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe

╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Good for moderate obfuscation. Balanced size and safety.                                                               │
│ Encoding Options: base64, compressed_base64                                                                                        │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Basic Tier (Small, Low-Impact Sections)                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┓
┃ Section ┃ Type                  ┃ Size    ┃ Address ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━┩
│ .xdata  │ Exception Unwind Data │ 9.89 KB │ 0x40000 │
│ .pdata  │ Exception Data        │ 4.65 KB │ 0x3e000 │
└─────────┴───────────────────────┴─────────┴─────────┘

cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .xdata --encoding hex -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe
cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .pdata --encoding hex -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe

╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Suitable for light obfuscation. Small sections, minimal impact.                                                        │
│ Encoding Options: hex, octal                                                                                                       │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Avoid (Critical Sections)                                                                                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Section ┃ Type            ┃ Size      ┃ Address  ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━┩
│ .cpload │ Unknown         │ 5.38 MB   │ 0x558000 │
│ .cpload │ Unknown         │ 2.69 MB   │ 0x2a7000 │
│ .cpload │ Unknown         │ 1.34 MB   │ 0x14e000 │
│ .cpload │ Unknown         │ 687.22 KB │ 0xa1000  │
│ .cpload │ Unknown         │ 343.22 KB │ 0x4a000  │
│ .text   │ Executable Code │ 210.49 KB │ 0x1000   │
│ .idata  │ Import Data     │ 4.21 KB   │ 0x44000  │
│ .reloc  │ Relocation Data │ 892 bytes │ 0x48000  │
│ .CRT    │ Unknown         │ 112 bytes │ 0x46000  │
│ .stub   │ Unknown         │ 22 bytes  │ 0x49000  │
│ .stub   │ Unknown         │ 22 bytes  │ 0xa0000  │
│ .stub   │ Unknown         │ 22 bytes  │ 0x14d000 │
│ .stub   │ Unknown         │ 22 bytes  │ 0x2a6000 │
│ .stub   │ Unknown         │ 22 bytes  │ 0x557000 │
│ .tls    │ Unknown         │ 16 bytes  │ 0x47000  │
└─────────┴─────────────────┴───────────┴──────────┘
╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Critical for program execution. Avoid obfuscation.                                                                     │
│ DO NOT OBFUSCATE                                                                                                                   │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Overall Recommendations                                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
 Best section:  .rdata (Read-only Data)
 Size:          26704 bytes
 Command:       cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .rdata --encoding compressed_base64 -o
                obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe
╭───────────────────────────────────────────────────────────── WARNING ──────────────────────────────────────────────────────────────╮
│ Obfuscating executable sections (.text) will break the program. Use with extreme caution.                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
────────────────────────────────────────────────────────────────────────────────
✅ Command completed successfully!

Press Enter to continue ():
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🎯 Target: ca_iter_packed_4_mxpkonlyteerz.exe                                                                                      │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────── 🛠️ Build-a-Binary Menu ───────────────────────────────────────────────────────╮
│                                                                                                                                    │
│   1           Quick Analysis               Fast section analysis and obfuscation suggestions                                       │
│   2           Deep Analysis                Comprehensive plugin-based analysis with reporting                                      │
│   3           Interactive Hex Viewer       Explore binary with interactive hex dump                                                │
│   4           Encoding Operations          Obfuscate specific sections with various encodings                                      │
│   5           Generate Reports             Create detailed analysis reports in multiple formats                                    │
│   6           Change Target                Select a different binary file                                                          │
│   b           Back                         Return to main start menu                                                               │
│   h           Help                         Show detailed help and examples                                                         │
│   q           Quit                         Exit the framework                                                                      │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

Select an option [1/2/3/4/5/6/b/h/q] (1): 1
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🔍 Quick Analysis Options                                                                                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Option   ┃ Description                    ┃ Command Preview                                                                        ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1        │ Section Analysis Only          │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --analyze-sections                           │
│ 2        │ Obfuscation Suggestions        │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --suggest-obfuscation                        │
│ 3        │ Both Analysis + Suggestions    │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --analyze-sections --suggest-obfuscation     │
│ 4        │ With Basic Hex View            │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --analyze-sections --suggest-obfuscation     │
│          │                                │ --hex-view                                                                             │
│ b        │ Back to Main Menu              │                                                                                        │
└──────────┴────────────────────────────────┴────────────────────────────────────────────────────────────────────────────────────────┘

Select quick analysis option [1/2/3/4/b] (3): 3

🚀 Executing: cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --analyze-sections --suggest-obfuscation
────────────────────────────────────────────────────────────────────────────────
<frozen runpy>:128: RuntimeWarning: 'cumpyl_package.cumpyl' found in sys.modules after import of package 'cumpyl_package', but prior to execution of 'cumpyl_package.cumpyl'; this may result in unpredictable behaviour
[+] Successfully loaded ca_iter_packed_4_mxpkonlyteerz.exe
[*] Discovered 22 plugin(s): analysis_utils, packer_plugin, config_manager, performance, format_strategies, cgo_packer_plugin, test_utils, plugin_registry, format_utils, transmuter_plugin, test_go_packer_plugin, string_extraction, entropy_analysis, crypto_utils, consolidated_utils, go_packer_plugin, doc_utils, exceptions, analysis, base_plugin, transform, logging_config
[DEBUG] Looking for factory functions in analysis_utils
[DEBUG] Found function: analyze_binary_sections
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[-] No valid plugin class or factory function found in analysis_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis_utils: No valid plugin class or factory function found in analysis_utils
[DEBUG] Looking for factory functions in packer_plugin
[DEBUG] Found function: calculate_entropy
[DEBUG] Found function: create_integrity_hash
[DEBUG] Found function: decrypt_bytes_aesgcm
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: encrypt_bytes_aesgcm
[DEBUG] Found function: get_plugin
[DEBUG] Checking factory function: get_plugin
[DEBUG] Factory function get_plugin returned instance: <class 'packer_plugin.PackerPlugin'>
[DEBUG] Factory function get_plugin is valid
[DEBUG] Looking for factory functions in config_manager
[-] No valid plugin class or factory function found in config_manager
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin config_manager: No valid plugin class or factory function found in config_manager
[DEBUG] Looking for factory functions in performance
[DEBUG] Found function: _get_memory_usage
[DEBUG] Found function: dataclass
[DEBUG] Found function: monitor_performance
[DEBUG] Found function: wraps
[-] No valid plugin class or factory function found in performance
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin performance: No valid plugin class or factory function found in performance
[DEBUG] Looking for factory functions in format_strategies
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in format_strategies
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_strategies: No valid plugin class or factory function found in format_strategies
[-] Failed to load plugin cgo_packer_plugin: attempted relative import with no known parent package
[DEBUG] Looking for factory functions in test_utils
[-] No valid plugin class or factory function found in test_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_utils: No valid plugin class or factory function found in test_utils
[DEBUG] Looking for factory functions in plugin_registry
[DEBUG] Found function: get_packer_plugin
[DEBUG] Found function: get_packer_transform_plugin
[-] No valid plugin class or factory function found in plugin_registry
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin plugin_registry: No valid plugin class or factory function found in plugin_registry
[DEBUG] Looking for factory functions in format_utils
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: section_permissions_from_program_headers
[-] No valid plugin class or factory function found in format_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_utils: No valid plugin class or factory function found in format_utils
[DEBUG] Looking for factory functions in test_go_packer_plugin
[DEBUG] Found function: get_analysis_plugin
[-] No valid plugin class or factory function found in test_go_packer_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_go_packer_plugin: No valid plugin class or factory function found in test_go_packer_plugin
[DEBUG] Looking for factory functions in crypto_utils
[DEBUG] Found function: default_backend
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: generate_metadata_key
[DEBUG] Found function: load_and_derive_key
[DEBUG] Found function: retry
[DEBUG] Found function: safe_hash
[-] No valid plugin class or factory function found in crypto_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin crypto_utils: No valid plugin class or factory function found in crypto_utils
[DEBUG] Looking for factory functions in consolidated_utils
[DEBUG] Found function: detect_format_enhanced
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: lru_cache
[-] No valid plugin class or factory function found in consolidated_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin consolidated_utils: No valid plugin class or factory function found in consolidated_utils
{"timestamp": "2025-08-30 15:09:13", "level": "INFO", "module": "plugin_registry", "message": "Registered analysis plugin: go_packer_plugin", "filename": "plugin_registry.py", "lineno": 21, "process_id": 201984, "thread_id": 140121448335232}
[DEBUG] Looking for factory functions in doc_utils
[DEBUG] Found function: documented_method
[-] No valid plugin class or factory function found in doc_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin doc_utils: No valid plugin class or factory function found in doc_utils
[DEBUG] Looking for factory functions in exceptions
[-] No valid plugin class or factory function found in exceptions
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin exceptions: No valid plugin class or factory function found in exceptions
[DEBUG] Looking for factory functions in analysis
[DEBUG] Found function: analyze_sections_for_packing
[DEBUG] Found function: find_go_build_id
[DEBUG] Found function: is_executable_section
[-] No valid plugin class or factory function found in analysis
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis: No valid plugin class or factory function found in analysis
[DEBUG] Looking for factory functions in base_plugin
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in base_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin base_plugin: No valid plugin class or factory function found in base_plugin
[DEBUG] Looking for factory functions in transform
[DEBUG] Found function: apply_transformation_plan
[DEBUG] Found function: create_transformation_plan
[DEBUG] Found function: generate_dry_run_report
[DEBUG] Found function: get_transformation_summary
[DEBUG] Found function: safe_hash
[DEBUG] Found function: validate
[DEBUG] Found function: validate_binary_object
[DEBUG] Found function: validate_transformation_plan
[DEBUG] Found function: validate_transformation_plan_schema
[-] No valid plugin class or factory function found in transform
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin transform: No valid plugin class or factory function found in transform
[DEBUG] Looking for factory functions in logging_config
[DEBUG] Found function: setup_logging
[-] No valid plugin class or factory function found in logging_config
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin logging_config: No valid plugin class or factory function found in logging_config
[+] Loaded 5 plugin(s)
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                                                    │
│  Obfuscation Suggestions for ca_iter_packed_4_mxpkonlyteerz.exe                                                                    │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
⠴ Analyzing binary sections...
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Advanced Tier (Large, High-Impact Sections)                                                                                        │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┓
┃ Section ┃ Type           ┃ Size     ┃ Address ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━┩
│ .rdata  │ Read-only Data │ 26.08 KB │ 0x37000 │
└─────────┴────────────────┴──────────┴─────────┘

cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .rdata --encoding base64 -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe

╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Best for heavy obfuscation. Large capacity for complex encoding.                                                       │
│ Encoding Options: base64, compressed_base64, hex                                                                                   │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Intermediate Tier (Medium-Size Data Sections)                                                                                      │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━┳━━━━━━━━━┳━━━━━━━━━┓
┃ Section ┃ Type ┃ Size    ┃ Address ┃
┡━━━━━━━━━╇━━━━━━╇━━━━━━━━━╇━━━━━━━━━┩
│ .data   │ Data │ 2.34 KB │ 0x36000 │
│ .bss    │ Data │ 0 bytes │ 0x43000 │
└─────────┴──────┴─────────┴─────────┘

cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .data --encoding base64 -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe
cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .bss --encoding base64 -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe

╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Good for moderate obfuscation. Balanced size and safety.                                                               │
│ Encoding Options: base64, compressed_base64                                                                                        │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Basic Tier (Small, Low-Impact Sections)                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┓
┃ Section ┃ Type                  ┃ Size    ┃ Address ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━┩
│ .xdata  │ Exception Unwind Data │ 9.89 KB │ 0x40000 │
│ .pdata  │ Exception Data        │ 4.65 KB │ 0x3e000 │
└─────────┴───────────────────────┴─────────┴─────────┘

cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .xdata --encoding hex -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe
cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .pdata --encoding hex -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe

╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Suitable for light obfuscation. Small sections, minimal impact.                                                        │
│ Encoding Options: hex, octal                                                                                                       │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Avoid (Critical Sections)                                                                                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Section ┃ Type            ┃ Size      ┃ Address  ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━┩
│ .cpload │ Unknown         │ 5.38 MB   │ 0x558000 │
│ .cpload │ Unknown         │ 2.69 MB   │ 0x2a7000 │
│ .cpload │ Unknown         │ 1.34 MB   │ 0x14e000 │
│ .cpload │ Unknown         │ 687.22 KB │ 0xa1000  │
│ .cpload │ Unknown         │ 343.22 KB │ 0x4a000  │
│ .text   │ Executable Code │ 210.49 KB │ 0x1000   │
│ .idata  │ Import Data     │ 4.21 KB   │ 0x44000  │
│ .reloc  │ Relocation Data │ 892 bytes │ 0x48000  │
│ .CRT    │ Unknown         │ 112 bytes │ 0x46000  │
│ .stub   │ Unknown         │ 22 bytes  │ 0x49000  │
│ .stub   │ Unknown         │ 22 bytes  │ 0xa0000  │
│ .stub   │ Unknown         │ 22 bytes  │ 0x14d000 │
│ .stub   │ Unknown         │ 22 bytes  │ 0x2a6000 │
│ .stub   │ Unknown         │ 22 bytes  │ 0x557000 │
│ .tls    │ Unknown         │ 16 bytes  │ 0x47000  │
└─────────┴─────────────────┴───────────┴──────────┘
╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Critical for program execution. Avoid obfuscation.                                                                     │
│ DO NOT OBFUSCATE                                                                                                                   │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Overall Recommendations                                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
 Best section:  .rdata (Read-only Data)
 Size:          26704 bytes
 Command:       cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .rdata --encoding compressed_base64 -o
                obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe
╭───────────────────────────────────────────────────────────── WARNING ──────────────────────────────────────────────────────────────╮
│ Obfuscating executable sections (.text) will break the program. Use with extreme caution.                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
────────────────────────────────────────────────────────────────────────────────
✅ Command completed successfully!

Press Enter to continue ():
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🎯 Target: ca_iter_packed_4_mxpkonlyteerz.exe                                                                                      │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────── 🛠️ Build-a-Binary Menu ───────────────────────────────────────────────────────╮
│                                                                                                                                    │
│   1           Quick Analysis               Fast section analysis and obfuscation suggestions                                       │
│   2           Deep Analysis                Comprehensive plugin-based analysis with reporting                                      │
│   3           Interactive Hex Viewer       Explore binary with interactive hex dump                                                │
│   4           Encoding Operations          Obfuscate specific sections with various encodings                                      │
│   5           Generate Reports             Create detailed analysis reports in multiple formats                                    │
│   6           Change Target                Select a different binary file                                                          │
│   b           Back                         Return to main start menu                                                               │
│   h           Help                         Show detailed help and examples                                                         │
│   q           Quit                         Exit the framework                                                                      │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

Select an option [1/2/3/4/5/6/b/h/q] (1): 1
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🔍 Quick Analysis Options                                                                                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Option   ┃ Description                    ┃ Command Preview                                                                        ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1        │ Section Analysis Only          │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --analyze-sections                           │
│ 2        │ Obfuscation Suggestions        │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --suggest-obfuscation                        │
│ 3        │ Both Analysis + Suggestions    │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --analyze-sections --suggest-obfuscation     │
│ 4        │ With Basic Hex View            │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --analyze-sections --suggest-obfuscation     │
│          │                                │ --hex-view                                                                             │
│ b        │ Back to Main Menu              │                                                                                        │
└──────────┴────────────────────────────────┴────────────────────────────────────────────────────────────────────────────────────────┘

Select quick analysis option [1/2/3/4/b] (3): 4

🚀 Executing: cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --analyze-sections --suggest-obfuscation --hex-view
────────────────────────────────────────────────────────────────────────────────
<frozen runpy>:128: RuntimeWarning: 'cumpyl_package.cumpyl' found in sys.modules after import of package 'cumpyl_package', but prior to execution of 'cumpyl_package.cumpyl'; this may result in unpredictable behaviour
[+] Successfully loaded ca_iter_packed_4_mxpkonlyteerz.exe
[*] Discovered 22 plugin(s): analysis_utils, packer_plugin, config_manager, performance, format_strategies, cgo_packer_plugin, test_utils, plugin_registry, format_utils, transmuter_plugin, test_go_packer_plugin, string_extraction, entropy_analysis, crypto_utils, consolidated_utils, go_packer_plugin, doc_utils, exceptions, analysis, base_plugin, transform, logging_config
[DEBUG] Looking for factory functions in analysis_utils
[DEBUG] Found function: analyze_binary_sections
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[-] No valid plugin class or factory function found in analysis_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis_utils: No valid plugin class or factory function found in analysis_utils
[DEBUG] Looking for factory functions in packer_plugin
[DEBUG] Found function: calculate_entropy
[DEBUG] Found function: create_integrity_hash
[DEBUG] Found function: decrypt_bytes_aesgcm
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: encrypt_bytes_aesgcm
[DEBUG] Found function: get_plugin
[DEBUG] Checking factory function: get_plugin
[DEBUG] Factory function get_plugin returned instance: <class 'packer_plugin.PackerPlugin'>
[DEBUG] Factory function get_plugin is valid
[DEBUG] Looking for factory functions in config_manager
[-] No valid plugin class or factory function found in config_manager
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin config_manager: No valid plugin class or factory function found in config_manager
[DEBUG] Looking for factory functions in performance
[DEBUG] Found function: _get_memory_usage
[DEBUG] Found function: dataclass
[DEBUG] Found function: monitor_performance
[DEBUG] Found function: wraps
[-] No valid plugin class or factory function found in performance
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin performance: No valid plugin class or factory function found in performance
[DEBUG] Looking for factory functions in format_strategies
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in format_strategies
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_strategies: No valid plugin class or factory function found in format_strategies
[-] Failed to load plugin cgo_packer_plugin: attempted relative import with no known parent package
[DEBUG] Looking for factory functions in test_utils
[-] No valid plugin class or factory function found in test_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_utils: No valid plugin class or factory function found in test_utils
[DEBUG] Looking for factory functions in plugin_registry
[DEBUG] Found function: get_packer_plugin
[DEBUG] Found function: get_packer_transform_plugin
[-] No valid plugin class or factory function found in plugin_registry
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin plugin_registry: No valid plugin class or factory function found in plugin_registry
[DEBUG] Looking for factory functions in format_utils
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: section_permissions_from_program_headers
[-] No valid plugin class or factory function found in format_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_utils: No valid plugin class or factory function found in format_utils
[DEBUG] Looking for factory functions in test_go_packer_plugin
[DEBUG] Found function: get_analysis_plugin
[-] No valid plugin class or factory function found in test_go_packer_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_go_packer_plugin: No valid plugin class or factory function found in test_go_packer_plugin
[DEBUG] Looking for factory functions in crypto_utils
[DEBUG] Found function: default_backend
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: generate_metadata_key
[DEBUG] Found function: load_and_derive_key
[DEBUG] Found function: retry
[DEBUG] Found function: safe_hash
[-] No valid plugin class or factory function found in crypto_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin crypto_utils: No valid plugin class or factory function found in crypto_utils
[DEBUG] Looking for factory functions in consolidated_utils
[DEBUG] Found function: detect_format_enhanced
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: lru_cache
[-] No valid plugin class or factory function found in consolidated_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin consolidated_utils: No valid plugin class or factory function found in consolidated_utils
{"timestamp": "2025-08-30 15:09:22", "level": "INFO", "module": "plugin_registry", "message": "Registered analysis plugin: go_packer_plugin", "filename": "plugin_registry.py", "lineno": 21, "process_id": 201993, "thread_id": 140658898569088}
[DEBUG] Looking for factory functions in doc_utils
[DEBUG] Found function: documented_method
[-] No valid plugin class or factory function found in doc_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin doc_utils: No valid plugin class or factory function found in doc_utils
[DEBUG] Looking for factory functions in exceptions
[-] No valid plugin class or factory function found in exceptions
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin exceptions: No valid plugin class or factory function found in exceptions
[DEBUG] Looking for factory functions in analysis
[DEBUG] Found function: analyze_sections_for_packing
[DEBUG] Found function: find_go_build_id
[DEBUG] Found function: is_executable_section
[-] No valid plugin class or factory function found in analysis
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis: No valid plugin class or factory function found in analysis
[DEBUG] Looking for factory functions in base_plugin
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in base_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin base_plugin: No valid plugin class or factory function found in base_plugin
[DEBUG] Looking for factory functions in transform
[DEBUG] Found function: apply_transformation_plan
[DEBUG] Found function: create_transformation_plan
[DEBUG] Found function: generate_dry_run_report
[DEBUG] Found function: get_transformation_summary
[DEBUG] Found function: safe_hash
[DEBUG] Found function: validate
[DEBUG] Found function: validate_binary_object
[DEBUG] Found function: validate_transformation_plan
[DEBUG] Found function: validate_transformation_plan_schema
[-] No valid plugin class or factory function found in transform
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin transform: No valid plugin class or factory function found in transform
[DEBUG] Looking for factory functions in logging_config
[DEBUG] Found function: setup_logging
[-] No valid plugin class or factory function found in logging_config
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin logging_config: No valid plugin class or factory function found in logging_config
[+] Loaded 5 plugin(s)
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│                                                                                                                                    │
│  Obfuscation Suggestions for ca_iter_packed_4_mxpkonlyteerz.exe                                                                    │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
⠴ Analyzing binary sections...
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Advanced Tier (Large, High-Impact Sections)                                                                                        │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┓
┃ Section ┃ Type           ┃ Size     ┃ Address ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━┩
│ .rdata  │ Read-only Data │ 26.08 KB │ 0x37000 │
└─────────┴────────────────┴──────────┴─────────┘

cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .rdata --encoding base64 -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe

╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Best for heavy obfuscation. Large capacity for complex encoding.                                                       │
│ Encoding Options: base64, compressed_base64, hex                                                                                   │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Intermediate Tier (Medium-Size Data Sections)                                                                                      │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━┳━━━━━━━━━┳━━━━━━━━━┓
┃ Section ┃ Type ┃ Size    ┃ Address ┃
┡━━━━━━━━━╇━━━━━━╇━━━━━━━━━╇━━━━━━━━━┩
│ .data   │ Data │ 2.34 KB │ 0x36000 │
│ .bss    │ Data │ 0 bytes │ 0x43000 │
└─────────┴──────┴─────────┴─────────┘

cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .data --encoding base64 -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe
cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .bss --encoding base64 -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe

╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Good for moderate obfuscation. Balanced size and safety.                                                               │
│ Encoding Options: base64, compressed_base64                                                                                        │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Basic Tier (Small, Low-Impact Sections)                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┓
┃ Section ┃ Type                  ┃ Size    ┃ Address ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━┩
│ .xdata  │ Exception Unwind Data │ 9.89 KB │ 0x40000 │
│ .pdata  │ Exception Data        │ 4.65 KB │ 0x3e000 │
└─────────┴───────────────────────┴─────────┴─────────┘

cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .xdata --encoding hex -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe
cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .pdata --encoding hex -o obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe

╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Suitable for light obfuscation. Small sections, minimal impact.                                                        │
│ Encoding Options: hex, octal                                                                                                       │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Avoid (Critical Sections)                                                                                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Section ┃ Type            ┃ Size      ┃ Address  ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━┩
│ .cpload │ Unknown         │ 5.38 MB   │ 0x558000 │
│ .cpload │ Unknown         │ 2.69 MB   │ 0x2a7000 │
│ .cpload │ Unknown         │ 1.34 MB   │ 0x14e000 │
│ .cpload │ Unknown         │ 687.22 KB │ 0xa1000  │
│ .cpload │ Unknown         │ 343.22 KB │ 0x4a000  │
│ .text   │ Executable Code │ 210.49 KB │ 0x1000   │
│ .idata  │ Import Data     │ 4.21 KB   │ 0x44000  │
│ .reloc  │ Relocation Data │ 892 bytes │ 0x48000  │
│ .CRT    │ Unknown         │ 112 bytes │ 0x46000  │
│ .stub   │ Unknown         │ 22 bytes  │ 0x49000  │
│ .stub   │ Unknown         │ 22 bytes  │ 0xa0000  │
│ .stub   │ Unknown         │ 22 bytes  │ 0x14d000 │
│ .stub   │ Unknown         │ 22 bytes  │ 0x2a6000 │
│ .stub   │ Unknown         │ 22 bytes  │ 0x557000 │
│ .tls    │ Unknown         │ 16 bytes  │ 0x47000  │
└─────────┴─────────────────┴───────────┴──────────┘
╭───────────────────────────────────────────────────────── Recommendations ──────────────────────────────────────────────────────────╮
│ Suggestion: Critical for program execution. Avoid obfuscation.                                                                     │
│ DO NOT OBFUSCATE                                                                                                                   │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Overall Recommendations                                                                                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
 Best section:  .rdata (Read-only Data)
 Size:          26704 bytes
 Command:       cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --encode-section .rdata --encoding compressed_base64 -o
                obfuscated_ca_iter_packed_4_mxpkonlyteerz.exe
╭───────────────────────────────────────────────────────────── WARNING ──────────────────────────────────────────────────────────────╮
│ Obfuscating executable sections (.text) will break the program. Use with extreme caution.                                          │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
[*] Generating interactive hex view with integrated analysis...
[+] Report saved to: ca_iter_packed_4_mxpkonlyteerz_hex.html
[+] Interactive hex view with integrated analysis saved to: ca_iter_packed_4_mxpkonlyteerz_hex.html
────────────────────────────────────────────────────────────────────────────────
✅ Command completed successfully!

Press Enter to continue ():
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🎯 Target: ca_iter_packed_4_mxpkonlyteerz.exe                                                                                      │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────── 🛠️ Build-a-Binary Menu ───────────────────────────────────────────────────────╮
│                                                                                                                                    │
│   1           Quick Analysis               Fast section analysis and obfuscation suggestions                                       │
│   2           Deep Analysis                Comprehensive plugin-based analysis with reporting                                      │
│   3           Interactive Hex Viewer       Explore binary with interactive hex dump                                                │
│   4           Encoding Operations          Obfuscate specific sections with various encodings                                      │
│   5           Generate Reports             Create detailed analysis reports in multiple formats                                    │
│   6           Change Target                Select a different binary file                                                          │
│   b           Back                         Return to main start menu                                                               │
│   h           Help                         Show detailed help and examples                                                         │
│   q           Quit                         Exit the framework                                                                      │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

Select an option [1/2/3/4/5/6/b/h/q] (1): 3
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🔧 Interactive Hex Viewer Options                                                                                                  │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Option   ┃ Description                    ┃ Command/Action                                                                         ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1        │ Basic Hex View (HTML)          │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --hex-view                                   │
│ 2        │ Interactive Section Selection  │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --hex-view --hex-view-interactive            │
│          │ (HTML)                         │                                                                                        │
│ 3        │ Interactive Terminal Hex       │ Launch TUI hex viewer with navigation                                                  │
│          │ Viewer                         │                                                                                        │
│ 4        │ Hex + Full Analysis            │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --hex-view --run-analysis                    │
│          │                                │ --suggest-obfuscation                                                                  │
│ 5        │ Custom Range (specify offset)  │ Custom command builder                                                                 │
│ 6        │ View Specific Section          │ Custom section selector                                                                │
│ 7        │ Large File View (8KB)          │ cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --hex-view --hex-view-bytes 8192             │
│ b        │ Back to Main Menu              │                                                                                        │
└──────────┴────────────────────────────────┴────────────────────────────────────────────────────────────────────────────────────────┘

Select hex viewer option [1/2/3/4/5/6/7/b] (3): 2

🚀 Executing: cumpyl ca_iter_packed_4_mxpkonlyteerz.exe --hex-view --hex-view-interactive
────────────────────────────────────────────────────────────────────────────────
<frozen runpy>:128: RuntimeWarning: 'cumpyl_package.cumpyl' found in sys.modules after import of package 'cumpyl_package', but prior to execution of 'cumpyl_package.cumpyl'; this may result in unpredictable behaviour
[+] Successfully loaded ca_iter_packed_4_mxpkonlyteerz.exe
[*] Discovered 22 plugin(s): analysis_utils, packer_plugin, config_manager, performance, format_strategies, cgo_packer_plugin, test_utils, plugin_registry, format_utils, transmuter_plugin, test_go_packer_plugin, string_extraction, entropy_analysis, crypto_utils, consolidated_utils, go_packer_plugin, doc_utils, exceptions, analysis, base_plugin, transform, logging_config
[DEBUG] Looking for factory functions in analysis_utils
[DEBUG] Found function: analyze_binary_sections
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[-] No valid plugin class or factory function found in analysis_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis_utils: No valid plugin class or factory function found in analysis_utils
[DEBUG] Looking for factory functions in packer_plugin
[DEBUG] Found function: calculate_entropy
[DEBUG] Found function: create_integrity_hash
[DEBUG] Found function: decrypt_bytes_aesgcm
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: encrypt_bytes_aesgcm
[DEBUG] Found function: get_plugin
[DEBUG] Checking factory function: get_plugin
[DEBUG] Factory function get_plugin returned instance: <class 'packer_plugin.PackerPlugin'>
[DEBUG] Factory function get_plugin is valid
[DEBUG] Looking for factory functions in config_manager
[-] No valid plugin class or factory function found in config_manager
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin config_manager: No valid plugin class or factory function found in config_manager
[DEBUG] Looking for factory functions in performance
[DEBUG] Found function: _get_memory_usage
[DEBUG] Found function: dataclass
[DEBUG] Found function: monitor_performance
[DEBUG] Found function: wraps
[-] No valid plugin class or factory function found in performance
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin performance: No valid plugin class or factory function found in performance
[DEBUG] Looking for factory functions in format_strategies
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in format_strategies
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_strategies: No valid plugin class or factory function found in format_strategies
[-] Failed to load plugin cgo_packer_plugin: attempted relative import with no known parent package
[DEBUG] Looking for factory functions in test_utils
[-] No valid plugin class or factory function found in test_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_utils: No valid plugin class or factory function found in test_utils
[DEBUG] Looking for factory functions in plugin_registry
[DEBUG] Found function: get_packer_plugin
[DEBUG] Found function: get_packer_transform_plugin
[-] No valid plugin class or factory function found in plugin_registry
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin plugin_registry: No valid plugin class or factory function found in plugin_registry
[DEBUG] Looking for factory functions in format_utils
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: section_permissions_from_program_headers
[-] No valid plugin class or factory function found in format_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin format_utils: No valid plugin class or factory function found in format_utils
[DEBUG] Looking for factory functions in test_go_packer_plugin
[DEBUG] Found function: get_analysis_plugin
[-] No valid plugin class or factory function found in test_go_packer_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin test_go_packer_plugin: No valid plugin class or factory function found in test_go_packer_plugin
[DEBUG] Looking for factory functions in crypto_utils
[DEBUG] Found function: default_backend
[DEBUG] Found function: derive_secure_key
[DEBUG] Found function: generate_metadata_key
[DEBUG] Found function: load_and_derive_key
[DEBUG] Found function: retry
[DEBUG] Found function: safe_hash
[-] No valid plugin class or factory function found in crypto_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin crypto_utils: No valid plugin class or factory function found in crypto_utils
[DEBUG] Looking for factory functions in consolidated_utils
[DEBUG] Found function: detect_format_enhanced
[DEBUG] Found function: is_executable_section
[DEBUG] Found function: is_readable_section
[DEBUG] Found function: is_writable_section
[DEBUG] Found function: lru_cache
[-] No valid plugin class or factory function found in consolidated_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin consolidated_utils: No valid plugin class or factory function found in consolidated_utils
{"timestamp": "2025-08-30 15:09:39", "level": "INFO", "module": "plugin_registry", "message": "Registered analysis plugin: go_packer_plugin", "filename": "plugin_registry.py", "lineno": 21, "process_id": 202005, "thread_id": 140698414806912}
[DEBUG] Looking for factory functions in doc_utils
[DEBUG] Found function: documented_method
[-] No valid plugin class or factory function found in doc_utils
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin doc_utils: No valid plugin class or factory function found in doc_utils
[DEBUG] Looking for factory functions in exceptions
[-] No valid plugin class or factory function found in exceptions
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin exceptions: No valid plugin class or factory function found in exceptions
[DEBUG] Looking for factory functions in analysis
[DEBUG] Found function: analyze_sections_for_packing
[DEBUG] Found function: find_go_build_id
[DEBUG] Found function: is_executable_section
[-] No valid plugin class or factory function found in analysis
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin analysis: No valid plugin class or factory function found in analysis
[DEBUG] Looking for factory functions in base_plugin
[DEBUG] Found function: abstractmethod
[-] No valid plugin class or factory function found in base_plugin
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin base_plugin: No valid plugin class or factory function found in base_plugin
[DEBUG] Looking for factory functions in transform
[DEBUG] Found function: apply_transformation_plan
[DEBUG] Found function: create_transformation_plan
[DEBUG] Found function: generate_dry_run_report
[DEBUG] Found function: get_transformation_summary
[DEBUG] Found function: safe_hash
[DEBUG] Found function: validate
[DEBUG] Found function: validate_binary_object
[DEBUG] Found function: validate_transformation_plan
[DEBUG] Found function: validate_transformation_plan_schema
[-] No valid plugin class or factory function found in transform
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin transform: No valid plugin class or factory function found in transform
[DEBUG] Looking for factory functions in logging_config
[DEBUG] Found function: setup_logging
[-] No valid plugin class or factory function found in logging_config
    plugin_class: None
    plugin_factory: None
[-] Failed to load plugin logging_config: No valid plugin class or factory function found in logging_config
[+] Loaded 5 plugin(s)
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Available Sections for Hex View                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ Index ┃ Section ┃ Size      ┃ File Offset ┃ Virtual Address ┃
┡━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ 0     │ .text   │ 210.5 KB  │ 0x600       │ 0x1000          │
│ 1     │ .data   │ 2.5 KB    │ 0x35000     │ 0x36000         │
│ 2     │ .rdata  │ 26.5 KB   │ 0x35a00     │ 0x37000         │
│ 3     │ .pdata  │ 5.0 KB    │ 0x3c400     │ 0x3e000         │
│ 4     │ .xdata  │ 10.0 KB   │ 0x3d800     │ 0x40000         │
│ 5     │ .bss    │ 0 bytes   │ 0x200       │ 0x43000         │
│ 6     │ .idata  │ 4.5 KB    │ 0x40000     │ 0x44000         │
│ 7     │ .CRT    │ 512 bytes │ 0x41200     │ 0x46000         │
│ 8     │ .tls    │ 512 bytes │ 0x41400     │ 0x47000         │
│ 9     │ .reloc  │ 1.0 KB    │ 0x41600     │ 0x48000         │
│ 10    │ .stub   │ 512 bytes │ 0x41a00     │ 0x49000         │
│ 11    │ .cpload │ 343.5 KB  │ 0x41c00     │ 0x4a000         │
│ 12    │ .stub   │ 512 bytes │ 0x97a00     │ 0xa0000         │
│ 13    │ .cpload │ 687.5 KB  │ 0x97c00     │ 0xa1000         │
│ 14    │ .stub   │ 512 bytes │ 0x143a00    │ 0x14d000        │
│ 15    │ .cpload │ 1375.5 KB │ 0x143c00    │ 0x14e000        │
│ 16    │ .stub   │ 512 bytes │ 0x29ba00    │ 0x2a6000        │
│ 17    │ .cpload │ 2752.0 KB │ 0x29bc00    │ 0x2a7000        │
│ 18    │ .stub   │ 512 bytes │ 0x54bc00    │ 0x557000        │
│ 19    │ .cpload │ 5504.5 KB │ 0x54be00    │ 0x558000        │
└───────┴─────────┴───────────┴─────────────┴─────────────────┘

Options:
• Enter section index (0-19) to view specific section
• Enter 'all' to view all sections
• Enter offset range like '0x1000-0x2000' or '4096-8192'
• Press Enter for default view (first 2048 bytes)

Select option: all
[*] Generating interactive hex view with integrated analysis...
[+] Report saved to: ca_iter_packed_4_mxpkonlyteerz_hex.html
[+] Interactive hex view with integrated analysis saved to: ca_iter_packed_4_mxpkonlyteerz_hex.html
────────────────────────────────────────────────────────────────────────────────
✅ Command completed successfully!

Press Enter to continue ():
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ 🎯 Target: ca_iter_packed_4_mxpkonlyteerz.exe                                                                                      │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────── 🛠️ Build-a-Binary Menu ───────────────────────────────────────────────────────╮
│                                                                                                                                    │
│   1           Quick Analysis               Fast section analysis and obfuscation suggestions                                       │
│   2           Deep Analysis                Comprehensive plugin-based analysis with reporting                                      │
│   3           Interactive Hex Viewer       Explore binary with interactive hex dump                                                │
│   4           Encoding Operations          Obfuscate specific sections with various encodings                                      │
│   5           Generate Reports             Create detailed analysis reports in multiple formats                                    │
│   6           Change Target                Select a different binary file                                                          │
│   b           Back                         Return to main start menu                                                               │
│   h           Help                         Show detailed help and examples                                                         │
│   q           Quit                         Exit the framework                                                                      │
│                                                                                                                                    │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯

Select an option [1/2/3/4/5/6/b/h/q] (1):
