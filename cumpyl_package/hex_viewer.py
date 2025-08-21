import math
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import json
import asyncio

try:
    from textual.app import App, ComposeResult
    from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
    from textual.widgets import Footer, Header, Static, DataTable, Input, Button, Label
    from textual.reactive import reactive
    from textual.binding import Binding
    from textual.message import Message
    from textual.screen import ModalScreen
    from textual.events import Key
    from textual import on
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

try:
    from .config import ConfigManager
except ImportError:
    from config import ConfigManager


@dataclass
class HexViewAnnotation:
    """𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯 𐑓𐑹 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑚𐑲𐑑 𐑮𐑱𐑯𐑡 𐑦𐑯 𐑞 𐑣𐑧𐑒𐑕 𐑝𐑿"""
    start_offset: int
    end_offset: int
    annotation_type: str  # 'suggestion', 'analysis', 'section', 'string', 'entropy'
    title: str
    description: str
    severity: str = "info"  # 'info', 'warning', 'danger', 'success'
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class HexViewer:
    """𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑣𐑧𐑒𐑕 𐑛𐑳𐑥𐑐 𐑝𐑿𐑼 𐑢𐑦𐑞 𐑨𐑯𐑨𐑤𐑦𐑕𐑦𐑕 𐑴𐑝𐑼𐑤𐑱"""
    
    def __init__(self, config: ConfigManager = None, base_offset: int = 0):
        """𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟 𐑞 𐑣𐑧𐑒𐑕 𐑝𐑿𐑼"""
        self.config = config
        self.annotations: List[HexViewAnnotation] = []
        self.binary_data: bytes = b''
        self.bytes_per_row = 16
        self.show_ascii = True
        self.show_offsets = True
        self.base_offset = base_offset  # 𐑚𐑱𐑕 𐑪𐑓𐑕𐑧𐑑 𐑓𐑹 𐑛𐑦𐑕𐑐𐑤𐑱
        
        # 𐑑𐑧𐑒𐑕𐑑𐑿𐑩𐑤 𐑝𐑿𐑼 𐑕𐑑𐑱𐑑
        self.current_offset = 0
        self.display_rows = 30  # 𐑦𐑯𐑒𐑮𐑰𐑕 𐑓𐑹 𐑚𐑧𐑑𐑼 𐑝𐑦𐑿𐑦𐑙
        self.search_results: List[int] = []
        self.search_index = 0
        
    def load_binary_data(self, data: bytes):
        """𐑤𐑴𐑛 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩 𐑦𐑯𐑑 𐑞 𐑝𐑿𐑼"""
        self.binary_data = data
        
    def add_annotation(self, annotation: HexViewAnnotation):
        """𐑨𐑛 𐑩 𐑯𐑿 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯 𐑑 𐑞 𐑝𐑿𐑼"""
        self.annotations.append(annotation)
        
    def add_section_annotations(self, sections: List[Dict[str, Any]]):
        """𐑨𐑛 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑓𐑹 𐑚𐑲𐑯𐑩𐑮𐑦 𐑕𐑧𐑒𐑖𐑩𐑯𐑟"""
        for section in sections:
            if hasattr(section, 'name') and hasattr(section, 'size'):
                # 𐑿𐑟 𐑓𐑲𐑤 𐑪𐑓𐑕𐑧𐑑 𐑦𐑓 𐑩𐑝𐑱𐑤𐑩𐑚𐑩𐑤, 𐑷𐑞𐑼𐑢𐑲𐑟 𐑓𐑷𐑤 𐑚𐑨𐑒 𐑑 𐑝𐑻𐑗𐑫𐑩𐑤 𐑨𐑛𐑮𐑧𐑕
                file_offset = getattr(section, 'offset', getattr(section, 'virtual_address', 0))
                section_size = section.size
                
                annotation = HexViewAnnotation(
                    start_offset=file_offset,
                    end_offset=file_offset + section_size,
                    annotation_type="section",
                    title=f"Section: {section.name}",
                    description=f"Size: {section_size} bytes, FileOffset: 0x{file_offset:08x}, VAddr: 0x{getattr(section, 'virtual_address', 0):08x}",
                    severity="info",
                    metadata={
                        "section_name": section.name,
                        "file_offset": file_offset,
                        "virtual_address": getattr(section, 'virtual_address', 0),
                        "size": section_size,
                        "characteristics": getattr(section, 'characteristics', None)
                    }
                )
                self.add_annotation(annotation)
                
    def add_analysis_annotations(self, analysis_results: Dict[str, Any]):
        """𐑨𐑛 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑓𐑮𐑩𐑥 𐑩𐑯𐑨𐑤𐑦𐑕𐑦𐑕 𐑮𐑦𐑟𐑳𐑤𐑑𐑟"""
        # 𐑨𐑛 𐑩𐑯𐑑𐑮𐑴𐑐𐑦 𐑨𐑯𐑨𐑤𐑦𐑕𐑦𐑕 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟
        if 'entropy_analysis' in analysis_results:
            entropy_data = analysis_results['entropy_analysis']
            if isinstance(entropy_data, dict) and 'high_entropy_regions' in entropy_data:
                for region in entropy_data['high_entropy_regions']:
                    annotation = HexViewAnnotation(
                        start_offset=region['offset'],
                        end_offset=region['offset'] + region['size'],
                        annotation_type="entropy",
                        title=f"High Entropy Region",
                        description=f"Entropy: {region.get('entropy', 0):.2f} - Possibly packed/encrypted",
                        severity="warning",
                        metadata=region
                    )
                    self.add_annotation(annotation)
                    
        # 𐑨𐑛 𐑕𐑑𐑮𐑦𐑙 𐑩𐑝𐑕𐑑𐑮𐑨𐑒𐑖𐑩𐑯 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟
        if 'string_extraction' in analysis_results:
            string_data = analysis_results['string_extraction']
            if isinstance(string_data, dict):
                # ℌ𐑨𐑯𐑛𐑩𐑤 𐑯𐑿 𐑕𐑑𐑮𐑦𐑙 𐑩𐑝𐑕𐑑𐑮𐑨𐑒𐑖𐑩𐑯 𐑓𐑹𐑥𐑨𐑑
                if 'strings' in string_data:
                    for string_info in string_data['strings']:
                        if isinstance(string_info, dict) and 'offset' in string_info:
                            annotation = HexViewAnnotation(
                                start_offset=string_info['offset'],
                                end_offset=string_info['offset'] + len(string_info.get('value', '')),
                                annotation_type="string",
                                title=f"String: {string_info.get('value', '')[:20]}...",
                                description=f"String: {string_info.get('value', '')}",
                                severity="info",
                                metadata=string_info
                            )
                            self.add_annotation(annotation)
                            
                # ℌ𐑨𐑯𐑛𐑩𐑤 𐑴𐑤𐑛 𐑕𐑑𐑮𐑦𐑙 𐑩𐑝𐑕𐑑𐑮𐑨𐑒𐑖𐑩𐑯 𐑓𐑹𐑥𐑨𐑑 𐑢𐑦𐑞 𐑕𐑧𐑒𐑖𐑩𐑯𐑟
                elif 'sections' in string_data:
                    for section_name, section_result in string_data['sections'].items():
                        if isinstance(section_result, dict) and 'categorized_strings' in section_result:
                            for category, category_strings in section_result['categorized_strings'].items():
                                if isinstance(category_strings, list):
                                    for string_obj in category_strings:
                                        if isinstance(string_obj, dict) and 'offset' in string_obj:
                                            annotation = HexViewAnnotation(
                                                start_offset=string_obj['offset'],
                                                end_offset=string_obj['offset'] + string_obj.get('length', len(string_obj.get('value', ''))),
                                                annotation_type="string",
                                                title=f"String ({category}): {string_obj.get('value', '')[:20]}...",
                                                description=f"String: {string_obj.get('value', '')}",
                                                severity="info",
                                                metadata=string_obj
                                            )
                                            self.add_annotation(annotation)
    
    def add_obfuscation_suggestions(self, suggestions: List[Dict[str, Any]]):
        """𐑨𐑛 𐑪𐑚𐑓𐑳𐑕𐑒𐑱𐑖𐑩𐑯 𐑕𐑩𐑡𐑧𐑕𐑑𐑩𐑯 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟"""
        for suggestion in suggestions:
            if isinstance(suggestion, dict):
                section_name = suggestion.get('section_name', 'Unknown')
                start_offset = suggestion.get('start_offset', 0)
                end_offset = suggestion.get('end_offset', 0)
                tier = suggestion.get('tier', 'Unknown')
                risk = suggestion.get('risk', 'Unknown')
                
                severity_map = {
                    'Green (Advanced)': 'info',
                    'Yellow (Intermediate)': 'warning', 
                    'Blue (Basic)': 'info',
                    'Red (Avoid)': 'danger'
                }
                severity = severity_map.get(tier, 'info')
                
                annotation = HexViewAnnotation(
                    start_offset=start_offset,
                    end_offset=end_offset,
                    annotation_type="suggestion",
                    title=f"Obfuscation Suggestion: {section_name}",
                    description=f"Tier: {tier}, Risk: {risk}",
                    severity=severity,
                    metadata=suggestion
                )
                self.add_annotation(annotation)
                
    def generate_hex_dump_html(self, output_file: str = None, max_bytes: int = None) -> str:
        """𐑡𐑧𐑯𐑼𐑱𐑑 𐑞 ℌ𐑑𐑥𐑩𐑤 𐑣𐑧𐑒𐑕 𐑛𐑳𐑥𐑐"""
        if not self.binary_data:
            return "𐑯𐑴 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩 𐑤𐑴𐑛𐑦𐑛"
            
        if max_bytes is None:
            max_bytes = min(self.config.output.hex_viewer.max_display_bytes if self.config else 2048, len(self.binary_data))
            
        import tempfile
        if not output_file:
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.html')
            output_file = temp_file.name
            temp_file.close()
        
        data_to_show = self.binary_data[self.current_offset:self.current_offset + max_bytes]
        
        # 𐑡𐑧𐑯𐑼𐑱𐑑 ℌ𐑑𐑥𐑩𐑤 𐑒𐑪𐑯𐑑𐑧𐑯𐑑
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>CUMPYL Hex Viewer</title>
    <style>
        body {{
            font-family: 'Courier New', monospace;
            background-color: #0f0f23;
            color: #cccccc;
            margin: 20px;
            font-size: 12px;
            line-height: 1.4;
        }}
        .hex-container {{
            border: 1px solid #333;
            padding: 10px;
            background-color: #1a1a2e;
            border-radius: 5px;
            margin: 10px 0;
        }}
        .hex-line {{
            margin: 2px 0;
            white-space: pre;
        }}
        .offset {{
            color: #66d9ef;
            font-weight: bold;
        }}
        .hex-byte {{
            color: #e6e6e6;
        }}
        .hex-zero {{
            color: #666666;
        }}
        .ascii-printable {{
            color: #9fef00;
        }}
        .ascii-non-printable {{
            color: #444444;
        }}
        
        /* 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯 𐑒𐑩𐑤𐑼𐑟 */
        .section {{ background-color: rgba(253, 151, 31, 0.3); }}
        .string {{ background-color: rgba(166, 226, 46, 0.3); }}
        .entropy {{ background-color: rgba(249, 38, 114, 0.3); }}
        .suggestion {{ background-color: rgba(174, 129, 255, 0.3); }}
        
        .annotation-info {{
            background-color: #16213e;
            border: 1px solid #49483e;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
        }}
        
        .annotation-count {{
            color: #a6e22e;
            font-weight: bold;
        }}
        
        .tooltip {{
            position: relative;
            display: inline;
        }}
        
        .tooltip:hover::after {{
            content: attr(data-tooltip);
            position: absolute;
            background: #000;
            color: #fff;
            padding: 5px;
            border-radius: 3px;
            font-size: 10px;
            white-space: nowrap;
            z-index: 1000;
            bottom: 125%;
            left: 50%;
            margin-left: -60px;
        }}
    </style>
</head>
<body>
    <h2>🔥 CUMPYL Interactive Hex Viewer</h2>
    <div class="annotation-info">
        <div class="annotation-count">Total annotations: {len(self.annotations)}</div>
        <div>Displaying {len(data_to_show)} bytes (offset: 0x{self.base_offset + self.current_offset:08x})</div>
    </div>
    
    <div class="hex-container">
        <div class="hex-content">"""
        
        # 𐑡𐑧𐑯𐑼𐑱𐑑 𐑣𐑧𐑒𐑕 𐑤𐑲𐑯𐑟
        for i in range(0, len(data_to_show), self.bytes_per_row):
            row_data = data_to_show[i:i + self.bytes_per_row]
            row_offset = self.base_offset + self.current_offset + i
            html_content += self._generate_hex_row_html(row_offset, row_data)
            
        html_content += """
        </div>
    </div>
    
    <div class="annotation-info">
        <h3>Legend:</h3>
        <span class="section">■</span> Sections &nbsp;
        <span class="string">■</span> Strings &nbsp;
        <span class="entropy">■</span> High Entropy &nbsp;
        <span class="suggestion">■</span> Suggestions
    </div>
    
    <script>
        // 𐑨𐑛 𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝𐑦𐑑𐑦 𐑓𐑹 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟
        document.addEventListener('DOMContentLoaded', function() {
            const tooltips = document.querySelectorAll('.tooltip');
            tooltips.forEach(function(tooltip) {
                tooltip.addEventListener('mouseenter', function() {
                    // 𐑨𐑛 𐑨𐑯𐑦 𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑚𐑦𐑣𐑱𐑝𐑘𐑼 ℎ𐑽
                });
            });
        });
    </script>
</body>
</html>"""
        
        # 𐑮𐑲𐑑 ℌ𐑑𐑥𐑩𐑤 𐑓𐑲𐑤
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file
        
    def _generate_hex_row_html(self, offset: int, row_data: bytes) -> str:
        """𐑡𐑧𐑯𐑼𐑱𐑑 𐑩 𐑕𐑦𐑙𐑜𐑩𐑤 ℌ𐑑𐑥𐑩𐑤 𐑣𐑧𐑒𐑕 𐑮𐑴"""
        # 𐑪𐑓𐑕𐑧𐑑 𐑒𐑩𐑤𐑩𐑥
        offset_str = f'<span class="offset">{offset:08x}</span>'
        
        # ℌ𐑧𐑒𐑕 𐑚𐑲𐑑𐑟
        hex_bytes = []
        for i, byte_val in enumerate(row_data):
            byte_offset = offset + i
            annotations = self._get_annotations_for_offset(byte_offset)
            css_classes = self._get_css_classes_for_annotations(annotations)
            
            byte_class = "hex-zero" if byte_val == 0 else "hex-byte"
            
            if annotations:
                tooltip_text = "; ".join([ann.description for ann in annotations])
                hex_byte_html = f'<span class="{css_classes} tooltip" data-tooltip="{tooltip_text}">{byte_val:02x}</span>'
            else:
                hex_byte_html = f'<span class="{byte_class}">{byte_val:02x}</span>'
            
            hex_bytes.append(hex_byte_html)
            
        # 𐑐𐑨𐑛 𐑦𐑯𐑒𐑩𐑥𐑐𐑤𐑰𐑑 𐑮𐑴𐑟
        while len(hex_bytes) < self.bytes_per_row:
            hex_bytes.append('<span class="hex-byte">  </span>')
            
        hex_str = " ".join(hex_bytes)
        
        # ASCII 𐑮𐑦𐑐𐑮𐑦𐑟𐑧𐑯𐑑𐑱𐑖𐑩𐑯
        ascii_chars = []
        if self.show_ascii:
            for i, byte_val in enumerate(row_data):
                byte_offset = offset + i
                annotations = self._get_annotations_for_offset(byte_offset)
                css_classes = self._get_css_classes_for_annotations(annotations)
                
                if 32 <= byte_val <= 126:
                    char = chr(byte_val)
                    char_class = "ascii-printable"
                else:
                    char = "."
                    char_class = "ascii-non-printable"
                
                if annotations:
                    tooltip_text = "; ".join([ann.description for ann in annotations])
                    ascii_char_html = f'<span class="{css_classes} tooltip" data-tooltip="{tooltip_text}">{char}</span>'
                else:
                    ascii_char_html = f'<span class="{char_class}">{char}</span>'
                
                ascii_chars.append(ascii_char_html)
            
            # 𐑐𐑨𐑛 ASCII 𐑐𐑸𐑑
            while len(ascii_chars) < self.bytes_per_row:
                ascii_chars.append('<span class="ascii-non-printable"> </span>')
                
        ascii_str = "".join(ascii_chars)
        
        return f'<div class="hex-line">{offset_str}  {hex_str}  |{ascii_str}|</div>\n'
        
    def _get_annotations_for_offset(self, offset: int) -> List[HexViewAnnotation]:
        """𐑜𐑧𐑑 𐑩𐑤 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑓𐑹 𐑩 𐑜𐑦𐑝𐑩𐑯 𐑪𐑓𐑕𐑧𐑑"""
        annotations = []
        for annotation in self.annotations:
            if annotation.start_offset <= offset < annotation.end_offset:
                annotations.append(annotation)
        return annotations
        
    def _get_css_classes_for_annotations(self, annotations: List[HexViewAnnotation]) -> str:
        """𐑜𐑧𐑑 CSS 𐑒𐑤𐑨𐑕𐑩𐑟 𐑓𐑹 𐑩 𐑤𐑦𐑕𐑑 𐑝 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟"""
        if not annotations:
            return ""
        
        classes = []
        for annotation in annotations:
            classes.append(annotation.annotation_type)
            
        return " ".join(set(classes))  # 𐑮𐑰𐑥𐑿𐑝 𐑛𐑿𐑐𐑤𐑦𐑒𐑩𐑑𐑕
        
    def generate_textual_hex_view(self, max_bytes: int = None) -> str:
        """𐑡𐑧𐑯𐑼𐑱𐑑 𐑑𐑧𐑒𐑕𐑑𐑿𐑩𐑤 𐑣𐑧𐑒𐑕 𐑝𐑿 𐑦𐑯 𐑓𐑹𐑥𐑨𐑑"""
        if not self.binary_data:
            return "𐑯𐑴 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩 𐑤𐑴𐑛𐑦𐑛"
            
        if max_bytes is None:
            max_bytes = min(self.config.output.hex_viewer.max_display_bytes if self.config else 2048, len(self.binary_data))
            
        data_to_show = self.binary_data[self.current_offset:self.current_offset + max_bytes]
        hex_lines = []
        
        for i in range(0, len(data_to_show), self.bytes_per_row):
            row_data = data_to_show[i:i + self.bytes_per_row]
            row_offset = self.base_offset + self.current_offset + i
            hex_line = self._generate_textual_hex_row(row_offset, row_data)
            hex_lines.append(hex_line)
            
        return "\n".join(hex_lines)
        
    def _generate_textual_hex_row(self, offset: int, row_data: bytes) -> str:
        """𐑡𐑧𐑯𐑼𐑱𐑑 𐑩 𐑕𐑦𐑙𐑜𐑩𐑤 𐑣𐑧𐑒𐑕 𐑮𐑴 𐑓𐑹 𐑑𐑧𐑒𐑕𐑑𐑿𐑩𐑤 𐑛𐑦𐑕𐑐𐑤𐑱"""
        # 𐑪𐑓𐑕𐑧𐑑 𐑒𐑩𐑤𐑩𐑥
        offset_str = f"{offset:08x}"
        
        # ℌ𐑧𐑒𐑕 𐑚𐑲𐑑𐑟
        hex_bytes = []
        for byte_val in row_data:
            annotations = self._get_annotations_for_offset(offset + len(hex_bytes))
            color_code = self._get_color_code_for_annotations(annotations)
            hex_bytes.append(f"{color_code}{byte_val:02x}[/]")
            
        # 𐑐𐑨𐑛 𐑦𐑯𐑒𐑩𐑥𐑐𐑤𐑰𐑑 𐑮𐑴𐑟
        while len(hex_bytes) < self.bytes_per_row:
            hex_bytes.append("  ")
            
        hex_str = " ".join(hex_bytes)
        
        # ASCII 𐑮𐑦𐑐𐑮𐑦𐑟𐑧𐑯𐑑𐑱𐑖𐑩𐑯
        ascii_chars = []
        if self.show_ascii:
            for i, byte_val in enumerate(row_data):
                byte_offset = offset + i
                annotations = self._get_annotations_for_offset(byte_offset)
                color_code = self._get_color_code_for_annotations(annotations)
                
                if 32 <= byte_val <= 126:
                    char = chr(byte_val)
                else:
                    char = "."
                    
                ascii_chars.append(f"{color_code}{char}[/]")
            
            # 𐑐𐑨𐑛 ASCII 𐑐𐑸𐑑 𐑓𐑹 𐑒𐑩𐑯𐑕𐑦𐑕𐑑𐑩𐑯𐑑 𐑢𐑦𐑛𐑔
            while len(ascii_chars) < self.bytes_per_row:
                ascii_chars.append(" ")
                
        ascii_str = "".join(ascii_chars)
        
        return f'[cyan]{offset_str}[/]  {hex_str}  |{ascii_str}|'
        
    def _get_color_code_for_annotations(self, annotations: List[HexViewAnnotation]) -> str:
        """𐑜𐑧𐑑 𐑑𐑧𐑒𐑕𐑑𐑿𐑩𐑤 𐑒𐑩𐑤𐑼 𐑒𐑴𐑛 𐑓𐑹 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟"""
        if not annotations:
            return "[white]"
        
        # 𐑕𐑪𐑮𐑑 𐑚𐑲 𐑐𐑮𐑲𐑪𐑮𐑦𐑑𐑦: 𐑕𐑩𐑡𐑧𐑕𐑑𐑩𐑯 > 𐑩𐑯𐑑𐑮𐑴𐑐𐑦 > 𐑕𐑑𐑮𐑦𐑙 > 𐑕𐑧𐑒𐑖𐑩𐑯
        priority_map = {
            'suggestion': 4,
            'entropy': 3,  
            'string': 2,
            'section': 1
        }
        
        # 𐑓𐑦𐑯𐑛 𐑣𐑲𐑩𐑕𐑑 𐑐𐑮𐑲𐑪𐑮𐑦𐑑𐑦 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯
        highest_annotation = max(annotations, key=lambda ann: priority_map.get(ann.annotation_type, 0))
        
        color_map = {
            'section': '[blue]',
            'string': '[green]', 
            'entropy': '[yellow]',
            'suggestion': '[red]'
        }
        
        return color_map.get(highest_annotation.annotation_type, '[white]')
        
    def scroll_up(self):
        """𐑕𐑒𐑮𐑴𐑤 𐑞 𐑣𐑧𐑒𐑕 𐑝𐑿 𐑳𐑐"""
        if self.current_offset > 0:
            self.current_offset = max(0, self.current_offset - self.bytes_per_row * self.display_rows // 2)
    
    def scroll_down(self):
        """𐑕𐑒𐑮𐑴𐑤 𐑞 𐑣𐑧𐑒𐑕 𐑝𐑿 𐑛𐑬𐑯"""
        max_offset = len(self.binary_data) - self.bytes_per_row * self.display_rows
        if self.current_offset < max_offset:
            self.current_offset = min(max_offset, self.current_offset + self.bytes_per_row * self.display_rows // 2)
            
    def goto_offset(self, offset: int):
        """𐑜𐑴 𐑑 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑪𐑓𐑕𐑧𐑑"""
        if 0 <= offset < len(self.binary_data):
            self.current_offset = offset - (offset % self.bytes_per_row)  # 𐑩𐑤𐑲𐑯 𐑑 𐑮𐑴 𐑚𐑬𐑯𐑛𐑼𐑦
    
    def search_hex(self, hex_string: str) -> int:
        """𐑕𐑻𐑗 𐑓𐑹 𐑣𐑧𐑒𐑕 𐑚𐑲𐑑𐑟 𐑦𐑯 𐑞 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩"""
        try:
            search_bytes = bytes.fromhex(hex_string.replace(' ', ''))
            self.search_results = []
            
            for i in range(len(self.binary_data) - len(search_bytes) + 1):
                if self.binary_data[i:i + len(search_bytes)] == search_bytes:
                    self.search_results.append(i)
                    
            self.search_index = 0
            return len(self.search_results)
        except ValueError:
            return 0
    
    def search_string(self, search_string: str) -> int:
        """𐑕𐑻𐑗 𐑓𐑹 𐑩 𐑕𐑑𐑮𐑦𐑙 𐑦𐑯 𐑞 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩"""
        search_bytes = search_string.encode('utf-8', errors='ignore')
        self.search_results = []
        
        for i in range(len(self.binary_data) - len(search_bytes) + 1):
            if self.binary_data[i:i + len(search_bytes)] == search_bytes:
                self.search_results.append(i)
                
        self.search_index = 0
        return len(self.search_results)
    
    def next_search_result(self):
        """𐑜𐑴 𐑑 𐑞 𐑯𐑧𐑒𐑕𐑑 𐑕𐑻𐑗 𐑮𐑦𐑟𐑳𐑤𐑑"""
        if self.search_results and self.search_index < len(self.search_results) - 1:
            self.search_index += 1
            self.goto_offset(self.search_results[self.search_index])
            return True
        return False
            
    def prev_search_result(self):
        """𐑜𐑴 𐑑 𐑞 𐑐𐑮𐑰𐑝𐑦𐑩𐑕 𐑕𐑻𐑗 𐑮𐑦𐑟𐑳𐑤𐑑"""
        if self.search_results and self.search_index > 0:
            self.search_index -= 1
            self.goto_offset(self.search_results[self.search_index])
            return True
        return False


# 𐑑𐑧𐑒𐑕𐑑𐑿𐑩𐑤 𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 ℌ𐑧𐑒𐑕 𐑝𐑿𐑼 (if textual is available)
if TEXTUAL_AVAILABLE:
    
    class TextualHexViewer(Static):
        """𐑑𐑧𐑒𐑕𐑑𐑿𐑩𐑤 ℌ𐑧𐑒𐑕 𐑝𐑿𐑼 𐑢𐑦𐑡𐑧𐑑"""
        
        def __init__(self, hex_viewer: HexViewer, **kwargs):
            # Initialize the Static widget with the hex content
            hex_content = hex_viewer.generate_textual_hex_view()
            super().__init__(hex_content, **kwargs)
            self.hex_viewer = hex_viewer
    
    
    class HexSearchDialog(ModalScreen[str]):
        """ℌ𐑧𐑒𐑕 𐑕𐑻𐑗 𐑛𐑲𐑩𐑤𐑪𐑜"""
        
        BINDINGS = [
            Binding("escape", "dismiss", "Cancel"),
            Binding("enter", "search", "Search"),
        ]
        
        def compose(self) -> ComposeResult:
            with Container(id="search-dialog"):
                yield Label("Search for hex bytes or string:", id="search-label")
                yield Input(placeholder="Enter hex (e.g. 4D5A) or string", id="search-input")
                with Horizontal():
                    yield Button("Search Hex", variant="primary", id="search-hex")
                    yield Button("Search String", variant="primary", id="search-string")
                    yield Button("Cancel", variant="default", id="cancel")
                    
        def action_dismiss(self):
            self.dismiss("")
            
        def action_search(self):
            input_widget = self.query_one("#search-input", Input)
            self.dismiss(input_widget.value)
        
        @on(Button.Pressed, "#search-hex")
        def search_hex_pressed(self):
            input_widget = self.query_one("#search-input", Input)
            self.dismiss(f"hex:{input_widget.value}")
            
        @on(Button.Pressed, "#search-string")  
        def search_string_pressed(self):
            input_widget = self.query_one("#search-input", Input)
            self.dismiss(f"string:{input_widget.value}")
            
        @on(Button.Pressed, "#cancel")
        def cancel_pressed(self):
            self.dismiss("")
    
    
    class InteractiveHexViewerApp(App):
        """𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 ℌ𐑧𐑒𐑕 𐑝𐑿𐑼 𐑨𐑐"""
        
        CSS = """
        /* CUMPYL Enhanced Textual Hex Viewer Styles */
        Screen {
            background: $background;
        }

        /* Full-width hex display with proper padding */
        #hex-display {
            width: 100%;
            height: 100%;
            background: $surface;
            margin: 0;
            padding: 0 1;
            scrollbar-size: 1 1;
        }
        
        #search-dialog {
            align: center middle;
            background: $panel;
            border: thick $primary;
            width: 60;
            height: auto;
            padding: 1;
        }
        
        #search-label {
            margin-bottom: 1;
        }
        
        #search-input {
            margin-bottom: 1;
        }
        """
        
        TITLE = "🔥 CUMPYL Interactive Hex Viewer"
        
        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("j,down", "scroll_down", "Scroll down"),
            Binding("k,up", "scroll_up", "Scroll up"),
            Binding("g", "goto_top", "Go to top"),
            Binding("shift+g", "goto_bottom", "Go to bottom"),
            Binding("f,slash", "search", "Search"),
            Binding("n", "next_search", "Next result"),
            Binding("shift+n", "prev_search", "Previous result"),
            Binding("r", "refresh", "Refresh"),
            Binding("a", "show_annotations", "Show annotations"),
        ]
        
        def __init__(self, hex_viewer: HexViewer, **kwargs):
            super().__init__(**kwargs)
            self.hex_viewer = hex_viewer
            
        def compose(self) -> ComposeResult:
            """𐑒𐑩𐑥𐑐𐑴𐑟 𐑞 𐑨𐑐 𐑦𐑯𐑑𐑼𐑓𐑱𐑕"""
            yield Header(show_clock=True)
            yield TextualHexViewer(self.hex_viewer, id="hex-viewer")
            yield Footer()
            
        def action_quit(self):
            """𐑒𐑢𐑦𐑑 𐑞 𐑨𐑐"""
            self.exit()
            
        def action_scroll_down(self):
            """𐑕𐑒𐑮𐑴𐑤 𐑞 ℌ𐑧𐑒𐑕 𐑝𐑿 𐑛𐑬𐑯"""
            self.hex_viewer.scroll_down()
            self._refresh_display()
            
        def action_scroll_up(self):
            """𐑕𐑒𐑮𐑴𐑤 𐑞 ℌ𐑧𐑒𐑕 𐑝𐑿 𐑳𐑐"""
            self.hex_viewer.scroll_up()
            self._refresh_display()
            
        def action_goto_top(self):
            """𐑜𐑴 𐑑 𐑞 𐑑𐑪𐑐 𐑝 𐑞 ℌ𐑧𐑒𐑕 𐑝𐑿"""
            self.hex_viewer.current_offset = 0
            self._refresh_display()
            
        def action_goto_bottom(self):
            """𐑜𐑴 𐑑 𐑞 𐑚𐑪𐑑𐑩𐑥 𐑝 𐑞 ℌ𐑧𐑒𐑕 𐑝𐑿"""
            max_offset = max(0, len(self.hex_viewer.binary_data) - self.hex_viewer.bytes_per_row * self.hex_viewer.display_rows)
            self.hex_viewer.current_offset = max_offset
            self._refresh_display()
            
        def action_search(self):
            """𐑴𐑐𐑩𐑯 𐑞 𐑕𐑻𐑗 𐑛𐑲𐑩𐑤𐑪𐑜"""
            def handle_search_result(search_term: str) -> None:
                if not search_term:
                    return
                    
                if search_term.startswith("hex:"):
                    hex_term = search_term[4:]
                    results = self.hex_viewer.search_hex(hex_term)
                    self.notify(f"Found {results} hex matches for: {hex_term}")
                elif search_term.startswith("string:"):
                    string_term = search_term[7:]
                    results = self.hex_viewer.search_string(string_term)
                    self.notify(f"Found {results} string matches for: {string_term}")
                else:
                    # 𐑑𐑮𐑲 𐑚𐑴𐑔 ℌ𐑧𐑒𐑕 𐑯 𐑕𐑑𐑮𐑦𐑙
                    hex_results = self.hex_viewer.search_hex(search_term)
                    string_results = self.hex_viewer.search_string(search_term)
                    total_results = hex_results + string_results
                    self.notify(f"Found {total_results} total matches (hex: {hex_results}, string: {string_results})")
                
                # 𐑜𐑴 𐑑 𐑞 𐑓𐑻𐑕𐑑 𐑮𐑦𐑟𐑳𐑤𐑑
                if self.hex_viewer.search_results:
                    self.hex_viewer.goto_offset(self.hex_viewer.search_results[0])
                    self._refresh_display()
            
            self.push_screen(HexSearchDialog(), handle_search_result)
            
        def action_next_search(self):
            """𐑜𐑴 𐑑 𐑞 𐑯𐑧𐑒𐑕𐑑 𐑕𐑻𐑗 𐑮𐑦𐑟𐑳𐑤𐑑"""
            if self.hex_viewer.next_search_result():
                self._refresh_display()
                current = self.hex_viewer.search_index + 1
                total = len(self.hex_viewer.search_results)
                self.notify(f"Search result {current}/{total}")
            else:
                self.notify("No more search results")
                
        def action_prev_search(self):
            """𐑜𐑴 𐑑 𐑞 𐑐𐑮𐑰𐑝𐑦𐑩𐑕 𐑕𐑻𐑗 𐑮𐑦𐑟𐑳𐑤𐑑"""
            if self.hex_viewer.prev_search_result():
                self._refresh_display()
                current = self.hex_viewer.search_index + 1
                total = len(self.hex_viewer.search_results)
                self.notify(f"Search result {current}/{total}")
            else:
                self.notify("No previous search results")
                
        def action_refresh(self):
            """𐑮𐑰𐑓𐑮𐑧𐑖 𐑞 ℌ𐑧𐑒𐑕 𐑛𐑦𐑕𐑐𐑤𐑱 𐑯 𐑮𐑰𐑤𐑴𐑛 𐑒𐑩𐑤𐑼 𐑕𐑒𐑦𐑥"""
            # Refresh the hex display and reload any color scheme changes
            self._refresh_display()
            # Force a complete re-render by invalidating the screen
            self.refresh(layout=True)
            self.notify("Hex view and palette refreshed")
            
        def action_show_annotations(self):
            """𐑖𐑴 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯 𐑦𐑯𐑓𐑹𐑥𐑱𐑖𐑩𐑯"""
            annotation_count = len(self.hex_viewer.annotations)
            
            # 𐑒𐑬𐑯𐑑 𐑞 𐑞 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 ℌ𐑞 𐑤 𐑦 𐑞 𐑒𐑹𐑩𐑯𐑑 𐑦
            current_annotations = []
            start_offset = self.hex_viewer.base_offset + self.hex_viewer.current_offset
            end_offset = start_offset + self.hex_viewer.bytes_per_row * self.hex_viewer.display_rows
            
            for annotation in self.hex_viewer.annotations:
                if (annotation.start_offset <= end_offset and annotation.end_offset >= start_offset):
                    current_annotations.append(annotation)
                    
            self.notify(f"Total annotations: {annotation_count}, Visible: {len(current_annotations)}")
            
        def _refresh_display(self):
            """𐑮𐑰𐑓𐑮𐑧𐑖 𐑞 ℌ𐑧𐑒𐑕 𐑛𐑦𐑕𐑐𐑤𐑱"""
            hex_viewer_widget = self.query_one("#hex-viewer", TextualHexViewer)
            hex_viewer_widget.update(self.hex_viewer.generate_textual_hex_view())


def launch_textual_hex_viewer(file_path: str):
    """𐑤𐑷𐑯𐑗 𐑞 𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑑𐑧𐑒𐑕𐑑𐑿𐑩𐑤 ℌ𐑧𐑒𐑕 𐑝𐑿𐑼"""
    if not TEXTUAL_AVAILABLE:
        raise ImportError("Textual package is required for interactive hex viewer. Install with: pip install textual")
    
    import os
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    try:
        # 𐑤𐑴𐑛 𐑞 𐑓𐑲𐑤 𐑯 𐑒𐑮𐑦𐑱𐑑 ℌ𐑧𐑒𐑕 𐑝𐑿𐑼
        from .config import get_config
        from .cumpyl import BinaryRewriter
        
        config = get_config()
        hex_viewer = HexViewer(config)
        
        with open(file_path, 'rb') as f:
            binary_data = f.read()
        hex_viewer.load_binary_data(binary_data)
        
        # 𐑮𐑳𐑯 𐑩𐑯𐑨𐑤𐑦𐑕𐑦𐑕 𐑞 ℌ𐑧𐑒𐑕 𐑝𐑿𐑼
        rewriter = BinaryRewriter(file_path, config)
        if rewriter.load_binary():
            # 𐑨𐑛 𐑕𐑧𐑒𐑖𐑩𐑯 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟
            hex_viewer.add_section_annotations(rewriter.binary.sections)
            
            # 𐑮𐑳𐑯 𐑯𐑦𐑯 𐑦 𐑩𐑤 𐑞 𐑩𐑯 𐑩 𐑞 𐑞
            analysis_results = rewriter.plugin_manager.run_all_plugins(rewriter)
            hex_viewer.add_analysis_annotations(analysis_results)
            
            # 𐑨𐑛 𐑩𐑚𐑓𐑳𐑕𐑒𐑱𐑖𐑩𐑯 𐑟 𐑞
            suggestions = rewriter.get_obfuscation_suggestions()
            hex_viewer.add_obfuscation_suggestions(suggestions)
        
        # 𐑤𐑷𐑯𐑗 𐑞 ℌ𐑧𐑒𐑕 𐑝𐑿 𐑨
        app = InteractiveHexViewerApp(hex_viewer)
        app.run()
        
    except ImportError:
        # 𐑯 𐑤 𐑟 ℌ 𐑯 𐑤 𐑒 𐑞 𐑯 𐑩 𐑓 𐑞 𐑒 ℌ𐑤
        hex_viewer = HexViewer()
        
        with open(file_path, 'rb') as f:
            binary_data = f.read()
        hex_viewer.load_binary_data(binary_data)
        
        app = InteractiveHexViewerApp(hex_viewer)
        app.run()