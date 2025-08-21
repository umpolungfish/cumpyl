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
                    severity = "danger" if region.get('entropy', 0) > 7.5 else "warning"
                    annotation = HexViewAnnotation(
                        start_offset=region.get('offset', 0),
                        end_offset=region.get('offset', 0) + region.get('size', 0),
                        annotation_type="entropy",
                        title=f"High Entropy Region (Score: {region.get('entropy', 0):.2f})",
                        description=f"Potentially packed/encrypted data. Entropy: {region.get('entropy', 0):.2f}",
                        severity=severity,
                        metadata=region
                    )
                    self.add_annotation(annotation)
                    
        # 𐑨𐑛 𐑕𐑑𐑮𐑦𐑙 𐑦𐑒𐑕𐑑𐑮𐑨𐑒𐑖𐑩𐑯 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟
        if 'string_extraction' in analysis_results:
            string_data = analysis_results['string_extraction']
            if isinstance(string_data, dict) and 'extracted_strings' in string_data:
                for string_info in string_data['extracted_strings'][:50]:  # 𐑤𐑦𐑥𐑦𐑑 𐑑 50 𐑕𐑑𐑮𐑦𐑙𐑟
                    annotation = HexViewAnnotation(
                        start_offset=string_info.get('offset', 0),
                        end_offset=string_info.get('offset', 0) + len(string_info.get('value', '')),
                        annotation_type="string",
                        title=f"String: {string_info.get('value', '')[:30]}{'...' if len(string_info.get('value', '')) > 30 else ''}",
                        description=f"String found: '{string_info.get('value', '')}' (Type: {string_info.get('type', 'unknown')})",
                        severity="info",
                        metadata=string_info
                    )
                    self.add_annotation(annotation)
                    
    def add_suggestion_annotations(self, suggestions: List[Dict[str, Any]]):
        """𐑨𐑛 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑓𐑹 𐑪𐑚𐑓𐑳𐑕𐑒𐑱𐑖𐑩𐑯 𐑕𐑩𐑜𐑧𐑕𐑑𐑑𐑩𐑯𐑟"""
        for suggestion in suggestions:
            if 'section' in suggestion and 'tier' in suggestion:
                severity_map = {
                    'green': 'success',
                    'yellow': 'warning', 
                    'blue': 'info',
                    'red': 'danger'
                }
                severity = severity_map.get(suggestion['tier'].lower(), 'info')
                
                annotation = HexViewAnnotation(
                    start_offset=suggestion.get('offset', 0),
                    end_offset=suggestion.get('offset', 0) + suggestion.get('size', 0),
                    annotation_type="suggestion",
                    title=f"Encoding Suggestion: {suggestion['section']} ({suggestion['tier'].upper()})",
                    description=f"Tier: {suggestion['tier']} - {suggestion.get('reason', 'No reason provided')}",
                    severity=severity,
                    metadata=suggestion
                )
                self.add_annotation(annotation)
                
    def generate_html_hex_view(self, max_bytes: int = None) -> str:
        """𐑡𐑧𐑯𐑼𐑱𐑑 HTML 𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑣𐑧𐑒𐑕 𐑝𐑿"""
        if not self.binary_data:
            return "<p>𐑯𐑴 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩 𐑤𐑴𐑛𐑦𐑛</p>"
            
        # 𐑿𐑟 𐑒𐑩𐑯𐑓𐑦𐑜 𐑝𐑨𐑤𐑿 𐑦𐑓 𐑯𐑴 𐑥𐑨𐑒𐑕_𐑚𐑲𐑑𐑟 𐑦𐑟 𐑐𐑮𐑴𐑝𐑲𐑛𐑦𐑛
        if max_bytes is None:
            try:
                max_bytes = self.config.output.hex_viewer.max_display_bytes if self.config else 2048
            except AttributeError:
                max_bytes = 2048
            
        # 𐑤𐑦𐑥𐑦𐑑 𐑛𐑱𐑑𐑩 𐑓𐑹 𐑐𐑻𐑓𐑹𐑥𐑩𐑯𐑕
        data_to_show = self.binary_data[:max_bytes]
        total_rows = math.ceil(len(data_to_show) / self.bytes_per_row)
        
        html = f"""
        <div class="hex-viewer">
            <div class="hex-viewer-header">
                <h3>🔍 Interactive Hex View</h3>
                <div class="hex-controls">
                    <span class="hex-info">Showing {len(data_to_show)} of {len(self.binary_data)} bytes</span>
                    <span class="hex-info">{len(self.annotations)} annotations</span>
                </div>
            </div>
            <div class="hex-container">
                <div class="hex-content">
        """
        
        # 𐑡𐑧𐑯𐑼𐑱𐑑 𐑣𐑧𐑒𐑕 𐑮𐑴𐑟
        for row in range(total_rows):
            start_offset = row * self.bytes_per_row
            end_offset = min(start_offset + self.bytes_per_row, len(data_to_show))
            row_data = data_to_show[start_offset:end_offset]
            
            html += self._generate_hex_row(start_offset, row_data)
            
        html += """
                </div>
            </div>
            <div class="annotation-tooltip" id="annotationTooltip"></div>
        </div>
        """
        
        return html
        
    def _generate_hex_row(self, offset: int, row_data: bytes) -> str:
        """𐑡𐑧𐑯𐑼𐑱𐑑 𐑩 𐑕𐑦𐑙𐑜𐑩𐑤 𐑣𐑧𐑒𐑕 𐑮𐑴"""
        hex_cells = []
        ascii_cells = []
        
        for i, byte_val in enumerate(row_data):
            byte_offset = offset + i
            display_offset = self.base_offset + byte_offset  # 𐑨𐑒𐑗𐑫𐑩𐑤 𐑪𐑓𐑕𐑧𐑑 𐑦𐑯 𐑞 𐑓𐑲𐑤
            annotations = self._get_annotations_for_offset(display_offset)
            
            # 𐑒𐑮𐑦𐑱𐑑 CSS 𐑒𐑤𐑭𐑕 𐑚𐑱𐑕𐑑 𐑪𐑯 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟
            css_classes = ["hex-byte"]
            if annotations:
                css_classes.append("annotated")
                for ann in annotations:
                    css_classes.append(f"severity-{ann.severity}")
                    css_classes.append(f"type-{ann.annotation_type}")
            
            annotations_json = json.dumps([{
                'title': ann.title,
                'description': ann.description,
                'type': ann.annotation_type,
                'severity': ann.severity,
                'metadata': ann.metadata
            } for ann in annotations])
            
            class_string = " ".join(css_classes)
            escaped_annotations = annotations_json.replace('"', '&quot;')
            hex_cell = f'<span class="{class_string}" data-offset="{display_offset}" data-annotations="{escaped_annotations}">{byte_val:02x}</span>'
            hex_cells.append(hex_cell)
            
            # ASCII 𐑮𐑦𐑐𐑮𐑦𐑟𐑧𐑯𐑑𐑱𐑖𐑩𐑯
            if 32 <= byte_val <= 126:
                ascii_char = chr(byte_val)
            else:
                ascii_char = "."
                
            ascii_cell = f'<span class="{class_string}" data-offset="{display_offset}" data-annotations="{escaped_annotations}">{ascii_char}</span>'
            ascii_cells.append(ascii_cell)
            
        # 𐑐𐑨𐑛 𐑦𐑯𐑒𐑩𐑥𐑐𐑤𐑰𐑑 𐑮𐑴𐑟
        while len(hex_cells) < self.bytes_per_row:
            hex_cells.append('<span class="hex-byte empty">  </span>')
            ascii_cells.append('<span class="hex-byte empty"> </span>')
            
        display_row_offset = self.base_offset + offset
        offset_str = f"{display_row_offset:08x}" if self.show_offsets else ""
        hex_str = " ".join(hex_cells)
        ascii_str = "".join(ascii_cells) if self.show_ascii else ""
        
        return f"""
        <div class="hex-row">
            <span class="hex-offset">{offset_str}</span>
            <span class="hex-data">{hex_str}</span>
            <span class="hex-ascii">{ascii_str}</span>
        </div>
        """
        
    def _get_annotations_for_offset(self, offset: int) -> List[HexViewAnnotation]:
        """𐑜𐑧𐑑 𐑷𐑤 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑞𐑨𐑑 𐑨𐑐𐑤𐑲 𐑑 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑪𐑓𐑕𐑧𐑑"""
        return [ann for ann in self.annotations 
                if ann.start_offset <= offset < ann.end_offset]
                
    def get_css_styles(self) -> str:
        """𐑜𐑧𐑑 CSS 𐑕𐑑𐑲𐑤𐑟 𐑓𐑹 𐑞 𐑣𐑧𐑒𐑕 𐑝𐑿𐑼"""
        return """
        .hex-viewer {
            border: 1px solid #ddd;
            border-radius: 8px;
            margin: 20px 0;
            background: #fff;
            font-family: 'Courier New', Consolas, monospace;
        }
        
        .hex-viewer-header {
            background: #f8f9fa;
            padding: 10px 15px;
            border-bottom: 1px solid #ddd;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .hex-viewer-header h3 {
            margin: 0;
            color: #333;
        }
        
        .hex-controls {
            display: flex;
            gap: 15px;
        }
        
        .hex-info {
            font-size: 12px;
            color: #666;
            background: #e9ecef;
            padding: 4px 8px;
            border-radius: 4px;
        }
        
        .hex-container {
            max-height: 600px;
            overflow-y: auto;
            padding: 10px;
        }
        
        .hex-content {
            font-size: 13px;
            line-height: 1.4;
        }
        
        .hex-row {
            display: flex;
            margin-bottom: 2px;
            align-items: center;
        }
        
        .hex-offset {
            color: #666;
            margin-right: 15px;
            min-width: 80px;
            font-weight: bold;
        }
        
        .hex-data {
            margin-right: 15px;
            min-width: 400px;
        }
        
        .hex-ascii {
            color: #333;
            background: #f8f9fa;
            padding: 0 5px;
            border-radius: 3px;
        }
        
        .hex-byte {
            cursor: pointer;
            padding: 1px 2px;
            border-radius: 2px;
            transition: all 0.2s ease;
        }
        
        .hex-byte:hover {
            background: #e3f2fd;
            transform: scale(1.1);
        }
        
        .hex-byte.annotated {
            position: relative;
            font-weight: bold;
        }
        
        .hex-byte.severity-info {
            background-color: #e3f2fd;
            color: #1976d2;
        }
        
        .hex-byte.severity-success {
            background-color: #e8f5e8;
            color: #2e7d32;
        }
        
        .hex-byte.severity-warning {
            background-color: #fff3cd;
            color: #d68910;
        }
        
        .hex-byte.severity-danger {
            background-color: #f8d7da;
            color: #dc3545;
        }
        
        .hex-byte.type-section {
            border-bottom: 2px solid #1976d2;
        }
        
        .hex-byte.type-string {
            border-bottom: 2px solid #2e7d32;
        }
        
        .hex-byte.type-entropy {
            border-bottom: 2px solid #d68910;
        }
        
        .hex-byte.type-suggestion {
            border-bottom: 2px solid #dc3545;
        }
        
        .hex-byte.empty {
            color: #ccc;
            cursor: default;
        }
        
        .annotation-tooltip {
            position: absolute;
            background: #333;
            color: white;
            padding: 10px;
            border-radius: 6px;
            font-size: 12px;
            max-width: 300px;
            z-index: 1000;
            display: none;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        
        .annotation-tooltip .tooltip-title {
            font-weight: bold;
            margin-bottom: 5px;
            color: #fff;
        }
        
        .annotation-tooltip .tooltip-description {
            margin-bottom: 5px;
            line-height: 1.3;
        }
        
        .annotation-tooltip .tooltip-metadata {
            font-size: 10px;
            color: #ccc;
            border-top: 1px solid #555;
            padding-top: 5px;
            margin-top: 5px;
        }
        """
        
    def get_javascript(self) -> str:
        """𐑜𐑧𐑑 JavaScript 𐑓𐑹 𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑓𐑳𐑙𐑒𐑖𐑩𐑯𐑨𐑤𐑦𐑑𐑦"""
        return """
        document.addEventListener('DOMContentLoaded', function() {
            const tooltip = document.getElementById('annotationTooltip');
            const hexBytes = document.querySelectorAll('.hex-byte.annotated');
            
            hexBytes.forEach(function(hexByte) {
                hexByte.addEventListener('mouseenter', function(e) {
                    const annotations = JSON.parse(e.target.getAttribute('data-annotations') || '[]');
                    if (annotations.length > 0) {
                        showTooltip(e, annotations);
                    }
                });
                
                hexByte.addEventListener('mouseleave', function() {
                    hideTooltip();
                });
                
                hexByte.addEventListener('mousemove', function(e) {
                    updateTooltipPosition(e);
                });
            });
            
            function showTooltip(event, annotations) {
                let content = '';
                
                annotations.forEach(function(ann, index) {
                    if (index > 0) content += '<hr style="margin: 8px 0; border-color: #555;">';
                    
                    content += '<div class="tooltip-title">' + escapeHtml(ann.title) + '</div>';
                    content += '<div class="tooltip-description">' + escapeHtml(ann.description) + '</div>';
                    
                    if (ann.metadata && Object.keys(ann.metadata).length > 0) {
                        content += '<div class="tooltip-metadata">';
                        content += 'Type: ' + escapeHtml(ann.type) + '<br>';
                        content += 'Severity: ' + escapeHtml(ann.severity) + '<br>';
                        
                        // 𐑕𐑴 𐑦𐑯𐑑𐑼𐑧𐑕𐑑𐑦𐑙 𐑥𐑧𐑑𐑩𐑛𐑱𐑑𐑩
                        for (const [key, value] of Object.entries(ann.metadata)) {
                            if (key !== 'type' && key !== 'severity' && value !== null && value !== undefined) {
                                content += escapeHtml(key) + ': ' + escapeHtml(String(value)) + '<br>';
                            }
                        }
                        content += '</div>';
                    }
                });
                
                tooltip.innerHTML = content;
                tooltip.style.display = 'block';
                updateTooltipPosition(event);
            }
            
            function hideTooltip() {
                tooltip.style.display = 'none';
            }
            
            function updateTooltipPosition(event) {
                const x = event.pageX + 10;
                const y = event.pageY + 10;
                
                tooltip.style.left = x + 'px';
                tooltip.style.top = y + 'px';
                
                // 𐑩𐑡𐑳𐑕𐑑 𐑦𐑓 𐑑𐑵𐑤𐑑𐑦𐑐 𐑣𐑦𐑑𐑟 𐑞 𐑧𐑡 𐑝 𐑞 𐑢𐑦𐑯𐑛𐑴
                const rect = tooltip.getBoundingClientRect();
                if (rect.right > window.innerWidth) {
                    tooltip.style.left = (event.pageX - rect.width - 10) + 'px';
                }
                if (rect.bottom > window.innerHeight) {
                    tooltip.style.top = (event.pageY - rect.height - 10) + 'px';
                }
            }
            
            function escapeHtml(text) {
                const div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }
        });
        """
        
    def generate_textual_hex_view(self, max_bytes: int = None) -> str:
        """𐑡𐑧𐑯𐑼𐑱𐑑 𐑑𐑧𐑒𐑕𐑑𐑿𐑩𐑤 𐑣𐑧𐑒𐑕 𐑝𐑿 𐑦𐑯 𐑓𐑹𐑥𐑨𐑑"""
        if not self.binary_data:
            return "𐑯𐑴 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩 𐑤𐑴𐑛𐑦𐑛"
            
        # 𐑓𐑹 𐑑𐑧𐑒𐑕𐑑𐑿𐑩𐑤 𐑝𐑿𐑼, 𐑢𐑰 𐑢𐑪𐑯𐑑 𐑑 𐑛𐑦𐑕𐑐𐑤𐑱 𐑞 𐑒𐑻𐑩𐑯𐑑 𐑝𐑦𐑿 (display_rows)
        if max_bytes is None:
            max_bytes = self.display_rows * self.bytes_per_row
            
        # 𐑧𐑯𐑖𐑫𐑼 𐑢𐑰 𐑛𐑴𐑯𐑑 𐑜𐑴 𐑚𐑦𐑘𐑪𐑯𐑛 𐑞 𐑧𐑯𐑛 𐑝 𐑞 𐑓𐑲𐑤
        remaining_bytes = len(self.binary_data) - self.current_offset
        bytes_to_show = min(max_bytes, remaining_bytes)
        
        data_to_show = self.binary_data[self.current_offset:self.current_offset + bytes_to_show]
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
        
        # 𐑣𐑧𐑒𐑕 𐑚𐑲𐑑𐑟
        hex_bytes = []
        for byte_val in row_data:
            annotations = self._get_annotations_for_offset(offset + len(hex_bytes))
            color_code = self._get_color_code_for_annotations(annotations)
            if color_code:
                hex_bytes.append(f"{color_code}{byte_val:02x}[/]")
            else:
                hex_bytes.append(f"{byte_val:02x}")
            
        # 𐑐𐑨𐑛 𐑦𐑯𐑒𐑩𐑥𐑐𐑤𐑰𐑑 𐑮𐑴𐑟
        while len(hex_bytes) < self.bytes_per_row:
            hex_bytes.append("  ")
            
        hex_str = " ".join(hex_bytes)
        
        # ASCII 𐑮𐑦𐑐𐑮𐑦𐑟𐑧𐑯𐑑𐑱𐑖𐑩𐑯
        ascii_chars = []
        if self.show_ascii:
            for i, byte_val in enumerate(row_data):
                annotations = self._get_annotations_for_offset(offset + i)
                color_code = self._get_color_code_for_annotations(annotations)
                if 32 <= byte_val <= 126:
                    char = chr(byte_val)
                else:
                    char = "."
                    
                if color_code:
                    ascii_chars.append(f"{color_code}{char}[/]")
                else:
                    ascii_chars.append(char)
            while len(ascii_chars) < self.bytes_per_row:
                ascii_chars.append(" ")
                
        ascii_str = "".join(ascii_chars) if self.show_ascii else ""
        
        return f"[cyan]{offset_str}[/] │ {hex_str} │ {ascii_str}"
        
    def _get_color_code_for_annotations(self, annotations: List[HexViewAnnotation]) -> str:
        """𐑜𐑧𐑑 𐑒𐑳𐑤𐑼 𐑒𐑴𐑛 𐑚𐑱𐑕𐑑 𐑪𐑯 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯 𐑕𐑦𐑝𐑺𐑦𐑑𐑦"""
        if not annotations:
            return ""
            
        # 𐑐𐑮𐑲𐑹𐑦𐑑𐑦 𐑹𐑛𐑼: 𐑛𐑱𐑯𐑡𐑼 > 𐑢𐑹𐑯𐑦𐑙 > 𐑦𐑯𐑓𐑴 > 𐑕𐑳𐑒𐑕𐑧𐑕
        for ann in annotations:
            if ann.severity == "danger":
                return "[bold red]"
            elif ann.severity == "warning":
                return "[bold yellow]"
            elif ann.severity == "success":
                return "[bold green]"
            elif ann.severity == "info":
                return "[bold blue]"
        return ""
        
    def search_bytes(self, pattern: bytes) -> List[int]:
        """𐑕𐑻𐑗 𐑓𐑹 𐑚𐑲𐑑 𐑐𐑨𐑑𐑼𐑯 𐑦𐑯 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩"""
        results = []
        data_len = len(self.binary_data)
        pattern_len = len(pattern)
        
        for i in range(data_len - pattern_len + 1):
            if self.binary_data[i:i + pattern_len] == pattern:
                results.append(i)
                
        self.search_results = results
        self.search_index = 0
        return results
        
    def search_string(self, pattern: str) -> List[int]:
        """𐑕𐑻𐑗 𐑓𐑹 𐑕𐑑𐑮𐑦𐑙 𐑐𐑨𐑑𐑼𐑯 𐑦𐑯 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩"""
        return self.search_bytes(pattern.encode('utf-8', errors='ignore'))
        
    def navigate_to_offset(self, offset: int):
        """𐑯𐑨𐑝𐑦𐑜𐑱𐑑 𐑑 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑪𐑓𐑕𐑧𐑑"""
        # 𐑞 𐑪𐑓𐑕𐑧𐑑 𐑦𐑟 𐑞 𐑞𐑦𐑙 𐑢𐑰 𐑢𐑪𐑯𐑑 𐑑 𐑣𐑲𐑤𐑲𐑑, 𐑕𐑴 𐑨𐑤𐑲𐑯 𐑞 𐑝𐑦𐑿 𐑑 𐑦𐑯𐑒𐑤𐑵𐑛 𐑦𐑑
        # 𐑩𐑤𐑲𐑯 𐑞 𐑝𐑦𐑿 𐑑 𐑖𐑴 𐑞 𐑤𐑦𐑯 𐑢𐑦𐑞 𐑞 𐑞𐑸𐑜𐑧𐑑 𐑪𐑓𐑕𐑧𐑑
        target_row_start = (offset // self.bytes_per_row) * self.bytes_per_row
        
        # 𐑞𐑻𐑶 𐑨 𐑓𐑿 𐑮𐑴𐑟 𐑚𐑦𐑓𐑹 𐑞 𐑞𐑸𐑜𐑧𐑑 𐑓𐑹 𐑒𐑪𐑯𐑑𐑧𐑒𐑕𐑑
        context_rows = 3
        view_start = max(0, target_row_start - (context_rows * self.bytes_per_row))
        
        # 𐑧𐑯𐑖𐑫𐑼 𐑢𐑰 𐑛𐑴𐑯𐑑 𐑜𐑴 𐑚𐑦𐑘𐑪𐑯𐑛 𐑞 𐑧𐑯𐑛 𐑝 𐑞 𐑓𐑲𐑤
        max_start = len(self.binary_data) - (self.display_rows * self.bytes_per_row)
        self.current_offset = max(0, min(view_start, max_start))
        
    def navigate_next_search_result(self):
        """𐑯𐑨𐑝𐑦𐑜𐑱𐑑 𐑑 𐑯𐑧𐑒𐑕𐑑 𐑕𐑻𐑗 𐑮𐑦𐑟𐑳𐑤𐑑"""
        if self.search_results:
            self.search_index = (self.search_index + 1) % len(self.search_results)
            target_offset = self.search_results[self.search_index] 
            self.navigate_to_offset(target_offset)
            return target_offset
        return None
            
    def navigate_previous_search_result(self):
        """𐑯𐑨𐑝𐑦𐑜𐑱𐑑 𐑑 𐑐𐑮𐑰𐑝𐑦𐑩𐑕 𐑕𐑻𐑗 𐑮𐑦𐑟𐑳𐑤𐑑"""
        if self.search_results:
            self.search_index = (self.search_index - 1) % len(self.search_results)
            target_offset = self.search_results[self.search_index]
            self.navigate_to_offset(target_offset)
            return target_offset
        return None


class TextualHexViewer(Static):
    """𐑑𐑧𐑒𐑕𐑑𐑿𐑩𐑤 𐑣𐑧𐑒𐑕 𐑝𐑿𐑼 𐑢𐑦𐑡𐑧𐑑"""
    
    def __init__(self, hex_viewer: HexViewer, **kwargs):
        super().__init__(hex_viewer.generate_textual_hex_view(), id="hex-display", **kwargs)
        self.hex_viewer = hex_viewer


class HexSearchDialog(ModalScreen[str]):
    """𐑣𐑧𐑒𐑕 𐑕𐑻𐑗 𐑛𐑲𐑩𐑤𐑪𐑜"""
    
    BINDINGS = [
        Binding("escape", "dismiss", "Cancel"),
        Binding("enter", "search", "Search"),
    ]
    
    def compose(self) -> ComposeResult:
        with Container(id="search-dialog"):
            yield Label("Search for hex bytes or string:", id="search-label")
            yield Input(placeholder="Enter hex (e.g. 4D5A) or string", id="search-input")
            yield Button("Search Hex", variant="primary", id="search-hex")
            yield Button("Search String", variant="primary", id="search-string")
            yield Button("Cancel", variant="default", id="cancel")
                
    def action_dismiss(self):
        self.dismiss("")
        
    def action_search(self):
        search_input = self.query_one("#search-input")
        self.dismiss(search_input.value)
        
    @on(Button.Pressed, "#search-hex")
    def search_hex(self):
        search_input = self.query_one("#search-input")
        self.dismiss(f"hex:{search_input.value}")
        
    @on(Button.Pressed, "#search-string") 
    def search_string(self):
        search_input = self.query_one("#search-input")
        self.dismiss(f"string:{search_input.value}")
        
    @on(Button.Pressed, "#cancel")
    def cancel(self):
        self.dismiss("")


class InteractiveHexViewerApp(App):
    """𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑣𐑧𐑒𐑕 𐑝𐑿𐑼 𐑨𐑐𐑤𐑦𐑒𐑱𐑖𐑩𐑯"""
    
    CSS_PATH = None
    CSS = """
    #search-dialog {
        width: 50;
        height: 10;
        background: $surface;
        border: thick $primary;
    }
    
    #search-label {
        margin: 1;
        text-align: center;
    }
    
    #search-input {
        margin: 0 1;
    }
    
    #hex-display {
        width: 100%;
        height: 100%;
        margin: 0;
        padding: 1;
        border: none;
        background: $surface;
    }
    """
    
    BINDINGS = [
        Binding("j,down", "scroll_down", "Scroll Down"),
        Binding("k,up", "scroll_up", "Scroll Up"),
        Binding("ctrl+d", "page_down", "Page Down"),
        Binding("ctrl+u", "page_up", "Page Up"),
        Binding("g", "go_to_top", "Go to Top"),
        Binding("G", "go_to_bottom", "Go to Bottom"),
        Binding("f,/", "search", "Search"),
        Binding("n", "next_search", "Next Match"),
        Binding("N", "previous_search", "Previous Match"),
        Binding("r", "refresh", "Refresh"),
        Binding("a", "show_annotations", "Show Annotations"),
        Binding("q", "quit", "Quit"),
    ]
    
    def __init__(self, hex_viewer: HexViewer, **kwargs):
        super().__init__(**kwargs)
        self.hex_viewer = hex_viewer
        
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield TextualHexViewer(self.hex_viewer, id="hex-viewer")
        yield Footer()
        
    def action_scroll_down(self):
        """𐑕𐑒𐑮𐑴𐑤 𐑛𐑬𐑯 𐑦𐑯 𐑞 𐑣𐑧𐑒𐑕 𐑝𐑿"""
        max_offset = len(self.hex_viewer.binary_data) - (self.hex_viewer.display_rows * self.hex_viewer.bytes_per_row)
        new_offset = self.hex_viewer.current_offset + self.hex_viewer.bytes_per_row
        self.hex_viewer.current_offset = min(new_offset, max(0, max_offset))
        self._refresh_display()
        
    def action_scroll_up(self):
        """𐑕𐑒𐑮𐑴𐑤 𐑳𐑐 𐑦𐑯 𐑞 𐑣𐑧𐑒𐑕 𐑝𐑿"""
        self.hex_viewer.current_offset = max(0, self.hex_viewer.current_offset - self.hex_viewer.bytes_per_row)
        self._refresh_display()
        
    def action_page_down(self):
        """𐑐𐑱𐑡 𐑛𐑬𐑯 (𐑕𐑒𐑮𐑴𐑤 𐑩 𐑓𐑻𐑤 𐑕𐑒𐑮𐑰𐑯)"""
        page_size = (self.hex_viewer.display_rows - 2) * self.hex_viewer.bytes_per_row
        max_offset = len(self.hex_viewer.binary_data) - (self.hex_viewer.display_rows * self.hex_viewer.bytes_per_row)
        new_offset = self.hex_viewer.current_offset + page_size
        self.hex_viewer.current_offset = min(new_offset, max(0, max_offset))
        self._refresh_display()
        
    def action_page_up(self):
        """𐑐𐑱𐑡 𐑳𐑐 (𐑕𐑒𐑮𐑴𐑤 𐑩 𐑓𐑻𐑤 𐑕𐑒𐑮𐑰𐑯)"""
        page_size = (self.hex_viewer.display_rows - 2) * self.hex_viewer.bytes_per_row
        new_offset = self.hex_viewer.current_offset - page_size
        self.hex_viewer.current_offset = max(0, new_offset)
        self._refresh_display()
        
    def action_go_to_top(self):
        """𐑜𐑴 𐑑 𐑑𐑪𐑐 𐑝 𐑓𐑲𐑤"""
        self.hex_viewer.current_offset = 0
        self._refresh_display()
        
    def action_go_to_bottom(self):
        """𐑜𐑴 𐑑 𐑚𐑪𐑑𐑩𐑥 𐑝 𐑓𐑲𐑤"""
        max_offset = len(self.hex_viewer.binary_data) - (self.hex_viewer.display_rows * self.hex_viewer.bytes_per_row)
        self.hex_viewer.current_offset = max(0, max_offset)
        self._refresh_display()
        
    def action_search(self):
        """𐑴𐑐𐑧𐑯 𐑕𐑻𐑗 𐑛𐑲𐑩𐑤𐑪𐑜"""
        self.push_screen(HexSearchDialog(), self._handle_search_result)
        
    def _handle_search_result(self, result: str):
        """𐑣𐑨𐑯𐑛𐑩𐑤 𐑕𐑻𐑗 𐑮𐑦𐑟𐑳𐑤𐑑"""
        if not result:
            return
            
        try:
            if result.startswith("hex:"):
                hex_string = result[4:].strip()
                # 𐑮𐑦𐑥𐑵𐑝 𐑕𐑐𐑱𐑕𐑦𐑟 𐑯 𐑒𐑩𐑯𐑝𐑻𐑑 𐑣𐑧𐑒𐑕 𐑑 𐑚𐑲𐑑𐑟
                hex_string = hex_string.replace(" ", "")
                pattern = bytes.fromhex(hex_string)
                results = self.hex_viewer.search_bytes(pattern)
            elif result.startswith("string:"):
                string_pattern = result[7:]
                results = self.hex_viewer.search_string(string_pattern)
            else:
                # 𐑛𐑦𐑓𐑷𐑤𐑑 𐑑 𐑕𐑑𐑮𐑦𐑙 𐑕𐑻𐑗
                results = self.hex_viewer.search_string(result)
                
            if results:
                self.notify(f"Found {len(results)} matches - use n/N to navigate")
                # 𐑯𐑨𐑝𐑦𐑜𐑱𐑑 𐑑 𐑓𐑻𐑕𐑑 𐑮𐑦𐑟𐑳𐑤𐑑 𐑯 𐑮𐑰𐑓𐑮𐑧𐑖
                self.hex_viewer.navigate_to_offset(results[0])
                self._refresh_display()
                self.notify(f"Match 1/{len(results)} at offset 0x{results[0]:X}")
            else:
                self.notify("No matches found", severity="warning")
                
        except Exception as e:
            self.notify(f"Search error: {str(e)}", severity="error")
            
    def action_next_search(self):
        """𐑯𐑧𐑒𐑕𐑑 𐑕𐑻𐑗 𐑮𐑦𐑟𐑳𐑤𐑑"""
        if self.hex_viewer.search_results:
            target_offset = self.hex_viewer.navigate_next_search_result()
            self._refresh_display()
            if target_offset is not None:
                match_num = self.hex_viewer.search_index + 1
                total_matches = len(self.hex_viewer.search_results)
                self.notify(f"Match {match_num}/{total_matches} at offset 0x{target_offset:X}")
            else:
                self.notify("Navigation failed", severity="error")
        else:
            self.notify("No search results - perform search first (f or /)", severity="warning")
            
    def action_previous_search(self):
        """𐑐𐑮𐑰𐑝𐑦𐑩𐑕 𐑕𐑻𐑗 𐑮𐑦𐑟𐑳𐑤𐑑"""
        if self.hex_viewer.search_results:
            target_offset = self.hex_viewer.navigate_previous_search_result()
            self._refresh_display()
            if target_offset is not None:
                match_num = self.hex_viewer.search_index + 1
                total_matches = len(self.hex_viewer.search_results)
                self.notify(f"Match {match_num}/{total_matches} at offset 0x{target_offset:X}")
            else:
                self.notify("Navigation failed", severity="error")
        else:
            self.notify("No search results - perform search first (f or /)", severity="warning")
            
    def action_refresh(self):
        """𐑮𐑰𐑓𐑮𐑧𐑖 𐑛𐑦𐑕𐑐𐑤𐑱"""
        self._refresh_display()
        self.notify("Display refreshed")
        
    def action_show_annotations(self):
        """𐑕𐑴 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯 𐑦𐑯𐑓𐑹𐑥𐑱𐑖𐑩𐑯"""
        annotation_count = len(self.hex_viewer.annotations)
        current_annotations = []
        
        # 𐑓𐑲𐑯𐑛 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑦𐑯 𐑞 𐑒𐑻𐑩𐑯𐑑 𐑝𐑿
        view_start = self.hex_viewer.current_offset
        view_end = view_start + (self.hex_viewer.display_rows * self.hex_viewer.bytes_per_row)
        
        for ann in self.hex_viewer.annotations:
            if ann.start_offset < view_end and ann.end_offset > view_start:
                current_annotations.append(ann)
                
        # 𐑨𐑛 𐑛𐑦𐑑𐑱𐑤 𐑦𐑯𐑓𐑹𐑥𐑱𐑖𐑩𐑯
        info_lines = [f"Total annotations: {annotation_count}, Visible: {len(current_annotations)}"]
        info_lines.append(f"Current view: 0x{view_start:X} - 0x{view_end:X}")
        info_lines.append(f"File size: {len(self.hex_viewer.binary_data)} bytes")
        
        if current_annotations:
            info_lines.append("Visible annotations:")
            for i, ann in enumerate(current_annotations[:5]):  # 𐑤𐑦𐑥𐑦𐑑 𐑑 5
                info_lines.append(f"  {i+1}. {ann.annotation_type} at 0x{ann.start_offset:X}")
                
        self.notify("\n".join(info_lines))
        
    def _refresh_display(self):
        """𐑮𐑰𐑓𐑮𐑧𐑖 𐑞 𐑣𐑧𐑒𐑕 𐑛𐑦𐑕𐑐𐑤𐑱"""
        hex_display = self.query_one("#hex-display")
        hex_display.update(self.hex_viewer.generate_textual_hex_view())


def launch_textual_hex_viewer(hex_viewer: HexViewer):
    """𐑤𐑷𐑯𐑗 𐑞 𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑑𐑧𐑒𐑕𐑑𐑿𐑩𐑤 𐑣𐑧𐑒𐑕 𐑝𐑿𐑼"""
    if not TEXTUAL_AVAILABLE:
        raise ImportError("Textual package is required for interactive hex viewer. Install with: pip install textual")
    
    try:
        # Ensure hex viewer has data
        if not hex_viewer.binary_data:
            raise ValueError("HexViewer has no binary data loaded")
            
        # Test the hex generation before launching the app
        test_output = hex_viewer.generate_textual_hex_view(max_bytes=64)
        if not test_output or "𐑯𐑴 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩 𐑤𐑴𐑛𐑦𐑛" in test_output:
            raise ValueError("Failed to generate hex view output")
        
        app = InteractiveHexViewerApp(hex_viewer)
        app.run()
    except Exception as e:
        print(f"Error launching textual hex viewer: {e}")
        import traceback
        traceback.print_exc()
        raise