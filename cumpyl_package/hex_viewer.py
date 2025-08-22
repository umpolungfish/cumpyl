import math
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import json
import asyncio
from collections import Counter

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
        self.file_handle = None  # 𐑯𐑿: 𐑤𐑱𐑟𐑦 𐑤𐑴𐑛𐑦𐑙 𐑓𐑲𐑤 ℌ𐑨𐑯𐑛𐑩𐑤
        self.file_size = 0
        self.file_path = None
        self.bytes_per_row = 16
        self.show_ascii = True
        self.show_offsets = True
        self.base_offset = base_offset  # 𐑚𐑱𐑕 𐑪𐑓𐑕𐑧𐑑 𐑓𐑹 𐑛𐑦𐑕𐑐𐑤𐑱
        
        # 𐑯𐑿: 𐑒𐑨𐑖𐑦𐑙 𐑓𐑹 𐑐𐑼𐑓𐑹𐑥𐑩𐑯𐑕
        self._annotation_cache = {}  # 𐑒𐑨𐑖 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯 𐑤𐑫𐑒𐑳𐑐𐑕 𐑚𐑲 𐑪𐑓𐑕𐑧𐑑
        self._entropy_cache = {}     # 𐑒𐑨𐑖 𐑩𐑯𐑑𐑮𐑴𐑐𐑦 𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑖𐑩𐑯𐑟
        self._chunk_size = 4096      # 𐑗𐑳𐑙𐑒 𐑕𐑲𐑟 𐑓𐑹 𐑤𐑱𐑟𐑦 𐑤𐑴𐑛𐑦𐑙
        self._current_view_data = None  # 𐑒𐑨𐑖 𐑞 𐑒𐑳𐑮𐑩𐑯𐑑 𐑝𐑦𐑿𐑦𐑚𐑩𐑤 𐑛𐑱𐑑𐑩
        self._last_offset = -1       # 𐑤𐑨𐑕𐑑 𐑮𐑧𐑯𐑛𐑼𐑛 𐑪𐑓𐑕𐑧𐑑
        
        # 𐑑𐑧𐑒𐑕𐑑𐑿𐑩𐑤 𐑝𐑿𐑼 𐑕𐑑𐑱𐑑
        self.current_offset = 0
        self.display_rows = 24  # 𐑦𐑯𐑦𐑖𐑩𐑤 𐑛𐑦𐑓𐑷𐑤𐑑 - 𐑢𐑦𐑤 𐑚 𐑩𐑛𐑡𐑳𐑕𐑑𐑦𐑛 𐑛𐑦𐑯𐑨𐑥𐑦𐑒𐑩𐑤𐑦
        self.search_results: List[int] = []
        self.search_index = 0
        
        # 𐑔𐑰𐑥 𐑕𐑦𐑕𐑑𐑩𐑥
        self.current_theme = 'cybernoir'  # 𐑛𐑦𐑓𐑷𐑤𐑑: 'cybernoir', 'monochrome', 'hellfire'
        self.theme_styles = self._init_themes()
        
    def _init_themes(self) -> Dict[str, Dict[str, str]]:
        """𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟 𐑞𐑰𐑥 𐑕𐑦𐑕𐑑𐑩𐑥 𐑢𐑦𐑞 𐑥𐑨𐑒𐑕𐑦𐑥𐑩𐑤𐑦𐑕𐑑 𐑕𐑲𐑚𐑼𐑐𐑳𐑙𐑒 𐑧𐑕𐑔𐑧𐑑𐑦𐑒"""
        return {
            'cybernoir': {
                # 𐑛𐑰𐑐 𐑚𐑤𐑨𐑒 𐑚𐑜, 𐑯𐑰𐑪𐑯 𐑕𐑲𐑨𐑯/𐑥𐑩𐑡𐑧𐑯𐑑𐑩/𐑹𐑦𐑯𐑡 𐑣𐑲𐑤𐑲𐑑𐑕
                'section': 'cyan',
                'string': 'green', 
                'entropy': 'yellow',
                'suggestion': 'bright_red',
                'high_entropy': 'bright_red',
                'medium_entropy': 'orange',  
                'low_entropy': 'dim blue',
                'ascii_printable': 'bright_white',
                'utf16': 'magenta',
                'offset_normal': 'cyan',
                'offset_boundary': 'bright_cyan'
            },
            'monochrome': {
                # 𐑚𐑤𐑨𐑒 + 𐑢𐑲𐑑 𐑴𐑯𐑤𐑦, 𐑯𐑴 𐑒𐑩𐑤𐑼 - 𐑡𐑳𐑕𐑑 𐑚𐑴𐑤𐑛/𐑦𐑑𐑨𐑤𐑦𐑒 𐑢𐑱𐑑 𐑗𐑱𐑯𐑡𐑩𐑟
                'section': 'dim white',
                'string': 'white',
                'entropy': 'bold white',
                'suggestion': 'bold white',
                'high_entropy': 'bold white',
                'medium_entropy': 'white',
                'low_entropy': 'dim white',
                'ascii_printable': 'bright_white',
                'utf16': 'white',
                'offset_normal': 'white',
                'offset_boundary': 'bold white'
            },
            'hellfire': {
                # 𐑚𐑨𐑒𐑜𐑮𐑬𐑯𐑛 = 𐑷𐑤𐑥𐑴𐑕𐑑 𐑚𐑤𐑨𐑒-𐑮𐑧𐑛, 𐑚𐑲𐑑𐑟 𐑜𐑤𐑴 𐑤𐑲𐑒 𐑧𐑥𐑚𐑼𐑟 𐑨𐑟 𐑩𐑯𐑑𐑮𐑴𐑐𐑦 𐑦𐑯𐑒𐑮𐑰𐑟𐑩𐑟
                'section': 'red',
                'string': 'bright_yellow',
                'entropy': 'orange',
                'suggestion': 'bright_red',
                'high_entropy': 'bright_red',
                'medium_entropy': 'red',
                'low_entropy': 'dim red',
                'ascii_printable': 'yellow',
                'utf16': 'bright_magenta',
                'offset_normal': 'red',
                'offset_boundary': 'bright_red'
            }
        }
    
    def get_themed_color(self, base_color: str, annotation_type: str = None) -> str:
        """𐑜𐑧𐑑 𐑔𐑰𐑥𐑛 𐑒𐑩𐑤𐑼 𐑓𐑹 𐑞 𐑒𐑳𐑮𐑩𐑯𐑑 𐑞𐑰𐑥"""
        theme = self.theme_styles.get(self.current_theme, self.theme_styles['cybernoir'])
        
        # 𐑥𐑨𐑐 𐑞 𐑚𐑱𐑕 𐑒𐑩𐑤𐑼 𐑑 𐑞𐑰𐑥-𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑒𐑩𐑤𐑼
        color_mapping = {
            'blue': theme.get('section', 'cyan'),
            'green': theme.get('string', 'green'),
            'yellow': theme.get('entropy', 'yellow'),
            'red': theme.get('suggestion', 'red'),
            'cyan': theme.get('offset_normal', 'cyan'),
            'bright_cyan': theme.get('offset_boundary', 'bright_cyan'),
            'bright_white': theme.get('ascii_printable', 'bright_white'),
            'magenta': theme.get('utf16', 'magenta')
        }
        
        return color_mapping.get(base_color, base_color)
    
    def set_theme(self, theme_name: str):
        """𐑕𐑧𐑑 𐑞 𐑒𐑳𐑮𐑩𐑯𐑑 𐑞𐑰𐑥"""
        if theme_name in self.theme_styles:
            self.current_theme = theme_name

    def load_binary_data(self, data: bytes):
        """𐑤𐑴𐑛 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩 𐑦𐑯𐑑 𐑞 𐑝𐑿𐑼"""
        self.binary_data = data
        self.file_size = len(data)
        self._clear_caches()
        
    def load_from_file(self, file_path: str):
        """𐑯𐑿: 𐑤𐑴𐑛 𐑚𐑲𐑯𐑩𐑮𐑦 𐑓𐑮𐑩𐑥 𐑓𐑲𐑤 𐑦𐑯 𐑤𐑱𐑟𐑦 𐑓𐑨𐑖𐑩𐑯"""
        import os
        self.file_path = file_path
        self.file_size = os.path.getsize(file_path)
        if self.file_handle:
            self.file_handle.close()
        self.file_handle = open(file_path, 'rb')
        self.binary_data = None  # 𐑛𐑴𐑯'𐑑 𐑤𐑴𐑛 𐑞 ℌ𐑴𐑤 𐑓𐑲𐑤 𐑦𐑯𐑑 𐑥𐑧𐑥𐑹𐑦
        self._clear_caches()
        
    def _clear_caches(self):
        """𐑒𐑤𐑽 𐑩𐑤 𐑒𐑨𐑖𐑟 𐑢𐑧𐑯 𐑦𐑓𐑕𐑧𐑑 𐑗𐑱𐑯𐑡𐑦𐑟"""
        self._annotation_cache.clear()
        self._entropy_cache.clear()
        self._current_view_data = None
        self._last_offset = None
        if hasattr(self, '_viewport_annotations'):
            delattr(self, '_viewport_annotations')
        
    def _read_chunk(self, offset: int, size: int) -> bytes:
        """𐑯𐑿: 𐑮𐑰𐑛 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑗𐑳𐑙𐑒 𐑝 𐑞 𐑓𐑲𐑤"""
        if self.binary_data is not None:
            # 𐑘𐑴𐑤 𐑓𐑲𐑤 𐑦𐑯 𐑥𐑧𐑥𐑹𐑦
            return self.binary_data[offset:offset + size]
        elif self.file_handle:
            # 𐑤𐑱𐑟𐑦 𐑮𐑰𐑛 𐑓𐑮𐑩𐑥 𐑓𐑲𐑤
            self.file_handle.seek(offset)
            return self.file_handle.read(size)
        else:
            return b''
        
    def add_annotation(self, annotation: HexViewAnnotation):
        """𐑨𐑛 𐑩 𐑯𐑿 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯 𐑑 𐑞 𐑝𐑿𐑼"""
        self.annotations.append(annotation)
        self._annotation_cache.clear()  # 𐑦𐑯𐑝𐑨𐑤𐑦𐑛𐑱𐑑 𐑒𐑨𐑖 𐑢𐑧𐑯 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑗𐑱𐑯𐑡
        
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
        if (not self.binary_data and not self.file_handle) or self.file_size == 0:
            return "𐑯𐑴 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩 𐑤𐑴𐑛𐑦𐑛"
            
        if max_bytes is None:
            max_bytes = min(self.config.output.hex_viewer.max_display_bytes if self.config else 2048, self.file_size)
            
        import tempfile
        if not output_file:
            temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.html')
            output_file = temp_file.name
            temp_file.close()
        
        data_to_show = self._read_chunk(self.current_offset, max_bytes)
        
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
        # 𐑤𐑱𐑟𐑦 𐑤𐑴𐑛𐑦𐑙: 𐑴𐑯𐑤𐑦 𐑗𐑧𐑒 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑯𐑦𐑼 𐑞 𐑒𐑳𐑮𐑩𐑯𐑑 𐑝𐑦𐑿𐑐𐑹𐑑
        if not hasattr(self, '_viewport_annotations'):
            self._cache_viewport_annotations()
        
        annotations = []
        for annotation in self._viewport_annotations:
            if annotation.start_offset <= offset < annotation.end_offset:
                annotations.append(annotation)
        return annotations
    
    def _cache_viewport_annotations(self):
        """𐑒𐑨𐑖 𐑩𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑝𐑦𐑟𐑦𐑚𐑩𐑤 𐑦𐑯 𐑞 𐑒𐑳𐑮𐑩𐑯𐑑 𐑝𐑦𐑿𐑐𐑹𐑑"""
        start_offset = self.base_offset + self.current_offset
        end_offset = start_offset + self.bytes_per_row * self.display_rows
        
        self._viewport_annotations = []
        for annotation in self.annotations:
            if (annotation.start_offset <= end_offset and annotation.end_offset >= start_offset):
                self._viewport_annotations.append(annotation)
    
        
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
        # 𐑯𐑿: 𐑗𐑧𐑒 𐑦𐑓 𐑯𐑴 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩
        if (not self.binary_data and not self.file_handle) or self.file_size == 0:
            return "𐑯𐑴 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩 𐑤𐑴𐑛𐑦𐑛"
            
        # 𐑯𐑿: 𐑒𐑨𐑖 𐑝𐑦𐑿 𐑦𐑓 𐑟𐑱𐑥 𐑗𐑱𐑯𐑡𐑱𐑛
        view_cache_key = (self.current_offset, max_bytes)
        if (self._current_view_data is not None and 
            self._last_offset == self.current_offset and
            view_cache_key == getattr(self, '_last_view_key', None)):
            return self._current_view_data
            
        if max_bytes is None:
            # 𐑤𐑦𐑥𐑦𐑑 𐑥𐑨𐑒𐑕 𐑚𐑲𐑑𐑟 𐑑 𐑝𐑦𐑿𐑩𐑚𐑤 𐑩𐑴𐑟
            viewport_bytes = self.bytes_per_row * self.display_rows
            max_bytes = min(viewport_bytes, self.file_size - self.current_offset)
            
        # 𐑮𐑰𐑛 𐑴𐑯𐑤𐑦 𐑝𐑦𐑿𐑩𐑚𐑤 𐑛𐑱𐑑𐑩
        data_to_show = self._read_chunk(self.current_offset, max_bytes)
        hex_lines = []
        
        for i in range(0, len(data_to_show), self.bytes_per_row):
            row_data = data_to_show[i:i + self.bytes_per_row]
            row_offset = self.base_offset + self.current_offset + i
            hex_line = self._generate_textual_hex_row(row_offset, row_data)
            hex_lines.append(hex_line)
            
        result = "\n".join(hex_lines)
        
        # 𐑒𐑨𐑖 𐑞 𐑮𐑦𐑟𐑳𐑤𐑑
        self._current_view_data = result
        self._last_offset = self.current_offset
        self._last_view_key = view_cache_key
        
        return result
        
    def _generate_textual_hex_row(self, offset: int, row_data: bytes) -> str:
        """𐑡𐑧𐑯𐑼𐑱𐑑 𐑩 𐑕𐑦𐑙𐑜𐑩𐑤 𐑣𐑧𐑒𐑕 𐑮𐑴 𐑓𐑹 𐑑𐑧𐑒𐑕𐑑𐑿𐑩𐑤 𐑛𐑦𐑕𐑐𐑤𐑱"""
        # 𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑑 𐑩𐑯𐑑𐑮𐑴𐑐𐑦 𐑓𐑹 𐑣𐑴𐑤 𐑮𐑴
        row_entropy = self.calculate_shannon_entropy(row_data)
        
        # 𐑪𐑓𐑕𐑧𐑑 𐑒𐑩𐑤𐑩𐑥 𐑢𐑦𐑞 0x100 𐑚𐑬𐑯𐑛𐑼𐑦 𐑣𐑲𐑤𐑲𐑑𐑦𐑙 (𐑔𐑰𐑥𐑛)
        base_color = "bright_cyan" if offset % 0x100 == 0 else "cyan"
        themed_offset_color = self.get_themed_color(base_color)
        offset_str = f"[{themed_offset_color}]{offset:08x}[/]"
        
        # ℌ𐑧𐑒𐑕 𐑚𐑲𐑑𐑟 𐑢𐑦𐑞 8-𐑚𐑲𐑑 𐑗𐑳𐑙𐑒 𐑜𐑮𐑿𐑐𐑦𐑙
        hex_bytes = []
        for i, byte_val in enumerate(row_data):
            byte_absolute_offset = offset + i
            annotations = self._get_annotations_for_offset(byte_absolute_offset)
            
            # 𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑑 8-𐑚𐑲𐑑 𐑗𐑳𐑙𐑒 𐑩𐑯𐑑𐑮𐑴𐑐𐑦 𐑓𐑹 𐑞𐑦𐑕 𐑚𐑲𐑑 𐑩𐑮𐑦𐑩
            chunk_start = (i // 8) * 8
            chunk_end = min(chunk_start + 8, len(row_data))
            chunk_entropy = self.calculate_shannon_entropy(row_data[chunk_start:chunk_end])
            
            color_code = self._get_color_code_for_annotations(annotations, byte_val, chunk_entropy)
            
            # 𐑗𐑧𐑒 𐑦𐑓 𐑞𐑦𐑕 𐑦𐑟 𐑞 𐑒𐑳𐑮𐑩𐑯𐑑 𐑒𐑻𐑕𐑼 𐑐𐑩𐑟𐑦𐑖𐑩𐑯
            cursor_offset = getattr(self, 'cursor_offset', 0)
            is_cursor_position = (byte_absolute_offset == self.current_offset + cursor_offset)
            
            if is_cursor_position:
                # ℌ𐑲𐑤𐑲𐑑 𐑒𐑳𐑮𐑩𐑯𐑑 𐑒𐑻𐑕𐑼 𐑐𐑩𐑟𐑦𐑖𐑩𐑯 𐑢𐑦𐑞 𐑦𐑯𐑝𐑻𐑑 𐑚𐑨𐑒𐑜𐑮𐑬𐑯𐑛
                hex_bytes.append(f"[bold white on blue]{byte_val:02x}[/]")
            else:
                hex_bytes.append(f"{color_code}{byte_val:02x}[/]")
            
            # 𐑨𐑛 8-𐑚𐑲𐑑 𐑛𐑦𐑤𐑦𐑥𐑦𐑑𐑼 (𐑓𐑱𐑯𐑑 𐑝𐑻𐑑𐑦𐑒𐑩𐑤 𐑛𐑦𐑤𐑦𐑥𐑦𐑑𐑼)
            if (i + 1) % 8 == 0 and i < len(row_data) - 1:
                hex_bytes.append("[dim white]│[/]")
            
        # 𐑐𐑨𐑛 𐑦𐑯𐑒𐑩𐑥𐑐𐑤𐑰𐑑 𐑮𐑴𐑟
        while len([b for b in hex_bytes if not b.startswith('[dim white]│')]) < self.bytes_per_row:
            hex_bytes.append("  ")
            
        hex_str = " ".join(hex_bytes)
        
        # 𐑦𐑯𐑣𐑨𐑯𐑕𐑑 ASCII 𐑜𐑳𐑑𐑼 𐑢𐑦𐑞 UTF-16 𐑛𐑦𐑑𐑧𐑒𐑖𐑩𐑯 𐑯 𐑩𐑯𐑑𐑮𐑴𐑐𐑦-𐑚𐑱𐑕𐑑 𐑚𐑮𐑲𐑑𐑯𐑩𐑕
        ascii_chars = []
        if self.show_ascii:
            i = 0
            while i < len(row_data):
                byte_absolute_offset = offset + i
                annotations = self._get_annotations_for_offset(byte_absolute_offset)
                byte_val = row_data[i]
                
                # 𐑗𐑧𐑒 𐑓𐑹 UTF-16 𐑤𐑦𐑑𐑩𐑤 𐑩𐑯𐑛𐑦𐑩𐑯 (𐑚𐑲𐑑 𐑓𐑪𐑤𐑴𐑛 𐑚𐑲 00)
                is_utf16_le = (i < len(row_data) - 1 and 
                              32 <= byte_val <= 126 and 
                              row_data[i + 1] == 0x00)
                
                cursor_offset = getattr(self, 'cursor_offset', 0)
                is_cursor_position = (byte_absolute_offset == self.current_offset + cursor_offset)
                
                if is_utf16_le:
                    # UTF-16 LE 𐑒𐑨𐑮𐑨𐑒𐑑𐑼 - 𐑛𐑩𐑚𐑩𐑤-𐑕𐑐𐑱𐑕𐑑 𐑐𐑨𐑕𐑑𐑩𐑤 𐑐𐑻𐑐𐑩𐑤
                    char = chr(byte_val)
                    if is_cursor_position:
                        ascii_chars.append(f"[bold white on blue]{char} [/]")
                    else:
                        # 𐑐𐑨𐑕𐑑𐑩𐑤 𐑐𐑻𐑐𐑩𐑤-𐑐𐑨𐑕𐑑𐑩𐑤 𐑛𐑩𐑚𐑩𐑤 𐑔 𐑯 𐑦𐑯𐑛𐑦𐑒𐑱𐑑 UTF-16
                        utf16_color = self.get_themed_color('magenta')
                        ascii_chars.append(f"[{utf16_color}]{char} [/]")
                    i += 2  # 𐑕𐑒𐑦𐑐 2 𐑚𐑲𐑑𐑟 𐑓𐑹 UTF-16
                elif 32 <= byte_val <= 126:
                    # 𐑐𐑮𐑦𐑯𐑑𐑩𐑚𐑩𐑤 ASCII
                    char = chr(byte_val)
                    if is_cursor_position:
                        ascii_chars.append(f"[bold white on blue]{char}[/]")
                    else:
                        ascii_color = self.get_themed_color('bright_white')
                        ascii_chars.append(f"[{ascii_color}]{char}[/]")
                    i += 1
                else:
                    # 𐑯𐑪𐑯𐑐𐑮𐑦𐑯𐑑𐑩𐑚𐑩𐑤 𐑚𐑲𐑑 - 𐑩𐑯𐑑𐑮𐑴𐑐𐑦-𐑚𐑱𐑕𐑑 𐑚𐑮𐑲𐑑𐑯𐑩𐑕
                    # 𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑑 𐑩𐑯𐑑𐑮𐑴𐑐𐑦 𐑝𐑨𐑤𐑿 𐑓𐑹 𐑞𐑦𐑕 𐑚𐑲𐑑
                    chunk_start = (i // 8) * 8
                    chunk_end = min(chunk_start + 8, len(row_data))
                    chunk_entropy = self.calculate_shannon_entropy(row_data[chunk_start:chunk_end])
                    entropy_brightness = self.get_entropy_color(chunk_entropy)
                    
                    if is_cursor_position:
                        ascii_chars.append(f"[bold white on blue].[/]")
                    else:
                        ascii_chars.append(f"{entropy_brightness}.[/]")
                    i += 1
            
            # 𐑐𐑨𐑛 ASCII 𐑐𐑸𐑑 𐑓𐑹 𐑒𐑩𐑯𐑕𐑦𐑕𐑑𐑩𐑯𐑑 𐑢𐑦𐑛𐑔
            while len(ascii_chars) < self.bytes_per_row:
                ascii_chars.append(" ")
                
        ascii_str = "".join(ascii_chars)
        
        # 𐑩𐑯𐑑𐑮𐑴𐑐𐑦 𐑕𐑐𐑸𐑒𐑤𐑲𐑯 𐑪𐑯 𐑞 𐑮𐑲𐑑
        entropy_bar = self.get_entropy_bar_char(row_entropy)
        entropy_color = self.get_entropy_color(row_entropy)
        
        return f'{offset_str}  {hex_str}  |{ascii_str}| {entropy_color}{entropy_bar}[/]'
        
    def calculate_shannon_entropy(self, data: bytes) -> float:
        """𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑑 𐑖𐑨𐑯𐑩𐑯 𐑩𐑯𐑑𐑮𐑴𐑐𐑦 𐑓𐑹 𐑩 𐑚𐑲𐑑 𐑕𐑦𐑒𐑢𐑩𐑯𐑕"""
        if not data:
            return 0.0
        
        # 𐑯𐑿: 𐑒𐑨𐑖 𐑩𐑯𐑑𐑮𐑴𐑐𐑦 𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑖𐑩𐑯𐑟
        data_hash = hash(data)
        if data_hash in self._entropy_cache:
            return self._entropy_cache[data_hash]
        
        # 𐑒𐑬𐑯𐑑 𐑞 𐑓𐑮𐑦𐑒𐑢𐑩𐑯𐑕𐑦 𐑝 𐑰𐑗 𐑚𐑲𐑑
        counter = Counter(data)
        length = len(data)
        
        # 𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑑 𐑖𐑨𐑯𐑩𐑯 𐑩𐑯𐑑𐑮𐑴𐑐𐑦
        entropy = 0.0
        for count in counter.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)
        
        # 𐑒𐑨𐑖 𐑞 𐑮𐑦𐑟𐑳𐑤𐑑 (𐑤𐑦𐑥𐑦𐑑 𐑒𐑨𐑖 𐑕𐑲𐑟)
        if len(self._entropy_cache) < 1000:
            self._entropy_cache[data_hash] = entropy
        
        return entropy
    
    def get_entropy_color(self, entropy: float) -> str:
        """𐑜𐑧𐑑 𐑔𐑰𐑥𐑛 𐑒𐑩𐑤𐑼 𐑚𐑱𐑟𐑛 𐑪𐑯 𐑩𐑯𐑑𐑮𐑴𐑐𐑦 𐑝𐑨𐑤𐑿"""
        theme = self.theme_styles.get(self.current_theme, self.theme_styles['cybernoir'])
        
        if entropy < 2.0:
            color = theme.get('low_entropy', 'dim blue')
        elif entropy < 4.0:
            color = 'dim white'  # 𐑤𐑴-𐑥𐑦𐑛 𐑩𐑯𐑑𐑮𐑴𐑐𐑦
        elif entropy < 6.0:
            color = theme.get('medium_entropy', 'yellow')
        elif entropy < 7.0:
            color = 'bright_yellow'  # 𐑣𐑲 𐑩𐑯𐑑𐑮𐑴𐑐𐑦
        else:
            color = theme.get('high_entropy', 'red')  # 𐑝𐑧𐑮𐑦 𐑣𐑲 𐑩𐑯𐑑𐑮𐑴𐑐𐑦 (𐑐𐑨𐑒𐑑/𐑦𐑯𐑒𐑮𐑦𐑐𐑑𐑦𐑛)
            
        return f'[{color}]'
    
    def get_entropy_bar_char(self, entropy: float) -> str:
        """𐑜𐑧𐑑 𐑚𐑸 𐑗𐑸 𐑓𐑹 𐑩𐑯𐑑𐑮𐑴𐑐𐑦 𐑕𐑐𐑸𐑒𐑤𐑲𐑯"""
        bar_chars = "▁▂▃▄▅▆▇█"
        index = min(int(entropy), len(bar_chars) - 1)
        return bar_chars[index]
    
    def get_section_background_color(self, annotations: List[HexViewAnnotation]) -> str:
        """𐑜𐑧𐑑 𐑕𐑧𐑒𐑖𐑩𐑯-𐑩𐑤 𐑚𐑨𐑒𐑜𐑮𐑬𐑯𐑛 𐑒𐑩𐑤𐑼 𐑓𐑹 𐑕𐑧𐑒𐑖𐑩𐑯"""
        section_annotations = [ann for ann in annotations if ann.annotation_type == 'section']
        if not section_annotations:
            return ''
        
        section_name = section_annotations[0].metadata.get('section_name', '').lower()
        
        # 𐑕𐑧𐑒𐑖𐑩𐑯-𐑩𐑤 𐑚𐑨𐑒𐑜𐑮𐑬𐑯𐑛 𐑚𐑱𐑟𐑛 𐑒𐑩𐑤𐑹𐑦𐑙 (𐑕𐑨𐑚𐑑𐑤 𐑓𐑨𐑒𐑜𐑮𐑬𐑯𐑛 𐑧𐑳𐑟)
        section_bg_colors = {
            '.text': 'on rgb(20,40,20)',    # 𐑛𐑦𐑥 𐑜𐑮𐑰 𐑚𐑨𐑒𐑜𐑮𐑬𐑯𐑛 - 𐑦𐑒𐑟𐑦𐑿𐑑𐑩𐑚𐑩𐑤 𐑒𐑴𐑛
            '.rdata': 'on rgb(20,20,40)',  # 𐑛𐑦𐑥 𐑚𐑤𐑿 𐑚𐑨𐑒𐑜𐑮𐑬𐑯𐑛 - 𐑮𐑰𐑛-𐑴𐑯𐑤𐑦 𐑛𐑱𐑑𐑩
            '.data': 'on rgb(40,20,20)',  # 𐑛𐑦𐑥 𐑮𐑧𐑛 𐑚𐑨𐑒𐑜𐑮𐑬𐑯𐑛 - 𐑛𐑱𐑑𐑩
            '.rsrc': 'on rgb(40,40,20)',  # 𐑛𐑦𐑥 𐑲𐑧𐑤𐑴 𐑚𐑨𐑒𐑜𐑮𐑬𐑯𐑛 - 𐑮𐑦𐑟𐑹𐑟’𐑦𐑟
            '.bss': 'on rgb(30,30,30)',   # 𐑑𐑸𐑑 𐑜𐑮𐑱 𐑚𐑨𐑒𐑜𐑮𐑬𐑯𐑛 - 𐑩𐑯𐑦𐑯𐑦𐑖𐑹𐑤𐑲𐑟𐑛 𐑛𐑱𐑑𐑩
            '.rodata': 'on rgb(20,30,40)', # 𐑛𐑦𐑥 𐑚𐑲𐑟 𐑚𐑨𐑒𐑜𐑮𐑬𐑯𐑛 - 𐑮𐑰𐑛-𐑴𐑯𐑤𐑦 𐑛𐑱𐑑𐑩
        }
        
        return section_bg_colors.get(section_name, '')
    
    def _get_color_code_for_annotations(self, annotations: List[HexViewAnnotation], byte_val: int = None, chunk_entropy: float = None) -> str:
        """𐑜𐑧𐑑 𐑑𐑧𐑒𐑕𐑑𐑿𐑩𐑤 𐑒𐑩𐑤𐑼 𐑒𐑴𐑛 𐑓𐑹 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑯 𐑩𐑯𐑑𐑮𐑴𐑐𐑦"""
        # 𐑯𐑿: 𐑒𐑨𐑖 𐑒𐑩𐑤𐑼 𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑖𐑩𐑯𐑟 𐑓𐑹 𐑚𐑧𐑑𐑼 𐑐𐑻𐑓𐑹𐑥𐑩𐑯𐑕
        cache_key = (len(annotations), byte_val, chunk_entropy) if annotations else (0, byte_val, chunk_entropy)
        if not hasattr(self, '_color_cache'):
            self._color_cache = {}
            
        if cache_key in self._color_cache:
            return self._color_cache[cache_key]
        
        # 𐑜𐑧𐑑 𐑕𐑧𐑒𐑖𐑩𐑯 𐑚𐑨𐑒𐑜𐑮𐑬𐑯𐑛 𐑒𐑩𐑤𐑼 𐑓𐑻𐑕𐑑
        section_bg = self.get_section_background_color(annotations)
        
        # 𐑦𐑓 𐑯𐑴 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟, 𐑿𐑟 𐑩𐑯𐑑𐑮𐑴𐑐𐑦-𐑚𐑱𐑟𐑛 𐑒𐑩𐑤𐑼𐑦𐑙
        if not annotations and chunk_entropy is not None:
            entropy_color = self.get_entropy_color(chunk_entropy).replace('[', '').replace(']', '')
            return f'[{entropy_color} {section_bg}]' if section_bg else f'[{entropy_color}]'
        
        if not annotations:
            # 𐑓𐑷𐑤𐑚𐑨𐑒 𐑑 𐑛𐑦𐑓𐑹𐑩𐑯𐑑 𐑒𐑩𐑤𐑼𐑟 𐑓𐑹 𐑛𐑦𐑓𐑻𐑩𐑯𐑑 𐑚𐑲𐑑 𐑝𐑨𐑤𐑿𐑟
            if byte_val == 0:
                color = 'dim blue'  # 𐑯𐑳𐑤 𐑚𐑲𐑑𐑟
            elif byte_val == 0xFF:
                color = 'dim white'  # 0xFF 𐑚𐑲𐑑𐑟
            elif 32 <= byte_val <= 126:
                color = 'bright_white'  # 𐑐𐑮𐑦𐑯𐑑𐑩𐑚𐑩𐑤 ASCII
            else:
                color = 'white'     # 𐑳𐑞𐑼 𐑚𐑲𐑑𐑟
            
            return f'[{color} {section_bg}]' if section_bg else f'[{color}]'
        
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
            'section': 'blue',
            'string': 'green', 
            'entropy': 'yellow',
            'suggestion': 'red'
        }
        
        foreground_color = color_map.get(highest_annotation.annotation_type, 'white')
        # 𐑩𐑐𐑤𐑲 𐑔𐑰𐑥-𐑩𐑢𐑺 𐑒𐑩𐑤𐑼 𐑩𐑛𐑡𐑳𐑕𐑑𐑩𐑯𐑑
        themed_color = self.get_themed_color(foreground_color, highest_annotation.annotation_type)
        result = f'[{themed_color} {section_bg}]' if section_bg else f'[{themed_color}]'
        
        # 𐑒𐑨𐑖 𐑞 𐑮𐑦𐑟𐑳𐑤𐑑 (𐑤𐑦𐑥𐑦𐑑 𐑒𐑨𐑖 𐑕𐑲𐑟)
        if len(self._color_cache) < 5000:
            self._color_cache[cache_key] = result
        
        return result
        
    def scroll_up(self):
        """𐑕𐑒𐑮𐑴𐑤 𐑞 𐑣𐑧𐑒𐑕 𐑝𐑿 𐑳𐑐"""
        if self.current_offset > 0:
            self.current_offset = max(0, self.current_offset - self.bytes_per_row)
            self._clear_caches()  # 𐑒𐑤𐑽 𐑒𐑨𐑖𐑟 𐑢𐑧𐑯 𐑪𐑓𐑕𐑧𐑑 𐑗𐑱𐑯𐑡
    
    def scroll_down(self):
        """𐑕𐑒𐑮𐑴𐑤 𐑞 𐑣𐑧𐑒𐑕 𐑝𐑿 𐑛𐑬𐑯"""
        max_offset = max(0, self.file_size - self.bytes_per_row * self.display_rows)
        if self.current_offset < max_offset:
            self.current_offset = min(max_offset, self.current_offset + self.bytes_per_row)
            self._clear_caches()  # 𐑒𐑤𐑽 𐑒𐑨𐑖𐑟 𐑢𐑧𐑯 𐑪𐑓𐑕𐑧𐑑 𐑗𐑱𐑯𐑡
            
    def goto_offset(self, offset: int):
        """𐑜𐑴 𐑑 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑪𐑓𐑕𐑧𐑑"""
        if 0 <= offset < self.file_size:
            self.current_offset = offset - (offset % self.bytes_per_row)  # 𐑩𐑤𐑲𐑯 𐑑 𐑮𐑴 𐑚𐑬𐑯𐑛𐑼𐑦
            self._clear_caches()  # 𐑒𐑤𐑽 𐑒𐑨𐑖𐑟 𐑢𐑧𐑯 𐑪𐑓𐑕𐑧𐑑 𐑗𐑱𐑯𐑡
    
    def search_hex(self, hex_string: str) -> int:
        """𐑕𐑻𐑗 𐑓𐑹 𐑣𐑧𐑒𐑕 𐑚𐑲𐑑𐑟 𐑦𐑯 𐑞 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩"""
        try:
            search_bytes = bytes.fromhex(hex_string.replace(' ', ''))
            self.search_results = []
            
            # 𐑕𐑻𐑗 𐑦𐑯 𐑗𐑳𐑙𐑒𐑟 𐑑 𐑩𐑝𐑶𐑛 𐑤𐑴𐑛𐑦𐑙 ℌ𐑴𐑤 𐑓𐑲𐑤
            chunk_size = 8192  # 8KB 𐑗𐑳𐑙𐑒𐑟
            overlap = len(search_bytes) - 1
            
            for offset in range(0, self.file_size, chunk_size - overlap):
                chunk = self._read_chunk(offset, chunk_size)
                if not chunk:
                    break
                    
                for i in range(len(chunk) - len(search_bytes) + 1):
                    if chunk[i:i + len(search_bytes)] == search_bytes:
                        self.search_results.append(offset + i)
                        
            self.search_index = 0
            return len(self.search_results)
        except ValueError:
            return 0
    
    def search_string(self, search_string: str) -> int:
        """𐑕𐑻𐑗 𐑓𐑹 𐑩 𐑕𐑑𐑮𐑦𐑙 𐑦𐑯 𐑞 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩"""
        search_bytes = search_string.encode('utf-8', errors='ignore')
        self.search_results = []
        
        # 𐑕𐑻𐑗 𐑦𐑯 𐑗𐑳𐑙𐑒𐑟 𐑑 𐑩𐑝𐑶𐑛 𐑤𐑴𐑛𐑦𐑙 ℌ𐑴𐑤 𐑓𐑲𐑤
        chunk_size = 8192  # 8KB 𐑗𐑳𐑙𐑒𐑟
        overlap = len(search_bytes) - 1
        
        for offset in range(0, self.file_size, chunk_size - overlap):
            chunk = self._read_chunk(offset, chunk_size)
            if not chunk:
                break
                
            for i in range(len(chunk) - len(search_bytes) + 1):
                if chunk[i:i + len(search_bytes)] == search_bytes:
                    self.search_results.append(offset + i)
                    
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
    
    class TextualHexViewer(ScrollableContainer):
        """𐑑𐑧𐑒𐑕𐑑𐑿𐑩𐑤 ℌ𐑧𐑒𐑕 𐑝𐑿𐑼 𐑢𐑦𐑡𐑧𐑑"""
        
        def __init__(self, hex_viewer: HexViewer, **kwargs):
            super().__init__(**kwargs)
            self.hex_viewer = hex_viewer
            self.hex_content_widget = None
            
        def compose(self) -> ComposeResult:
            # 𐑩𐑛𐑡𐑳𐑕𐑑 𐑚𐑲𐑑𐑟 𐑐𐑼 𐑮𐑴 𐑚𐑱𐑟𐑛 𐑪𐑯 𐑑𐑻𐑥𐑦𐑯𐑩𐑤 𐑢𐑦𐑛𐑔
            self._adjust_bytes_per_row()
            
            # 𐑴𐑯𐑤𐑦 𐑤𐑴𐑛 𐑝𐑦𐑿𐑐𐑹𐑑 𐑛𐑱𐑑𐑩 - 𐑯𐑪𐑑 𐑞 𐑦𐑯𐑑𐑲𐑼 𐑓𐑲𐑤
            viewport_bytes = self.hex_viewer.bytes_per_row * self.hex_viewer.display_rows
            hex_content = self.hex_viewer.generate_textual_hex_view(max_bytes=viewport_bytes)
            self.hex_content_widget = Static(hex_content, id="hex-content")
            yield self.hex_content_widget
            
        def _adjust_bytes_per_row(self):
            """𐑩𐑛𐑡𐑳𐑕𐑑 𐑚𐑲𐑑𐑟 𐑐𐑼 𐑮𐑴 𐑯 𐑛𐑦𐑕𐑐𐑤𐑱 𐑮𐑴𐑟 𐑚𐑱𐑟𐑛 𐑪𐑯 𐑑𐑻𐑥𐑦𐑯𐑩𐑤 𐑕𐑲𐑟"""
            try:
                # 𐑜𐑧𐑑 𐑒𐑳𐑮𐑩𐑯𐑑 𐑑𐑻𐑥𐑦𐑯𐑩𐑤 𐑢𐑦𐑛𐑔 𐑯 ℌ𐑲𐑑 - 𐑑𐑮𐑲 𐑥𐑩𐑤𐑑𐑦𐑐𐑩𐑤 𐑨𐑐𐑮𐑴𐑗𐑦𐑟
                terminal_width = 80  # 𐑛𐑦𐑓𐑷𐑤𐑑 𐑓𐑷𐑤𐑚𐑨𐑒
                terminal_height = 24  # 𐑛𐑦𐑓𐑷𐑤𐑑 𐑓𐑷𐑤𐑚𐑨𐑒
                
                # 𐑑𐑮𐑲 𐑑 𐑜𐑧𐑑 𐑑𐑻𐑥𐑦𐑯𐑩𐑤 𐑕𐑲𐑟 𐑦𐑯 𐑪𐑮𐑛𐑼 𐑝 𐑐𐑮𐑦𐑓𐑼𐑧𐑯𐑕
                try:
                    # 𐑓𐑻𐑕𐑑: 𐑑𐑮𐑲 app.size
                    if hasattr(self, 'app') and hasattr(self.app, 'size') and self.app.size:
                        terminal_width = self.app.size.width
                        terminal_height = self.app.size.height
                    # 𐑕𐑧𐑒𐑩𐑯𐑛: 𐑑𐑮𐑲 widget size
                    elif hasattr(self, 'size') and self.size:
                        terminal_width = self.size.width
                        terminal_height = self.size.height
                    # 𐑔𐑻𐑛: 𐑯𐑴 Textual app, 𐑿𐑟 𐑕𐑦𐑕𐑑𐑩𐑥 𐑑𐑻𐑥𐑦𐑯𐑩𐑤 𐑕𐑲𐑟
                    else:
                        import shutil
                        size = shutil.get_terminal_size()
                        terminal_width = size.columns
                        terminal_height = size.lines
                except Exception:
                    pass
                
                # 𐑦𐑓 𐑒𐑨𐑯𐑑 𐑛𐑦𐑑𐑧𐑒𐑑 𐑢𐑦𐑛𐑔, 𐑿𐑟 𐑩 𐑡𐑧𐑯𐑼𐑩𐑕 144 ℌ𐑑 𐑢𐑨𐑦𐑛 𐑑𐑻𐑥𐑦𐑯𐑩𐑤
                if terminal_width <= 80:
                    terminal_width = 144  # 𐑩𐑕𐑿𐑥 𐑩 𐑢𐑲𐑛 𐑑𐑻𐑥𐑦𐑯𐑩𐑤 𐑦𐑓 𐑛𐑦𐑑𐑧𐑒𐑖𐑩𐑯 𐑓𐑱𐑤𐑟
                
                # 𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑑 𐑪𐑐𐑑𐑦𐑥𐑩𐑤 𐑚𐑲𐑑𐑟 𐑐𐑼 𐑮𐑴
                # 𐑓𐑹𐑥𐑨𐑑: [8-char offset]  [hex bytes]  |[ascii]| [entropy]
                # Fixed 𐑪𐑝𐑼ℌ𐑧𐑛: 8 (offset) + 2 (spaces) + 3 (ASCII delim) + 2 (entropy) = 15
                overhead = 15
                
                # 𐑰𐑗 𐑚𐑲𐑑: 2 ℌ𐑧𐑒𐑕 + 1 𐑕𐑐𐑱𐑕 + 1 ASCII = 4 𐑗𐑸𐑟 𐑐𐑼 𐑚𐑲𐑑  
                # + 8-𐑚𐑲𐑑 𐑛𐑦𐑤𐑦𐑥𐑦𐑑𐑼 ℌ 8 𐑚𐑲𐑑𐑟 = ~0.125 ℌ 𐑚𐑲𐑑
                chars_per_byte = 4.125  # 𐑦𐑯𐑒𐑤𐑿𐑛 𐑞 𐑛𐑦𐑤𐑦𐑥𐑦𐑑𐑼
                
                # 𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑑 available space 𐑯 ℌ𐑬 𐑥𐑧𐑯𐑦 𐑚𐑲𐑑𐑟 𐑦𐑤 𐑓𐑦𐑑
                available_width = terminal_width - overhead
                raw_bytes_estimate = int(available_width / chars_per_byte)
                
                # 𐑮𐑬𐑯𐑛 𐑛𐑬𐑯 𐑑 𐑯𐑽𐑦𐑕𐑑 8-𐑚𐑲𐑑 𐑚𐑬𐑯𐑛𐑼𐑦 (𐑓𐑹 8-𐑚𐑲𐑑 𐑕𐑧𐑜𐑥𐑧𐑯𐑑 alignment)
                new_bytes_per_row = (raw_bytes_estimate // 8) * 8
                
                # 𐑧𐑯𐑓𐑹𐑕 𐑮𐑦𐑟𐑩𐑯𐑩𐑚𐑩𐑤 𐑤𐑦𐑥𐑦𐑑𐑟 (𐑩𐑛 𐑦𐑯 8 𐑦𐑓 𐑕𐑦𐑯𐑜𐑩𐑤 𐑛𐑦𐑡𐑦𐑑)
                if new_bytes_per_row < 8:
                    new_bytes_per_row = 8
                elif new_bytes_per_row > 64:
                    new_bytes_per_row = 64
                
                # 𐑨𐑛 𐑦𐑯 8 bytes 𐑦𐑓 𐑴𐑯𐑤𐑦 16 ℎ𐑨𐑝 ℌ smaller terminal
                if new_bytes_per_row <= 16 and terminal_width > 100:
                    new_bytes_per_row = 24
                
                self.hex_viewer.bytes_per_row = new_bytes_per_row
                
                # 𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑑 𐑪𐑐𐑑𐑦𐑥𐑩𐑤 𐑛𐑦𐑕𐑐𐑤𐑱 𐑮𐑴𐑟 𐑚𐑱𐑟𐑛 𐑪𐑯 terminal ℌ𐑲𐑑
                # 𐑩𐑒𐑬𐑯𐑑 𐑓𐑹 ℌ𐑧𐑛𐑼 (1 𐑮𐑴) + 𐑓𐑫𐑑𐑼 (1 𐑮𐑴) + 𐑥𐑦𐑯𐑦𐑥𐑩𐑤 𐑐𐑨𐑛𐑦𐑙 (2 𐑮𐑴𐑟)
                reserved_rows = 4  # ℌ𐑧𐑛𐑼, 𐑓𐑫𐑑𐑼, 𐑯 𐑕𐑩𐑥 𐑐𐑨𐑛𐑦𐑙
                available_rows = max(10, terminal_height - reserved_rows)  # minimum 10 𐑮𐑴𐑟
                
                # 𐑧𐑯𐑓𐑹𐑕 𐑮𐑦𐑟𐑩𐑯𐑩𐑚𐑩𐑤 𐑥𐑨𐑒𐑕𐑦𐑥𐑩𐑥 (𐑓𐑹 𐑐𐑼𐑓𐑹𐑥𐑩𐑯𐑕)
                self.hex_viewer.display_rows = min(available_rows, 100)  # cap 𐑨𐑑 100 𐑮𐑴𐑟 𐑓𐑹 performance
                
            except Exception:
                # 𐑓𐑷𐑤𐑚𐑨𐑒: 𐑓𐑹𐑕 32 𐑚𐑲𐑑𐑟 𐑐𐑼 𐑮𐑴 (doubled 𐑓𐑮𐑩𐑥 16) 𐑯 𐑛𐑦𐑓𐑷𐑤𐑑 𐑮𐑴𐑟
                self.hex_viewer.bytes_per_row = 32
                if not hasattr(self.hex_viewer, 'display_rows') or self.hex_viewer.display_rows <= 0:
                    self.hex_viewer.display_rows = 24
                
        def refresh_content(self):
            """𐑮𐑦𐑓𐑮𐑧𐑖 ℌ𐑧𐑒𐑕 𐑒𐑩𐑯𐑑𐑧𐑯𐑑 𐑢𐑦𐑞 𐑳𐑐𐑛𐑱𐑑𐑦𐑛 𐑢𐑦𐑛𐑔"""
            if self.hex_content_widget:
                self._adjust_bytes_per_row()
                viewport_bytes = self.hex_viewer.bytes_per_row * self.hex_viewer.display_rows
                new_content = self.hex_viewer.generate_textual_hex_view(max_bytes=viewport_bytes)
                self.hex_content_widget.update(new_content)
                
        def on_mount(self):
            """𐑒𐑷𐑤𐑛 𐑨𐑓𐑑𐑼 𐑥𐑬𐑯𐑑𐑦𐑙 - 𐑮𐑦-𐑩𐑛𐑡𐑳𐑕𐑑 𐑚𐑲𐑑𐑟 𐑐𐑼 𐑮𐑴 𐑯𐑬 𐑞𐑨𐑑 app 𐑦𐑟 𐑮𐑳𐑯𐑦𐑙"""
            self.refresh_content()
    
    
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
            layout: vertical;
        }

        /* Full-width hex display with proper padding - use 1fr to fill remaining space after header/footer */
        #hex-viewer {
            width: 100%;
            height: 1fr;
            background: $surface;
            margin: 0;
            padding: 0;
            scrollbar-size: 1 1;
            overflow-y: auto;
            overflow-x: auto;
        }
        
        /* Hex content within the scrollable container */
        #hex-content {
            width: 100%;
            height: auto;
            padding: 0 1;
            margin: 0;
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
            Binding("c", "copy_current_byte", "Copy current byte"),
            Binding("left", "cursor_left", "Move cursor left"),
            Binding("right", "cursor_right", "Move cursor right"),
            Binding("h", "cursor_left", "Move cursor left"),
            Binding("l", "cursor_right", "Move cursor right"),
            Binding("t", "cycle_theme", "Cycle theme"),
            Binding("d", "show_disasm", "Show disassembly"),
        ]
        
        def __init__(self, hex_viewer: HexViewer, **kwargs):
            super().__init__(**kwargs)
            self.hex_viewer = hex_viewer
            # 𐑨𐑑 𐑒𐑻𐑕𐑼 𐑐𐑪𐑟𐑦𐑖𐑩𐑯 𐑪𐑯 𐑣𐑧𐑒𐑕 𐑝𐑲𐑼𐑥 𐑦𐑑𐑕𐑧𐑤𐑓 №ℓ
            if not hasattr(self.hex_viewer, 'cursor_offset'):
                self.hex_viewer.cursor_offset = 0
            
        def compose(self) -> ComposeResult:
            """𐑒𐑩𐑥𐑐𐑴𐑟 𐑞 𐑨𐑐 𐑦𐑯𐑑𐑼𐑓𐑱𐑕"""
            yield Header(show_clock=True)
            yield TextualHexViewer(self.hex_viewer, id="hex-viewer")
            yield Footer()
            
        def on_resize(self, event):
            """ℌ𐑨𐑯𐑛𐑩𐑤 𐑮𐑦𐑟𐑲𐑟 𐑦𐑝𐑧𐑯𐑑𐑟 𐑑 𐑩𐑛𐑡𐑳𐑕𐑑 ℌ𐑧𐑒𐑕 𐑛𐑦𐑕𐑐𐑤𐑱"""
            try:
                hex_viewer_widget = self.query_one("#hex-viewer", TextualHexViewer)
                hex_viewer_widget.refresh_content()
            except Exception:
                pass
            
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
            self.hex_viewer._clear_caches()  # 𐑒𐑤𐑽 𐑒𐑨𐑖𐑟 𐑢𐑧𐑯 𐑪𐑓𐑕𐑧𐑑 𐑗𐑱𐑯𐑡
            self._refresh_display()
            
        def action_goto_bottom(self):
            """𐑜𐑴 𐑑 𐑞 𐑚𐑪𐑑𐑩𐑥 𐑝 𐑞 ℌ𐑧𐑒𐑕 𐑝𐑿"""
            max_offset = max(0, self.hex_viewer.file_size - self.hex_viewer.bytes_per_row * self.hex_viewer.display_rows)
            self.hex_viewer.current_offset = max_offset
            self.hex_viewer._clear_caches()  # 𐑒𐑤𐑽 𐑒𐑨𐑖𐑟 𐑢𐑧𐑯 𐑤𐑨𐑮𐑡 𐑡𐑳𐑥𐑐
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
            
        def action_copy_current_byte(self):
            """𐑒𐑩𐑐𐑦 𐑞 𐑒𐑹𐑩𐑯𐑑 𐑚𐑲𐑑 𐑝𐑨𐑤𐑿 𐑑 𐑒𐑤𐑦𐑐𐑚𐑪𐑮𐑛"""
            try:
                # 𐑜𐑧𐑑 𐑞 𐑒𐑹𐑩𐑯𐑑 𐑚𐑲𐑑 𐑨𐑑 𐑒𐑻𐑩𐑯𐑑 𐑪𐑓𐑕𐑧𐑑 + 𐑒𐑻𐑕𐑼 𐑐𐑪𐑟𐑦𐑖𐑩𐑯
                current_absolute_offset = self.hex_viewer.current_offset + self.hex_viewer.cursor_offset
                
                if current_absolute_offset < self.hex_viewer.file_size:
                    chunk = self.hex_viewer._read_chunk(current_absolute_offset, 1)
                    if chunk:
                        current_byte = chunk[0]
                    else:
                        return
                    byte_hex = f"{current_byte:02X}"
                    
                    # 𐑑𐑮𐑲 𐑑 𐑒𐑩𐑐𐑦 𐑑 𐑒𐑤𐑦𐑐𐑚𐑪𐑮𐑛 𐑿𐑟𐑦𐑙 𐑕𐑦𐑕𐑑𐑩𐑥 𐑒𐑩𐑥𐑨𐑯𐑛𐑟
                    import subprocess
                    import sys
                    
                    # 𐑑𐑮𐑲 𐑛𐑦𐑓𐑻𐑩𐑯𐑑 𐑒𐑤𐑦𐑐𐑚𐑪𐑮𐑛 𐑯𐑦𐑤𐑦𐑑𐑦𐑟 𐑛𐑦𐑐𐑧𐑯𐑛𐑦𐑙 𐑪𐑯 𐑞 𐑕𐑦𐑕𐑑𐑩𐑥
                    clipboard_success = False
                    
                    try:
                        # Linux/WSL with xclip
                        subprocess.run(['xclip', '-selection', 'clipboard'], 
                                     input=byte_hex.encode(), check=True)
                        clipboard_success = True
                    except (subprocess.CalledProcessError, FileNotFoundError):
                        try:
                            # Linux/WSL with xsel
                            subprocess.run(['xsel', '--clipboard', '--input'], 
                                         input=byte_hex.encode(), check=True)
                            clipboard_success = True
                        except (subprocess.CalledProcessError, FileNotFoundError):
                            try:
                                # Try wl-clipboard for Wayland
                                subprocess.run(['wl-copy'], 
                                             input=byte_hex.encode(), check=True)
                                clipboard_success = True
                            except (subprocess.CalledProcessError, FileNotFoundError):
                                try:
                                    # macOS
                                    subprocess.run(['pbcopy'], 
                                                 input=byte_hex.encode(), check=True)
                                    clipboard_success = True
                                except (subprocess.CalledProcessError, FileNotFoundError):
                                    # Windows
                                    try:
                                        import pyperclip
                                        pyperclip.copy(byte_hex)
                                        clipboard_success = True
                                    except ImportError:
                                        pass
                    
                    if clipboard_success:
                        self.notify(f"Copied byte 0x{byte_hex} (offset: 0x{current_absolute_offset:08X}) to clipboard")
                    else:
                        # 𐑓𐑷𐑤𐑚𐑨𐑒 - 𐑡𐑳𐑕𐑑 𐑖𐑴 𐑞 𐑝𐑨𐑤𐑿
                        self.notify(f"Byte value: 0x{byte_hex} (offset: 0x{current_absolute_offset:08X}) - clipboard not available")
                else:
                    self.notify("No byte at current position")
                    
            except Exception as e:
                self.notify(f"Error copying byte: {str(e)}")
                
        def action_cursor_left(self):
            """𐑥𐑿𐑝 𐑒𐑻𐑕𐑼 𐑤𐑧𐑓𐑑"""
            if self.hex_viewer.cursor_offset > 0:
                self.hex_viewer.cursor_offset -= 1
                self._refresh_display()
            elif self.hex_viewer.current_offset > 0:
                # 𐑥𐑿𐑝 𐑑 𐑐𐑮𐑦𐑝𐑦𐑩𐑕 𐑮𐑴
                self.hex_viewer.current_offset = max(0, self.hex_viewer.current_offset - self.hex_viewer.bytes_per_row)
                remaining_bytes = self.hex_viewer.file_size - self.hex_viewer.current_offset
                self.hex_viewer.cursor_offset = min(self.hex_viewer.bytes_per_row - 1, remaining_bytes - 1)
                self._refresh_display()
                
        def action_cursor_right(self):
            """𐑥𐑿𐑝 𐑒𐑻𐑕𐑼 𐑮𐑲𐑑"""
            current_absolute_offset = self.hex_viewer.current_offset + self.hex_viewer.cursor_offset
            
            if current_absolute_offset < self.hex_viewer.file_size - 1:
                # 𐑕𐑑𐑱 𐑦𐑯 𐑞 𐑒𐑳𐑮𐑩𐑯𐑑 𐑝𐑿
                remaining_bytes = self.hex_viewer.file_size - self.hex_viewer.current_offset
                visible_bytes = min(remaining_bytes, self.hex_viewer.bytes_per_row * self.hex_viewer.display_rows)
                if self.hex_viewer.cursor_offset < visible_bytes - 1:
                    self.hex_viewer.cursor_offset += 1
                    self._refresh_display()
                else:
                    # 𐑕𐑒𐑮𐑴𐑤 𐑑 𐑯𐑧𐑒𐑕𐑑 𐑮𐑴
                    self.hex_viewer.current_offset += self.hex_viewer.bytes_per_row
                    self.hex_viewer.cursor_offset = 0
                    self._refresh_display()
        
        def action_cycle_theme(self):
            """𐑕𐑲𐑒𐑩𐑤 𐑞𐑮𐑿 𐑞 𐑩𐑝𐑱𐑤𐑩𐑚𐑩𐑤 𐑞𐑰𐑥𐑟"""
            themes = ['cybernoir', 'monochrome', 'hellfire']
            current_index = themes.index(self.hex_viewer.current_theme)
            next_index = (current_index + 1) % len(themes)
            next_theme = themes[next_index]
            
            self.hex_viewer.set_theme(next_theme)
            self._refresh_display()
            
            theme_names = {
                'cybernoir': '🌃 Cybernoir',
                'monochrome': '⬛ Monochrome Brutalism', 
                'hellfire': '🔥 Terminal Hellfire'
            }
            self.notify(f"Theme: {theme_names[next_theme]}")
            
        def action_show_disasm(self):
            """𐑖𐑴 𐑦𐑯𐑤𐑲𐑯 𐑛𐑦𐑕𐑨𐑟𐑩𐑥𐑚𐑤𐑦 𐑝 𐑞 𐑒𐑳𐑮𐑩𐑯𐑑 𐑚𐑲𐑑 𐑮𐑱𐑯𐑡"""
            try:
                import capstone
                
                # 𐑜𐑧𐑑 𐑞 𐑒𐑳𐑮𐑩𐑯𐑑 8-𐑚𐑲𐑑 𐑗𐑳𐑙𐑒 𐑨𐑞 𐑞 𐑒𐑻𐑕𐑼
                current_absolute_offset = self.hex_viewer.current_offset + self.hex_viewer.cursor_offset
                start_offset = (current_absolute_offset // 8) * 8  # 𐑩𐑤𐑲𐑯 𐑑 8-𐑚𐑲𐑑 𐑚𐑬𐑯𐑛𐑼𐑦
                
                # 𐑜𐑧𐑑 16 𐑚𐑲𐑑𐑟 𐑝 𐑛𐑱𐑑𐑩 𐑓𐑹 𐑛𐑦𐑕𐑨𐑟𐑩𐑥𐑚𐑤𐑦
                end_offset = min(start_offset + 16, self.hex_viewer.file_size)
                chunk = self.hex_viewer._read_chunk(start_offset, end_offset - start_offset)
                
                if not chunk:
                    self.notify("No data to disassemble")
                    return
                    
                # 𐑑𐑮𐑲 x86-64 𐑛𐑦𐑕𐑨𐑟𐑩𐑥𐑚𐑤𐑦 𐑓𐑻𐑕𐑑
                try:
                    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                    instructions = list(cs.disasm(chunk, start_offset))
                    
                    if instructions:
                        disasm_lines = []
                        for insn in instructions[:3]:  # 𐑤𐑦𐑥𐑦𐑑 𐑑 3 𐑦𐑯𐑕𐑑𐑮𐑳𐑒𐑖𐑩𐑯𐑟
                            disasm_lines.append(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
                        
                        disasm_text = "\\n".join(disasm_lines)
                        self.notify(f"x86-64 disassembly:\\n{disasm_text}")
                        return
                except:
                    pass
                    
                # 𐑦𐑓 x86-64 𐑓𐑱𐑤𐑟, 𐑑𐑮𐑲 x86-32
                try:
                    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                    instructions = list(cs.disasm(chunk, start_offset))
                    
                    if instructions:
                        disasm_lines = []
                        for insn in instructions[:3]:
                            disasm_lines.append(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
                        
                        disasm_text = "\\n".join(disasm_lines)
                        self.notify(f"x86-32 disassembly:\\n{disasm_text}")
                        return
                except:
                    pass
                    
                # 𐑦𐑓 x86 𐑓𐑱𐑤𐑟, 𐑑𐑮𐑲 ARM
                try:
                    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
                    instructions = list(cs.disasm(chunk, start_offset))
                    
                    if instructions:
                        disasm_lines = []
                        for insn in instructions[:3]:
                            disasm_lines.append(f"0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
                        
                        disasm_text = "\\n".join(disasm_lines)
                        self.notify(f"ARM64 disassembly:\\n{disasm_text}")
                        return
                except:
                    pass
                    
                self.notify(f"Could not disassemble at 0x{start_offset:08x}")
                
            except ImportError:
                self.notify("Capstone not available - install with: pip install capstone")
            except Exception as e:
                self.notify(f"Disassembly error: {str(e)}")
            
        def _refresh_display(self):
            """𐑮𐑰𐑓𐑮𐑧𐑖 𐑞 ℌ𐑧𐑒𐑕 𐑛𐑦𐑕𐑐𐑤𐑱"""
            try:
                hex_viewer_widget = self.query_one("#hex-viewer", TextualHexViewer)
                hex_viewer_widget.refresh_content()
            except Exception as e:
                # 𐑓𐑷𐑤𐑚𐑨𐑒 𐑑 𐑞 𐑴𐑤𐑛 𐑥𐑧𐑔𐑩𐑛 𐑦𐑓 𐑞 𐑯𐑿 𐑥𐑧𐑔𐑩𐑛 𐑓𐑱𐑤𐑟
                try:
                    hex_content_widget = self.query_one("#hex-content", Static)
                    # 𐑴𐑯𐑤𐑦 𐑤𐑴𐑛 𐑝𐑦𐑿𐑐𐑹𐑑 𐑛𐑱𐑑𐑩 - 𐑯𐑪𐑑 𐑞 𐑦𐑯𐑑𐑲𐑼 𐑓𐑲𐑤
                    viewport_bytes = self.hex_viewer.bytes_per_row * self.hex_viewer.display_rows
                    new_content = self.hex_viewer.generate_textual_hex_view(max_bytes=viewport_bytes)
                    hex_content_widget.update(new_content)
                except Exception:
                    # 𐑓𐑨𐑦𐑤 𐑮𐑰𐑓𐑮𐑧𐑖 𐑧𐑮𐑹𐑦 - 𐑦𐑜𐑯𐑹 𐑦𐑓 𐑯𐑴 𐑓𐑲𐑤
                    pass


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
        
        # 𐑯𐑿: 𐑩𐑰𐑕 𐑤𐑱𐑟𐑦 𐑤𐑴𐑛𐑦𐑙 𐑓𐑹 𐑓𐑨𐑕𐑑 𐑐𐑼𐑓𐑹𐑥𐑩𐑯𐑕
        hex_viewer.load_from_file(file_path)
        
        # 𐑮𐑳𐑯 𐑩𐑯𐑨𐑤𐑦𐑕𐑦𐑕 𐑞 ℌ𐑧𐑒𐑕 𐑝𐑿𐑼
        rewriter = BinaryRewriter(file_path, config)
        if rewriter.load_binary():
            # 𐑨𐑛 𐑕𐑧𐑒𐑖𐑩𐑯 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑓𐑨𐑕𐑑
            hex_viewer.add_section_annotations(rewriter.binary.sections)
            
            # 𐑯𐑿: 𐑤𐑦𐑥𐑦𐑑 𐑩𐑯𐑨𐑤𐑦𐑕𐑦𐑕 𐑓𐑹 𐑤𐑨𐑮𐑡 𐑓𐑲𐑤𐑟
            if hex_viewer.file_size < 50 * 1024 * 1024:  # 𐑴𐑯𐑤𐑦 𐑮𐑳𐑯 𐑓𐑳𐑤 𐑩𐑯𐑨𐑤𐑦𐑕𐑦𐑕 𐑦𐑓 < 50MB
                analysis_results = rewriter.plugin_manager.execute_analysis_phase(rewriter)
                hex_viewer.add_analysis_annotations(analysis_results)
                
                # 𐑨𐑛 𐑩𐑚𐑓𐑳𐑕𐑒𐑱𐑖𐑩𐑯 𐑟 𐑞
                suggestions = rewriter.suggest_obfuscation(return_suggestions=True)
                hex_viewer.add_obfuscation_suggestions(suggestions)
            else:
                # 𐑦𐑯𐑓𐑹𐑥 𐑿𐑟𐑼 𐑴𐑯𐑤𐑦 𐑩𐑯𐑨𐑤𐑦𐑕𐑦𐑕 𐑓𐑹 𐑤𐑨𐑮𐑡 𐑓𐑲𐑤𐑟 
                pass  # 𐑦𐑙𐑯𐑹 𐑩𐑯𐑨𐑤𐑦𐑕𐑦𐑕 𐑓𐑹 𐑮𐑪𐑓𐑹𐑥𐑩𐑯𐑕 𐑹𐑿𐑯
        
        # 𐑤𐑷𐑯𐑗 𐑞 ℌ𐑧𐑒𐑕 𐑝𐑿 𐑨
        app = InteractiveHexViewerApp(hex_viewer)
        app.run()
        
    except ImportError:
        # 𐑯 𐑤 𐑟 ℌ 𐑯 𐑤 𐑒 𐑞 𐑯 𐑩 𐑓 𐑞 𐑒 ℌ𐑤
        hex_viewer = HexViewer()
        
        # 𐑯𐑿: 𐑩𐑰𐑕 𐑤𐑱𐑟𐑦 𐑤𐑴𐑛𐑦𐑙 𐑦𐑯 𐑓𐑨𐑤𐑚𐑨𐑒 𐑗𐑱𐑕 𐑩𐑴
        hex_viewer.load_from_file(file_path)
        
        app = InteractiveHexViewerApp(hex_viewer)
        app.run()