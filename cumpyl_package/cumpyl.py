import lief
import capstone
import binascii
import codecs
import os
from typing import Dict, List, Any, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from tqdm import tqdm
import time
try:
    from .config import ConfigManager, get_config
    from .plugin_manager import PluginManager
    from .batch_processor import BatchProcessor
    from .reporting import ReportGenerator
except ImportError:
    # Fallback import for direct script execution
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from config import ConfigManager, get_config
    from plugin_manager import PluginManager
    from batch_processor import BatchProcessor
    from reporting import ReportGenerator

class BinaryRewriter:
    def __init__(self, input_file: str, config: ConfigManager = None):
        """𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟 𐑞 𐑚𐑲𐑯𐑩𐑮𐑦 𐑮𐑰𐑮𐑲𐑑𐑼 𐑢𐑦𐑞 𐑑𐑸𐑜𐑧𐑑 𐑓𐑲𐑤"""
        self.input_file = input_file
        self.config = config or get_config()
        self.binary = None  # 𐑣𐑴𐑤𐑛𐑟 𐑐𐑸𐑕𐑑 𐑚𐑲𐑯𐑩𐑮𐑦
        self.modifications = []  # 𐑑𐑮𐑨𐑒 𐑷𐑤 𐑥𐑪𐑛𐑦𐑓𐑦𐑒𐑱𐑖𐑩𐑯𐑟
        self.analysis_results = {}  # 𐑕𐑑𐑹 𐑩𐑯𐑨𐑤𐑦𐑕𐑦𐑕 𐑛𐑱𐑑𐑩
        
        # 𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟 𐑐𐑤𐑳𐑜𐑦𐑯 𐑥𐑨𐑯𐑦𐑡𐑼
        self.plugin_manager = PluginManager(self.config)
        
        # 𐑝𐑨𐑤𐑦𐑛𐑱𐑑 𐑓𐑲𐑤 𐑕𐑲𐑟 𐑩𐑜𐑱𐑯𐑕𐑑 𐑒𐑪𐑯𐑓𐑦𐑜 𐑤𐑦𐑥𐑦𐑑
        if os.path.exists(input_file):
            file_size_mb = os.path.getsize(input_file) / (1024 * 1024)
            if file_size_mb > self.config.framework.max_file_size_mb:
                raise ValueError(f"File size ({file_size_mb:.1f}MB) exceeds maximum allowed size ({self.config.framework.max_file_size_mb}MB)")

    def load_binary(self) -> bool:
        """𐑤𐑴𐑛 𐑯 𐑐𐑸𐑕 𐑞 𐑦𐑯𐑐𐑫𐑑 𐑚𐑲𐑯𐑩𐑮𐑦 𐑓𐑲𐑤"""
        try:
            # 𐑛𐑦𐑟𐑱𐑚𐑩𐑤 LIEF 𐑝𐑻𐑚𐑴𐑕 𐑤𐑪𐑜𐑦𐑙 𐑑 𐑮𐑦𐑛𐑿𐑕 𐑯𐑱𐑟
            lief.logging.disable()
            self.binary = lief.parse(self.input_file)
            if self.binary is None:
                print(f"[-] Failed to parse {self.input_file}")
                return False
            print(f"[+] Successfully loaded {self.input_file}")
            return True
        except Exception as e:
            print(f"[-] Failed to load binary: {e}")
            return False

    def analyze_binary(self) -> Dict:
        """𐑐𐑼𐑓𐑹𐑥 𐑕𐑑𐑨𐑑𐑦𐑒 𐑩𐑯𐑨𐑤𐑦𐑕𐑦𐑕 𐑪𐑯 𐑞 𐑚𐑲𐑯𐑩𐑮𐑦"""
        try:
            entry_point = getattr(self.binary, 'entrypoint', getattr(self.binary, 'entrypoint_address', 0))
        except AttributeError:
            entry_point = 0

        self.analysis_results = {
            'architecture': getattr(self.binary.header, 'machine', 'unknown'),
            'endianness': 'little' if getattr(self.binary.header, 'is_little_endian', True) else 'big',
            'entry_point': entry_point,
            'sections': [section.name for section in self.binary.sections],
            'functions': [func.name for func in self.binary.get_functions()] if hasattr(self.binary, 'get_functions') else [],
            'vulnerabilities': []
        }
        return self.analysis_results

    def disassemble_section(self, section_name: str) -> List[str]:
        """𐑛𐑦𐑕𐑩𐑕𐑧𐑥𐑚𐑤 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑕𐑧𐑒𐑖𐑩𐑯"""
        try:
            section = next((s for s in self.binary.sections if s.name == section_name), None)
            if not section:
                raise ValueError(f"Section '{section_name}' not found")

            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            instructions = []
            for i in md.disasm(bytes(section.content), section.virtual_address):
                instructions.append(f"{i.mnemonic} {i.op_str}")
            return instructions
        except Exception as e:
            print(f"[-] Disassembly failed: {e}")
            return []

    def add_modification(self, patch_type: str, **kwargs):
        """𐑒𐑿 𐑩 𐑥𐑪𐑛𐑦𐑓𐑦𐑒𐑱𐑖𐑩𐑯 𐑑 𐑚𐑰 𐑩𐑐𐑤𐑲𐑛"""
        self.modifications.append({
            'type': patch_type,
            'data': kwargs,
            'applied': False
        })

    def apply_patches(self) -> bool:
        """𐑩𐑐𐑤𐑲 𐑷𐑤 𐑒𐑿𐑛 𐑥𐑪𐑛𐑦𐑓𐑦𐑒𐑱𐑖𐑩𐑯𐑟"""
        for mod in self.modifications:
            try:
                if mod['type'] == 'code_patch':
                    # 𐑩𐑐𐑤𐑲 𐑒𐑴𐑛 𐑐𐑨𐑗 𐑿𐑟𐑦𐑙 𐑒𐑰𐑕𐑑𐑴𐑯
                    # 𐑨𐑛𐑮 = mod['data']['address']
                    # 𐑯𐑿_𐑚𐑲𐑑𐑕 = mod['data']['new_bytes']
                    # 𐑦𐑯 𐑮𐑦𐑩𐑤 𐑦𐑥𐑐𐑤𐑦𐑥𐑧𐑯𐑑𐑱𐑖𐑩𐑯, 𐑞𐑦𐑕 𐑢𐑫𐑛 𐑥𐑪𐑛𐑦𐑓𐑲 𐑞 𐑚𐑲𐑯𐑩𐑮𐑦 𐑦𐑯 𐑥𐑧𐑥𐑼𐑦
                    mod['applied'] = True
                elif mod['type'] == 'data_patch':
                    # 𐑥𐑪𐑛𐑦𐑓𐑲 𐑛𐑱𐑑𐑩 𐑕𐑧𐑒𐑖𐑩𐑯
                    # 𐑕𐑧𐑉𐑖𐑯_𐑯𐑱𐑥 = mod['data']['section']
                    # 𐑫𐑓𐑕𐑧𐑑 = mod['data']['offset']
                    # 𐑝𐑨𐑤𐑿 = mod['data']['value']
                    # 𐑦𐑯 𐑮𐑦𐑩𐑤 𐑦𐑥𐑐𐑤𐑦𐑥𐑧𐑯𐑑𐑱𐑖𐑩𐑯, 𐑞𐑦𐑕 𐑢𐑫𐑛 𐑥𐑪𐑛𐑦𐑓𐑲 𐑞 𐑚𐑲𐑯𐑩𐑮𐑦 𐑦𐑯 𐑥𐑧𐑥𐑼𐑦
                    mod['applied'] = True
                elif mod['type'] == 'function_hook':
                    # 𐑣𐑫𐑒 𐑩 𐑓𐑳𐑙𐑒𐑖𐑩𐑯
                    # 𐑓𐑳𐑙𐑉_𐑯𐑱𐑥 = mod['data']['function']
                    # 𐑣𐑫𐑙_𐑉𐑴𐑛 = mod['data']['hook_code']
                    # 𐑦𐑯 𐑮𐑦𐑩𐑤 𐑦𐑥𐑐𐑤𐑦𐑥𐑧𐑯𐑑𐑱𐑖𐑩𐑯, 𐑞𐑦𐑕 𐑢𐑫𐑛 𐑣𐑫𐑒 𐑞 𐑓𐑳𐑙𐑒𐑖𐑩𐑯
                    mod['applied'] = True
            except Exception as e:
                print(f"[-] Failed to apply patch: {e}")
                return False
        return True

    def validate_binary(self) -> bool:
        """𐑝𐑨𐑤𐑦𐑛𐑱𐑑 𐑞 𐑥𐑪𐑛𐑦𐑓𐑲𐑛 𐑚𐑲𐑯𐑩𐑮𐑦"""
        # 𐑐𐑼𐑓𐑹𐑥 𐑚𐑱𐑕𐑦𐑒 𐑝𐑨𐑤𐑦𐑛𐑱𐑖𐑩𐑯
        try:
            # 𐑗𐑧𐑒 𐑓𐑹 𐑝𐑨𐑤𐑦𐑛 𐑸𐑒𐑦𐑑𐑧𐑒𐑗𐑼 (𐑢𐑻𐑒𐑕 𐑓𐑹 PE, ELF, Mach-O)
            if hasattr(self.binary, 'header') and hasattr(self.binary.header, 'machine'):
                # 𐑓𐑹 PE 𐑓𐑲𐑤𐑟, 𐑗𐑧𐑒 𐑦𐑓 𐑦𐑑𐑟 𐑩 𐑝𐑨𐑤𐑦𐑛 𐑥𐑩𐑖𐑰𐑯 𐑑𐑲𐑐
                if hasattr(lief, 'PE') and isinstance(self.binary, lief.PE.Binary):
                    # 𐑿𐑟 𐑞 𐑒𐑻𐑧𐑒𐑑 LIEF PE 𐑥𐑩𐑖𐑰𐑯 𐑑𐑲𐑐 𐑒𐑪𐑯𐑕𐑑𐑩𐑯𐑑𐑕
                    try:
                        valid_machines = [lief.PE.MACHINE_TYPES.AMD64, lief.PE.MACHINE_TYPES.I386]
                        if self.binary.header.machine not in valid_machines:
                            print("[-] Invalid PE architecture")
                            return False
                    except AttributeError:
                        # 𐑦𐑓 𐑢𐑰 𐑒𐑭𐑯𐑑 𐑝𐑨𐑤𐑦𐑛𐑱𐑑, 𐑡𐑳𐑕𐑑 𐑒𐑩𐑯𐑑𐑦𐑯𐑿
                        pass

            # 𐑗𐑧𐑒 𐑓𐑹 𐑝𐑨𐑤𐑦𐑛 𐑧𐑯𐑑𐑮𐑦 𐑐𐑶𐑯𐑑
            try:
                entry_point = getattr(self.binary, 'entrypoint', getattr(self.binary, 'entrypoint_address', None))
                if entry_point is not None and entry_point == 0:
                    print("[-] Invalid entry point")
                    return False
            except AttributeError:
                # 𐑧𐑯𐑑𐑮𐑦 𐑐𐑶𐑯𐑑 𐑝𐑨𐑤𐑦𐑛𐑱𐑖𐑩𐑯 𐑯𐑪𐑑 𐑩𐑝𐑱𐑤𐑩𐑚𐑤 𐑓𐑹 𐑞𐑦𐑕 𐑚𐑲𐑯𐑩𐑮𐑦 𐑑𐑲𐑐
                pass

            return True
        except Exception as e:
            print(f"[-] Validation failed: {e}")
            return False

    def save_binary(self, output_file: str) -> bool:
        """𐑕𐑱𐑝 𐑞 𐑥𐑪𐑛𐑦𐑓𐑲𐑛 𐑚𐑲𐑯𐑩𐑮𐑦"""
        try:
            self.binary.write(output_file)
            print(f"[+] Successfully saved to {output_file}")
            return True
        except Exception as e:
            print(f"[-] Failed to save binary: {e}")
            return False

    def encode_bytes(self, data: bytes, encoding: str) -> str:
        """𐑦𐑯𐑒𐑴𐑛 𐑚𐑲𐑑𐑕 𐑑 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑲𐑛 𐑓𐑹𐑥𐑨𐑑"""
        if encoding == "hex":
            return binascii.hexlify(data).decode()
        elif encoding == "octal":
            return "".join(f"\\{oct(b)[2:].zfill(3)}" for b in data)
        elif encoding == "null":
            # 𐑮𐑦𐑐𐑤𐑱𐑕 𐑢𐑦𐑞 𐑯𐑳𐑤 𐑚𐑲𐑑𐑕
            return "\\x00" * len(data)
        elif encoding == "base64":
            return codecs.encode(data, "base64").decode().strip()
        elif encoding == "compressed_base64":
            # 𐑒𐑩𐑥𐑐𐑮𐑧𐑕 𐑞 𐑛𐑱𐑑𐑩 𐑓𐑻𐑕𐑑, 𐑞𐑧𐑯 𐑦𐑯𐑒𐑴𐑛 𐑢𐑦𐑞 base64
            import zlib
            compressed = zlib.compress(data)
            return codecs.encode(compressed, "base64").decode().strip()
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")

    def decode_bytes(self, encoded_data: str, encoding: str) -> bytes:
        """𐑛𐑰𐑒𐑴𐑛 𐑛𐑱𐑑𐑩 𐑓𐑮𐑪𐑥 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑲𐑛 𐑓𐑹𐑥𐑨𐑑 𐑚𐑨𐑒 𐑑 𐑚𐑲𐑑𐑕"""
        if encoding == "hex":
            # 𐑮𐑦𐑵 𐑧𐑯𐑦 𐑕𐑐𐑱𐑕𐑌𐑚 𐑩 𐑐𐑮𐑦𐑜𐑧𐑕𐑌𐑚
            encoded_data = encoded_data.replace(" ", "").replace("0x", "")
            return binascii.unhexlify(encoded_data)
        elif encoding == "octal":
            # 𐑐𐑳𐑉𐑕 𐑫𐑉𐑑𐑩𐑤 𐑕𐑑𐑮𐑦𐑙 𐑤𐑲𐑉 \123\456\789
            import re
            octal_values = re.findall(r'\\(\d{3})', encoded_data)
            return bytes([int(oct_val, 8) for oct_val in octal_values])
        elif encoding == "null":
            # 𐑞𐑦𐑕 𐑢𐑫𐑛 𐑡𐑳𐑕𐑑 𐑚𐑦 𐑯𐑳𐑤 𐑚𐑲𐑑𐑕 𐑬 𐑞 𐑕𐑱𐑥 𐑤𐑧𐑙𐑔
            # 𐑕𐑦𐑯𐑕 𐑢𐑦 𐑛𐑴𐑯𐑑 𐑯𐑴 𐑞 𐑩𐑮𐑦𐑡𐑯𐑩𐑤 𐑤𐑧𐑙𐑔, 𐑢𐑦𐑤 𐑯𐑦𐑛 𐑑𐑫 𐑕𐑐𐑧𐑕𐑦𐑓𐑲 𐑦𐑑
            raise ValueError("Cannot decode null encoding without knowing the original length")
        elif encoding == "base64":
            return codecs.decode(encoded_data.encode(), "base64")
        elif encoding == "compressed_base64":
            # 𐑛𐑦𐑉𐑴𐑛 base64 𐑓𐑻𐑕𐑑, 𐑞𐑧𐑯 𐑛𐑦𐑉𐑩𐑭𐑐𐑮𐑧𐑕
            import zlib
            decoded = codecs.decode(encoded_data.encode(), "base64")
            return zlib.decompress(decoded)
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")

    def load_plugins(self) -> int:
        """𐑤𐑴𐑛 𐑷𐑤 𐑩𐑝𐑱𐑤𐑩𐑚𐑩𐑤 𐑐𐑤𐑳𐑜𐑦𐑯𐑟"""
        return self.plugin_manager.load_all_plugins()
    
    def run_plugin_analysis(self) -> Dict[str, Any]:
        """𐑮𐑳𐑯 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑓𐑱𐑟 𐑓𐑹 𐑷𐑤 𐑤𐑴𐑛𐑦𐑛 𐑐𐑤𐑳𐑜𐑦𐑯𐑟"""
        if self.binary is None:
            print("[-] Binary not loaded. Cannot run plugin analysis.")
            return {}
        
        print("[*] Running plugin analysis phase...")
        return self.plugin_manager.execute_analysis_phase(self)
    
    def run_plugin_transformations(self, analysis_results: Dict[str, Any]) -> bool:
        """𐑮𐑳𐑯 𐑑𐑮𐑨𐑯𐑕𐑓𐑼𐑥𐑱𐑖𐑩𐑯 𐑓𐑱𐑟 𐑓𐑹 𐑷𐑤 𐑤𐑴𐑛𐑦𐑛 𐑐𐑤𐑳𐑜𐑦𐑯𐑟"""
        if self.binary is None:
            print("[-] Binary not loaded. Cannot run plugin transformations.")
            return False
        
        print("[*] Running plugin transformation phase...")
        return self.plugin_manager.execute_transformation_phase(self, analysis_results)
    
    def list_loaded_plugins(self) -> None:
        """𐑤𐑦𐑕𐑑 𐑷𐑤 𐑤𐑴𐑛𐑦𐑛 𐑐𐑤𐑳𐑜𐑦𐑯𐑟 𐑢𐑦𐑞 𐑞𐑺 𐑦𐑯𐑓𐑼𐑥𐑱𐑖𐑩𐑯"""
        plugins = self.plugin_manager.list_plugins()
        
        if not plugins:
            print("[*] No plugins loaded")
            return
        
        console = Console()
        console.print(Panel("Loaded Plugins", style="bold cyan"))
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Description", style="white")
        table.add_column("Enabled", style="yellow")
        
        for plugin_info in plugins:
            enabled_status = "✓" if plugin_info['enabled'] else "✗"
            table.add_row(
                plugin_info['name'],
                plugin_info['version'],
                plugin_info['description'][:50] + "..." if len(plugin_info['description']) > 50 else plugin_info['description'],
                enabled_status
            )
        
        console.print(table)

    def get_section_data(self, section_name: str) -> bytes:
        """𐑦𐑒𐑕𐑑𐑮𐑨𐑒𐑑 𐑮𐑷 𐑚𐑲𐑑𐑕 𐑓𐑮𐑪𐑥 𐑩 𐑕𐑧𐑒𐑖𐑩𐑯"""
        try:
            section = next((s for s in self.binary.sections if s.name == section_name), None)
            if not section:
                raise ValueError(f"Section '{section_name}' not found")
            return bytes(section.content)  # Use content instead of data for mutable bytes
        except Exception as e:
            print(f"[-] Failed to get section data: {e}")
            return b""

    def modify_section_data(self, section_name: str, offset: int, new_data: bytes) -> bool:
        """𐑥𐑪𐑛𐑦𐑓𐑲 𐑛𐑱𐑑𐑩 𐑦𐑯 𐑩 𐑕𐑧𐑒𐑖𐑩𐑯 𐑨𐑑 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑪𐑓𐑕𐑧𐑑"""
        try:
            section = next((s for s in self.binary.sections if s.name == section_name), None)
            if not section:
                raise ValueError(f"Section '{section_name}' not found")

            # 𐑖𐑧𐑑 𐑞 𐑒𐑻𐑧𐑯𐑑 𐑒𐑩𐑯𐑑𐑧𐑯𐑑
            content = list(section.content)
            
            # 𐑗𐑧𐑒 𐑦𐑓 𐑞𐑦𐑕 𐑦𐑟 𐑩𐑯 𐑦𐑜𐑟𐑧𐑒𐑿𐑑𐑩𐑚𐑩𐑤 𐑕𐑧𐑒𐑖𐑩𐑯
            executable_sections = ['.text', '.code']
            if section_name in executable_sections:
                print(f"[!] WARNING: Modifying executable section '{section_name}' will likely break the binary!")
                print(f"[!] Consider encoding non-executable sections like .rdata, .data, or .rodata instead.")

            # 𐑗𐑧𐑒 𐑦𐑓 𐑢𐑦𐑮 𐑑𐑮𐑲𐑦𐑙 𐑑 𐑮𐑲𐑑 𐑚𐑦𐑘𐑪𐑯𐑛 𐑞 𐑕𐑧𐑒𐑖𐑩𐑯𐑟 𐑨𐑒𐑗𐑫𐑩𐑤 𐑕𐑲𐑟
            section_size = len(content)
            if offset + len(new_data) > section_size:
                print(f"[!] WARNING: Attempting to write {len(new_data)} bytes at offset {offset}")
                print(f"[!] Section '{section_name}' is only {section_size} bytes, need {offset + len(new_data)} bytes")
                print(f"[!] This will expand the section and may break the binary!")
                
                # 𐑭𐑕𐑒 𐑓𐑹 𐑿𐑟𐑼 𐑒𐑩𐑯𐑓𐑻𐑥𐑱𐑖𐑩𐑯 𐑹 𐑷𐑑𐑴𐑥𐑨𐑑𐑦𐑒𐑩𐑤𐑦 𐑮𐑦𐑡𐑧𐑒𐑑 𐑓𐑹 𐑦𐑜𐑟𐑧𐑒𐑿𐑑𐑩𐑚𐑩𐑤 𐑕𐑧𐑒𐑖𐑩𐑯𐑟
                if section_name in executable_sections:
                    print(f"[-] Refusing to expand executable section '{section_name}' to prevent binary corruption")
                    return False

            # 𐑦𐑯𐑖𐑫𐑼 𐑢𐑰 𐑣𐑨𐑝 𐑦𐑯𐑳𐑓 𐑕𐑐𐑱𐑕, 𐑦𐑜𐑟𐑐𐑨𐑯𐑛 𐑦𐑓 𐑯𐑧𐑒𐑧𐑕𐑧𐑮𐑦
            if offset + len(new_data) > len(content):
                # 𐑦𐑜𐑟𐑐𐑨𐑯𐑛 𐑒𐑩𐑯𐑑𐑧𐑯𐑑 𐑑 𐑩𐑒𐑪𐑥𐑩𐑛𐑱𐑑 𐑯𐑿 𐑛𐑱𐑑𐑩
                content.extend([0] * (offset + len(new_data) - len(content)))
                print(f"[*] Expanded section to accommodate {len(new_data)} bytes")

            # 𐑩𐑐𐑤𐑲 𐑞 𐑥𐑪𐑛𐑦𐑓𐑦𐑒𐑱𐑖𐑩𐑯
            for i, byte in enumerate(new_data):
                # 𐑥𐑱𐑒 𐑖𐑫𐑼 𐑢𐑰 𐑛𐑴𐑯𐑑 𐑜𐑴 𐑚𐑦𐑘𐑪𐑯𐑛 𐑞 𐑕𐑧𐑒𐑖𐑩𐑯 𐑚𐑬𐑯𐑛𐑼𐑦𐑟
                if offset + i < len(content):
                    content[offset + i] = byte
                else:
                    # 𐑞𐑦𐑕 𐑖𐑫𐑛𐑩𐑯𐑑 𐑣𐑨𐑐𐑩𐑯 𐑦𐑓 𐑢𐑰 𐑦𐑜𐑟𐑑𐑧𐑯𐑛𐑦𐑛 𐑒𐑹𐑩𐑒𐑤𐑦, 𐑚𐑳𐑑 𐑡𐑳𐑕𐑑 𐑦𐑯 𐑒𐑱𐑕
                    print(f"[!] Warning: Attempted to write beyond section boundaries")
                    break

            # 𐑳𐑐𐑛𐑱𐑑 𐑞 𐑕𐑧𐑒𐑖𐑩𐑯 𐑒𐑩𐑯𐑑𐑧𐑯𐑑
            section.content = content
            return True
        except Exception as e:
            print(f"[-] Failed to modify section data: {e}")
            return False

    def analyze_sections(self) -> None:
        """𐑩𐑯𐑨𐑤𐑲𐑟 𐑯 𐑛𐑦𐑕𐑐𐑤𐑱 𐑛𐑰𐑑𐑱𐑤𐑛 𐑕𐑧𐑒𐑖𐑩𐑯 𐑦𐑯𐑓𐑼𐑥𐑱𐑖𐑩𐑯"""
        print(f"\n[*] Section Analysis for {self.input_file}")
        print("=" * 60)
        print("[*] Suggested sections for encoding:")
        print("    - Safe: .rdata, .rodata, .data (non-executable data sections)")
        print("    - Use with caution: .text, .code (executable sections - will break program)")
        print("    - Avoid: .idata, .reloc (critical for program loading)")
        print()

        for section in self.binary.sections:
            try:
                content = bytes(section.content)
                content_preview = content[:32]  # First 32 bytes

                # 𐑜𐑮𐑲 𐑜 𐑛𐑦𐑜𐑻𐑥𐑲𐑯 𐑕𐑧𐑒𐑖𐑩𐑯 𐑜𐑲𐑐
                section_type = "Unknown"
                safe_for_encoding = "No"
                if section.name in ['.text', '.code']:
                    section_type = "Executable Code"
                    safe_for_encoding = "No - Will break program"
                elif section.name in ['.data', '.bss']:
                    section_type = "Data"
                    safe_for_encoding = "Yes"
                elif section.name in ['.rdata', '.rodata']:
                    section_type = "Read-only Data"
                    safe_for_encoding = "Yes"
                elif section.name in ['.idata']:
                    section_type = "Import Data"
                    safe_for_encoding = "No - Critical for loading"
                elif section.name in ['.reloc']:
                    section_type = "Relocation Data"
                    safe_for_encoding = "No - Critical for loading"
                elif section.name in ['.pdata']:
                    section_type = "Exception Data"
                    safe_for_encoding = "Use with caution"
                elif section.name in ['.xdata']:
                    section_type = "Exception Unwind Data"
                    safe_for_encoding = "Use with caution"
                elif section.name.startswith('/'):
                    section_type = "Resource/Debug Data"
                    safe_for_encoding = "Yes"

                print(f"Section: {section.name}")
                print(f"  Type: {section_type}")
                print(f"  Safe for encoding: {safe_for_encoding}")
                print(f"  Size: {len(content)} bytes")
                print(f"  Virtual Address: 0x{section.virtual_address:x}")
                if hasattr(section, 'characteristics'):
                    print(f"  Characteristics: 0x{section.characteristics:x}")

                # 𐑖𐑴 𐑒𐑩𐑯𐑜𐑧𐑯𐑜 𐑐𐑮𐑦𐑝𐑿
                if content:
                    hex_preview = ' '.join(f'{b:02x}' for b in content_preview)
                    print(f"  Content Preview: {hex_preview}")

                    # 𐑜𐑮𐑲 𐑜 𐑖𐑴 𐑐𐑮𐑦𐑯𐑜𐑩𐑚𐑤 𐑒𐑸𐑦𐑒𐑜𐑼𐑟
                    printable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in content_preview)
                    print(f"  ASCII Preview: {printable}")
                else:
                    print("  Content: Empty")

                print()

            except Exception as e:
                print(f"  Error analyzing section {section.name}: {e}")
                print()

    def suggest_obfuscation(self, return_suggestions: bool = False) -> Optional[List[Dict[str, Any]]]:
        """𐑨𐑯𐑩𐑤𐑲𐑟 𐑞 𐑚𐑲𐑯𐑻𐑦 𐑯 𐑕𐑳𐑜𐑧𐑕𐑑 𐑪𐑐𐑑𐑦𐑥𐑩𐑤 𐑕𐑧𐑒𐑖𐑩𐑯𐑟 𐑓 𐑩𐑚𐑓𐑳𐑕𐑒𐑱𐑖𐑩𐑯 𐑢 𐑛𐑦𐑓𐑻𐑩𐑯𐑑 𐑑𐑽𐑟"""
        console = Console()
        suggestions_data = []  # 𐑒𐑩𐑤𐑧𐑒𐑑 𐑕𐑩𐑡𐑧𐑕𐑗𐑩𐑯 𐑛𐑱𐑑𐑩 𐑦𐑓 𐑮𐑦𐑒𐑢𐑧𐑕𐑜𐑦𐑛
        
        # 𐑣𐑧𐑛𐑼 𐑢𐑦𐑞 𐑮𐑦𐑗 𐑐𐑨𐑯𐑩𐑤
        header_text = Text(f"Obfuscation Suggestions for {self.input_file}", style="bold cyan")
        console.print(Panel(header_text, border_style="cyan", padding=(1, 2)))
        
        # 𐑐𐑮𐑩𐑜𐑮𐑧𐑕 𐑕𐑐𐑦𐑯𐑼 𐑓𐑹 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Analyzing binary sections...", total=None)
            
            # 𐑒𐑩𐑤𐑧𐑒𐑜 𐑕𐑧𐑒𐑖𐑩𐑯 𐑦𐑯𐑓𐑼𐑥𐑱𐑖𐑩𐑯
            sections_info = []
            for section in self.binary.sections:
                try:
                    content = bytes(section.content)
                    # 𐑛𐑦𐑑𐑻𐑥𐑲𐑯 𐑕𐑧𐑒𐑖𐑩𐑯 𐑑𐑲𐑐 𐑯 𐑕𐑱𐑓𐑑𐑦
                    section_type = "Unknown"
                    safe_for_encoding = False
                    encoding_tier = 0  # 0 = avoid, 1 = basic, 2 = intermediate, 3 = advanced
                    
                    if section.name in ['.text', '.code']:
                        section_type = "Executable Code"
                        safe_for_encoding = False
                        encoding_tier = 0  # Avoid
                    elif section.name in ['.data', '.bss']:
                        section_type = "Data"
                        safe_for_encoding = True
                        encoding_tier = 2  # Intermediate
                    elif section.name in ['.rdata', '.rodata']:
                        section_type = "Read-only Data"
                        safe_for_encoding = True
                        encoding_tier = 3  # Advanced
                    elif section.name in ['.idata']:
                        section_type = "Import Data"
                        safe_for_encoding = False
                        encoding_tier = 0  # Avoid
                    elif section.name in ['.reloc']:
                        section_type = "Relocation Data"
                        safe_for_encoding = False
                        encoding_tier = 0  # Avoid
                    elif section.name in ['.pdata']:
                        section_type = "Exception Data"
                        safe_for_encoding = True
                        encoding_tier = 1  # Basic
                    elif section.name in ['.xdata']:
                        section_type = "Exception Unwind Data"
                        safe_for_encoding = True
                        encoding_tier = 1  # Basic
                    elif section.name.startswith('/'):
                        section_type = "Resource/Debug Data"
                        safe_for_encoding = True
                        encoding_tier = 2  # Intermediate
                    
                    section_data = {
                        'name': section.name,
                        'type': section_type,
                        'size': len(content),
                        'safe': safe_for_encoding,
                        'tier': encoding_tier,
                        'virtual_address': section.virtual_address,
                        'characteristics': getattr(section, 'characteristics', 0)
                    }
                    sections_info.append(section_data)
                    
                    # 𐑨𐑛 𐑑 𐑕𐑩𐑡𐑧𐑕𐑗𐑩𐑯𐑟 𐑛𐑱𐑑𐑩 𐑦𐑓 𐑮𐑦𐑒𐑢𐑧𐑕𐑜𐑦𐑛
                    if return_suggestions:
                        tier_colors = {3: "green", 2: "yellow", 1: "blue", 0: "red"}
                        tier_reasons = {
                            3: "Advanced tier - Large read-only data section, safe for heavy obfuscation",
                            2: "Intermediate tier - Data section, good for moderate obfuscation", 
                            1: "Basic tier - Small section, suitable for light obfuscation",
                            0: "Avoid - Critical for program execution"
                        }
                        
                        suggestions_data.append({
                            'section': section.name,
                            'tier': tier_colors.get(encoding_tier, "red"),
                            'reason': tier_reasons.get(encoding_tier, "Unknown tier"),
                            'offset': section.virtual_address,
                            'size': len(content),
                            'section_type': section_type,
                            'safe_for_encoding': safe_for_encoding
                        })
                    time.sleep(0.1)  # Small delay for spinner effect
                except Exception as e:
                    console.print(f"[red]Error analyzing section {section.name}: {e}[/red]")
            
            progress.update(task, completed=True)
        
        # 𐑕𐑹𐑜 𐑕𐑧𐑒𐑖𐑩𐑯𐑟 𐑚𐑲 𐑜𐑦𐑼 (𐑛𐑦𐑕𐑧𐑯𐑛𐑦𐑙) 𐑯 𐑕𐑲𐑟 (𐑛𐑦𐑕𐑧𐑯𐑛𐑦𐑙) 𐑓𐑹 𐑐𐑮𐑦𐑪𐑮𐑦𐑜𐑲𐑟𐑱𐑖𐑩𐑯
        sections_info.sort(key=lambda x: (x['tier'], x['size']), reverse=True)
        
        # 𐑛𐑦𐑕𐑐𐑤𐑱 𐑕𐑩𐑡𐑧𐑕𐑗𐑩𐑯𐑟 𐑚𐑲 𐑜𐑦𐑼 𐑢𐑦𐑞 𐑮𐑦𐑗 𐑓𐑹𐑥𐑨𐑜𐑦𐑙
        tier_configs = {
            3: {
                "name": "Advanced Tier (Large, High-Impact Sections)",
                "color": "green",
                "encodings": ["base64", "compressed_base64", "hex"],
                "suggestion": "Best for heavy obfuscation. Large capacity for complex encoding."
            },
            2: {
                "name": "Intermediate Tier (Medium-Size Data Sections)",
                "color": "yellow",
                "encodings": ["base64", "compressed_base64"],
                "suggestion": "Good for moderate obfuscation. Balanced size and safety."
            },
            1: {
                "name": "Basic Tier (Small, Low-Impact Sections)",
                "color": "blue",
                "encodings": ["hex", "octal"],
                "suggestion": "Suitable for light obfuscation. Small sections, minimal impact."
            },
            0: {
                "name": "Avoid (Critical Sections)",
                "color": "red",
                "encodings": [],
                "suggestion": "Critical for program execution. Avoid obfuscation."
            }
        }
        
        for tier in range(3, -1, -1):  # From 3 (Advanced) to 0 (Avoid)
            tier_sections = [s for s in sections_info if s['tier'] == tier]
            if tier_sections:
                tier_config = tier_configs[tier]
                
                # 𐑒𐑮𐑦𐑱𐑜 𐑜𐑦𐑼 𐑣𐑧𐑛𐑼 𐑐𐑨𐑯𐑩𐑤
                tier_title = Text(tier_config["name"], style=f"bold {tier_config['color']}")
                console.print(Panel(tier_title, border_style=tier_config["color"]))
                
                # 𐑒𐑮𐑦𐑱𐑜 𐑜𐑱𐑚𐑤 𐑓𐑹 𐑕𐑧𐑒𐑖𐑩𐑯𐑟 𐑦𐑯 𐑞𐑦𐑕 𐑜𐑦𐑼
                table = Table(show_header=True, header_style="bold")
                table.add_column("Section", style="cyan")
                table.add_column("Type", style="magenta")
                table.add_column("Size", style="green")
                table.add_column("Address", style="yellow")
                
                # 𐑕𐑑𐑹 𐑒𐑩𐑥𐑭𐑯𐑛𐑟 𐑓 𐑛𐑦𐑕𐑐𐑤𐑱 𐑬𐑑𐑕𐑲𐑛 𐑞 𐑜𐑱𐑚𐑤
                commands_for_tier = []
                
                for section in tier_sections:
                    # 𐑓𐑹𐑥𐑨𐑜 𐑕𐑲𐑟
                    size_mb = section['size'] / (1024 * 1024)
                    if size_mb >= 1:
                        size_str = f"{size_mb:.2f} MB"
                    else:
                        size_kb = section['size'] / 1024
                        if size_kb >= 1:
                            size_str = f"{size_kb:.2f} KB"
                        else:
                            size_str = f"{section['size']} bytes"
                    
                    # 𐑨𐑛 𐑞 𐑕𐑧𐑒𐑖𐑩𐑯 𐑦𐑯𐑓 𐑑 𐑞 𐑜𐑱𐑚𐑤
                    table.add_row(
                        section['name'],
                        section['type'],
                        size_str,
                        f"0x{section['virtual_address']:x}"
                    )
                    
                    # 𐑡𐑧𐑯𐑻𐑱𐑑 𐑒𐑩𐑥𐑭𐑯𐑛 𐑓 𐑞𐑦𐑕 𐑕𐑧𐑒𐑖𐑩𐑯 (𐑦𐑓 𐑦𐑑'𐑕 𐑯 𐑧𐑯𐑒𐑴𐑛𐑩𐑚𐑤 𐑜𐑦𐑼)
                    if tier > 0 and tier_config["encodings"]:
                        best_encoding = tier_config["encodings"][0]
                        output_filename = f"obfuscated_{os.path.basename(self.input_file)}"
                        command = f"cumpyl {self.input_file} --encode-section {section['name']} --encoding {best_encoding} -o {output_filename}"
                        commands_for_tier.append(command)
                
                console.print(table)
                
                # 𐑛𐑦𐑕𐑐𐑤𐑱 𐑒𐑩𐑥𐑭𐑯𐑛𐑟 𐑬𐑑𐑕𐑲𐑛 𐑞 𐑜𐑱𐑚𐑤 𐑓 𐑦𐑟𐑦 𐑒𐑪𐑐𐑦𐑦𐑙
                if commands_for_tier:
                    console.print()  # Add spacing
                    for command in commands_for_tier:
                        console.print(f"[white]{command}[/white]")
                    console.print()  # Add spacing
                
                # 𐑨𐑛 𐑕𐑩𐑡𐑧𐑕𐑗𐑩𐑯 𐑯 𐑦𐑯𐑒𐑴𐑛𐑦𐑙 𐑪𐑐𐑖𐑩𐑯𐑟
                suggestion_panel = Panel(
                    f"[bold]Suggestion:[/bold] {tier_config['suggestion']}\n" +
                    (f"[bold]Encoding Options:[/bold] {', '.join(tier_config['encodings'])}" if tier_config['encodings'] else "[bold red]DO NOT OBFUSCATE[/bold red]"),
                    title="Recommendations",
                    border_style=tier_config["color"],
                    padding=(0, 1)
                )
                console.print(suggestion_panel)
                console.print()  # Add spacing
        
        # 𐑴𐑝𐑼𐑷𐑤 𐑮𐑧𐑒𐑩𐑥𐑧𐑯𐑛𐑱𐑖𐑩𐑯𐑟 𐑐𐑨𐑯𐑩𐑤
        console.print(Panel(Text("Overall Recommendations", style="bold white"), border_style="white"))
        
        safe_sections = [s for s in sections_info if s['tier'] >= 2]
        if safe_sections:
            largest_safe = max(safe_sections, key=lambda x: x['size'])
            
            # 𐑒𐑮𐑦𐑱𐑜 𐑮𐑧𐑒𐑩𐑥𐑧𐑯𐑛𐑱𐑖𐑩𐑯 𐑜𐑱𐑚𐑤
            rec_table = Table(show_header=False, box=None)
            rec_table.add_column("Label", style="bold cyan")
            rec_table.add_column("Value", style="white")
            
            rec_table.add_row("Best section:", f"{largest_safe['name']} ({largest_safe['type']})")
            rec_table.add_row("Size:", f"{largest_safe['size']} bytes")
            output_filename = f"obfuscated_{os.path.basename(self.input_file)}"
            rec_table.add_row("Command:", f"cumpyl {self.input_file} --encode-section {largest_safe['name']} --encoding compressed_base64 -o {output_filename}")
            
            console.print(rec_table)
        else:
            console.print("[yellow]No large safe sections found for significant obfuscation.[/yellow]")
        
        # 𐑢𐑹𐑯𐑦𐑙𐑟 𐑓𐑹 𐑦𐑜𐑟𐑧𐑒𐑿𐑜𐑩𐑚𐑤 𐑕𐑧𐑒𐑖𐑩𐑯𐑟
        exec_sections = [s for s in sections_info if s['name'] in ['.text', '.code']]
        if exec_sections:
            warning_text = f"Obfuscating executable sections ({', '.join([s['name'] for s in exec_sections])}) will break the program. Use with extreme caution."
            console.print(Panel(
                Text(warning_text, style="bold red"),
                title="[bold red]WARNING[/bold red]",
                border_style="red"
            ))
        
        # 𐑮𐑦𐑑𐑻𐑯 𐑕𐑩𐑡𐑧𐑕𐑗𐑩𐑯 𐑛𐑱𐑑𐑩 𐑦𐑓 𐑮𐑦𐑒𐑢𐑧𐑕𐑜𐑦𐑛
        if return_suggestions:
            return suggestions_data


class RewriterPlugin:
    def __init__(self):
        self.name = "base_plugin"

    def analyze(self, rewriter: BinaryRewriter):
        """𐑐𐑤𐑳𐑜𐑦𐑯 𐑩𐑯𐑨𐑤𐑦𐑕𐑦𐑕 𐑓𐑱𐑟"""
        # 𐑦𐑜𐑟𐑭𐑥𐑐𐑤: 𐑛𐑦𐑑𐑧𐑒𐑑 𐑐𐑩𐑑𐑧𐑯𐑖𐑩𐑤 𐑝𐑳𐑤𐑯𐑼𐑩𐑚𐑦𐑤𐑦𐑑𐑦𐑟
        # 𐑗𐑧𐑒 𐑦𐑓 𐑚𐑲𐑯𐑩𐑮𐑦 𐑣𐑨𐑟 𐑓𐑳𐑙𐑒𐑖𐑩𐑯𐑟 𐑨𐑑𐑮𐑦𐑚𐑿𐑑 𐑚𐑦𐑓𐑹 𐑿𐑟𐑦𐑙 𐑦𐑑
        if hasattr(rewriter.binary, 'functions'):
            for func in rewriter.binary.functions:
                if "strcpy" in func.name or "sprintf" in func.name:
                    rewriter.analysis_results['vulnerabilities'].append({
                        'function': func.name,
                        'type': 'buffer_overflow',
                        'address': func.address
                    })
        else:
            # 𐑓𐑷𐑤𐑚𐑨𐑒 𐑓 𐑚𐑲𐑯𐑼𐑦𐑟 𐑞𐑨𐑑 𐑛𐑴𐑯𐑑 𐑣𐑨𐑝 𐑓𐑳𐑙𐑒𐑖𐑩𐑯𐑟 𐑨𐑑𐑮𐑦𐑚𐑿𐑑
            print("[-] Binary format does not support function analysis")

    def transform(self, rewriter: BinaryRewriter):
        """𐑐𐑤𐑳𐑜𐑦𐑯 𐑑𐑮𐑨𐑯𐑕𐑓𐑼𐑥𐑱𐑖𐑩𐑯 𐑓𐑱𐑟"""
        # 𐑦𐑜𐑟𐑭𐑥𐑐𐑤: 𐑨𐑛 𐑩 NOP 𐑕𐑤𐑧𐑛 𐑑 𐑩 𐑝𐑳𐑤𐑯𐑼𐑩𐑚𐑤 𐑓𐑳𐑙𐑒𐑖𐑩𐑯
        for vuln in rewriter.analysis_results['vulnerabilities']:
            rewriter.add_modification(
                patch_type='code_patch',
                address=vuln['address'],
                new_bytes=b'\x90' * 16  # NOP 𐑕𐑤𐑧𐑛
            )


class EncodingPlugin(RewriterPlugin):
    def __init__(self):
        self.name = "encoding_plugin"
        self.encoded_data = {}

    def analyze(self, rewriter: BinaryRewriter):
        """𐑩𐑯𐑨𐑤𐑲𐑟 𐑯 𐑐𐑮𐑦𐑐𐑺 𐑓 𐑦𐑯𐑒𐑴𐑛𐑦𐑙 𐑪𐑐𐑼𐑱𐑖𐑩𐑯𐑟"""
        # 𐑯𐑳𐑔𐑦𐑙 𐑑 𐑛 𐑦𐑯 𐑩𐑯𐑨𐑤𐑲𐑟 𐑓𐑱𐑟 𐑓 𐑞𐑦𐑕 𐑐𐑤𐑳𐑜𐑦𐑯
        pass

    def transform(self, rewriter: BinaryRewriter):
        """𐑩𐑐𐑤𐑲 𐑦𐑯𐑒𐑴𐑛𐑦𐑙 𐑑𐑮𐑨𐑯𐑕𐑓𐑼𐑥𐑱𐑖𐑩𐑯𐑟"""
        # 𐑞𐑦𐑕 𐑢𐑦𐑤 𐑚 𐑒𐑷𐑤𐑛 𐑦𐑒𐑕𐑑𐑻𐑯𐑩𐑤𐑦 𐑢 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑐𐑨𐑮𐑨𐑥𐑧𐑑𐑼𐑟
        pass

    def encode_section_portion(self, rewriter: BinaryRewriter, section_name: str, offset: int, length: int, encoding: str) -> str:
        """𐑦𐑯𐑒𐑴𐑛 𐑩 𐑐𐑹𐑖𐑩𐑯 𐑝 𐑩 𐑕𐑧𐑒𐑖𐑩𐑯 𐑯 𐑕𐑑𐑹 𐑦𐑑"""
        try:
            # 𐑜𐑧𐑜 𐑞 𐑕𐑧𐑒𐑖𐑩𐑯 𐑛𐑱𐑜𐑩
            section_data = rewriter.get_section_data(section_name)

            # 𐑷𐑑𐑴-𐑨𐑛𐑡𐑳𐑕𐑑 𐑤𐑧𐑙𐑔 𐑦𐑓 𐑑 𐑚𐑦𐑜
            original_length = length
            if offset + length > len(section_data):
                length = len(section_data) - offset
                print(f"  [!] Adjusted encode length from {original_length} to {length} bytes for section {section_name}")

            data_portion = section_data[offset:offset+length]

            # 𐑦𐑯𐑒𐑴𐑛 𐑞 𐑛𐑱𐑜𐑩
            encoded = rewriter.encode_bytes(data_portion, encoding)

            # 𐑕𐑜𐑹 𐑓𐑹 𐑤𐑱𐑜𐑼 𐑿𐑕
            key = f"{section_name}_{offset}_{length}_{encoding}"
            self.encoded_data[key] = {
                'original_data': data_portion,
                'encoded_data': encoded,
                'encoding': encoding
            }

            return encoded
        except Exception as e:
            print(f"[-] Failed to encode section portion: {e}")
            return ""

    def decode_and_apply(self, rewriter: BinaryRewriter, section_name: str, offset: int, encoded_data: str, encoding: str) -> bool:
        """𐑛𐑰𐑒𐑴𐑛 𐑛𐑱𐑑𐑩 𐑯 𐑩𐑐𐑤𐑲 𐑦𐑑 𐑚𐑨𐑒 𐑑 𐑞 𐑚𐑲𐑯𐑩𐑮𐑦"""
        try:
            # 𐑛𐑰𐑒𐑴𐑛 𐑞 𐑛𐑱𐑑𐑩
            if encoding == "null":
                # 𐑕𐑐𐑧𐑖𐑩𐑤 𐑒𐑱𐑕 𐑓 𐑯𐑳𐑤 𐑦𐑯𐑒𐑴𐑛𐑦𐑙 - 𐑢 𐑯𐑰𐑛 𐑞 𐑪𐑮𐑦𐑡𐑦𐑯𐑩𐑤 𐑤𐑧𐑙𐑔
                section_data = rewriter.get_section_data(section_name)
                if offset > len(section_data):
                    raise ValueError("Offset exceeds section size")
                decoded_data = b"\x00" * len(self.encoded_data.get(f"{section_name}_{offset}_{len(section_data)-offset}_null", {}).get("original_data", b""))
            else:
                decoded_data = rewriter.decode_bytes(encoded_data, encoding)

            # 𐑩𐑐𐑤𐑲 𐑞 𐑥𐑪𐑛𐑦𐑓𐑦𐑒𐑱𐑖𐑩𐑯
            return rewriter.modify_section_data(section_name, offset, decoded_data)
        except Exception as e:
            print(f"[-] Failed to decode and apply: {e}")
            return False

def handle_batch_processing(args, config):
    """𐑣𐑨𐑯𐑛𐑩𐑤 𐑚𐑨𐑗 𐑐𐑮𐑩𐑕𐑧𐑕𐑦𐑙 𐑪𐑐𐑼𐑱𐑖𐑩𐑯𐑟"""
    batch_processor = BatchProcessor(config)
    
    # 𐑨𐑛 𐑓𐑲𐑤𐑟 𐑚𐑱𐑕𐑛 𐑪𐑯 𐑩𐑮𐑜𐑿𐑥𐑩𐑯𐑑𐑟
    if args.batch_directory:
        extensions = args.batch_extensions.split(',') if args.batch_extensions else None
        added_files = batch_processor.add_directory(args.batch_directory, extensions, args.batch_recursive)
        print(f"[*] Added {added_files} files from directory: {args.batch_directory}")
    
    if args.batch_pattern:
        added_files = batch_processor.add_files(args.batch_pattern, args.batch_recursive)
        print(f"[*] Added {added_files} files from patterns: {args.batch_pattern}")
    
    # 𐑒𐑩𐑯𐑓𐑦𐑜 𐑪𐑐𐑼𐑱𐑖𐑩𐑯𐑟 𐑦𐑓 𐑕𐑐𐑧𐑕𐑦𐑓𐑲𐑛
    if args.batch_operation:
        for operation in args.batch_operation:
            if operation == "analyze_sections":
                batch_processor.configure_operation("analyze_sections")
            elif operation == "plugin_analysis":
                batch_processor.configure_operation("plugin_analysis")
            elif operation == "encode_section" and args.encode_section and args.encoding:
                # 𐑿𐑟 𐑞 𐑓𐑻𐑕𐑑 𐑦𐑯𐑒𐑴𐑛𐑦𐑙 𐑪𐑐𐑼𐑱𐑖𐑩𐑯 𐑓 𐑚𐑨𐑗 𐑐𐑮𐑩𐑕𐑧𐑕𐑦𐑙
                batch_processor.configure_operation("encode_section", 
                                                   section_name=args.encode_section[0],
                                                   encoding=args.encoding[0],
                                                   offset=args.encode_offset[0] if args.encode_offset else 0,
                                                   length=args.encode_length[0] if args.encode_length else None)
    
    # 𐑐𐑮𐑩𐑕𐑧𐑕 𐑷𐑤 𐑡𐑪𐑚𐑟
    print(f"[*] Starting batch processing of {len(batch_processor.jobs)} files...")
    batch_results = batch_processor.process_all()
    
    # 𐑛𐑦𐑕𐑐𐑤𐑱 𐑮𐑦𐑟𐑳𐑤𐑑𐑟
    batch_processor.print_summary(batch_results)
    
    # 𐑡𐑧𐑯𐑼𐑱𐑑 𐑮𐑦𐑐𐑹𐑑 𐑦𐑓 𐑮𐑦𐑒𐑢𐑧𐑕𐑜𐑦𐑛
    if args.generate_report or args.report_output:
        report_generator = ReportGenerator(config)
        report_data = report_generator.create_batch_report(batch_results)
        
        if args.report_output:
            report_generator.generate_report(report_data, args.report_format, args.report_output)
        else:
            # 𐑦𐑓 𐑯𐑴 𐑬𐑑𐑐𐑫𐑑 𐑓𐑲𐑤 𐑕𐑐𐑧𐑕𐑦𐑓𐑲𐑛, 𐑐𐑮𐑦𐑯𐑑 𐑞 𐑮𐑦𐑐𐑹𐑑
            report_content = report_generator.generate_report(report_data, args.report_format)
            print("\n" + "="*50)
            print("BATCH PROCESSING REPORT")
            print("="*50)
            print(report_content)


def main():
    import argparse
    try:
        from .config import init_config
    except ImportError:
        from config import init_config

    parser = argparse.ArgumentParser(description="Binary Rewriting Tool with YAML Configuration Support")
    parser.add_argument("input", nargs="?", help="Input binary file (optional when using batch mode)")
    parser.add_argument("-o", "--output", help="Output file")
    
    # 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯 𐑸𐑜𐑿𐑥𐑩𐑯𐑜𐑕
    parser.add_argument("--config", help="Path to configuration file (default: cumpyl.yaml)")
    parser.add_argument("--profile", help="Use predefined analysis profile (malware_analysis, forensics, research)")
    parser.add_argument("--validate-config", action="store_true", help="Validate configuration file and exit")
    parser.add_argument("--show-config", action="store_true", help="Display current configuration and exit")

    # 𐑨𐑛 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑸𐑜𐑿𐑥𐑩𐑯𐑜𐑕
    parser.add_argument("--analyze-sections", action="store_true", help="Analyze and display section information")
    parser.add_argument("--suggest-obfuscation", action="store_true", help="Suggest optimal sections for obfuscation with different tiers")
    
    # 𐑐𐑤𐑳𐑜𐑦𐑯 𐑸𐑜𐑿𐑥𐑩𐑯𐑜𐑕
    parser.add_argument("--list-plugins", action="store_true", help="List all loaded plugins and their information")
    parser.add_argument("--run-analysis", action="store_true", help="Run comprehensive analysis using all loaded plugins")
    parser.add_argument("--disable-plugins", action="store_true", help="Disable plugin system for this run")
    
    # 𐑚𐑨𐑗 𐑐𐑮𐑩𐑕𐑧𐑕𐑦𐑙 𐑸𐑜𐑿𐑥𐑩𐑯𐑜𐑕
    parser.add_argument("--batch", action="store_true", help="Enable batch processing mode")
    parser.add_argument("--batch-directory", help="Process all files in a directory")
    parser.add_argument("--batch-pattern", action="append", help="Glob pattern for batch processing (can be used multiple times)")
    parser.add_argument("--batch-extensions", help="Comma-separated list of file extensions for batch processing (e.g., '.exe,.dll,.so')")
    parser.add_argument("--batch-recursive", action="store_true", default=True, help="Recursively process subdirectories (default: True)")
    parser.add_argument("--batch-output-dir", help="Directory for batch output files (default: same as input)")
    parser.add_argument("--batch-operation", action="append", help="Operation to apply to all batch files (analyze_sections, plugin_analysis, encode_section)")
    parser.add_argument("--max-workers", type=int, help="Maximum number of worker threads for batch processing")
    
    # 𐑮𐑦𐑐𐑹𐑑𐑦𐑙 𐑯 𐑬𐑑𐑐𐑫𐑑 𐑸𐑜𐑿𐑥𐑩𐑯𐑜𐑕
    parser.add_argument("--report-format", choices=["json", "yaml", "xml", "html"], default="json", help="Output report format (default: json)")
    parser.add_argument("--report-output", help="Save report to specified file (auto-detects extension if not provided)")
    parser.add_argument("--generate-report", action="store_true", help="Generate structured analysis report")
    
    # 𐑣𐑧𐑒𐑕 𐑝𐑿𐑼 𐑸𐑜𐑿𐑥𐑩𐑯𐑜𐑕
    parser.add_argument("--hex-view", action="store_true", help="Generate interactive hex dump with analysis overlay")
    parser.add_argument("--hex-view-output", help="Output file for hex view (default: adds _hex.html to input filename)")
    parser.add_argument("--hex-view-bytes", type=int, default=2048, help="Maximum bytes to display in hex view (default: 2048)")
    parser.add_argument("--hex-view-offset", type=lambda x: int(x, 0), default=0, help="Starting offset for hex view (default: 0, supports hex like 0x1000)")
    parser.add_argument("--hex-view-section", help="Show hex view for specific section (e.g., .text, .data)")
    parser.add_argument("--hex-view-interactive", action="store_true", help="Interactively select sections/ranges after analysis")
    
    # 𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑥𐑧𐑯𐑿 𐑸𐑜𐑿𐑥𐑩𐑯𐑜
    parser.add_argument("--menu", action="store_true", help="Launch interactive menu system for guided framework usage")

    # 𐑨𐑛 𐑦𐑯𐑒𐑴𐑛𐑦𐑙/𐑛𐑦𐑒𐑴𐑛𐑦𐑙 𐑸𐑜𐑿𐑥𐑩𐑯𐑜𐑕
    parser.add_argument("--encode-section", action="append", help="Section name(s) to encode. Use comma-separated list for same encoding (e.g., '.text,.data'), or multiple flags for different encodings")
    parser.add_argument("--encode-offset", type=int, action="append", help="Offset within section to start encoding (default: 0)")
    parser.add_argument("--encode-length", type=int, action="append", help="Number of bytes to encode (default: entire section from offset)")
    parser.add_argument("--encoding-length", type=int, action="append", help="Alias for --encode-length")  # 𐑣𐑨𐑯𐑛𐑩𐑤 𐑤𐑧𐑜𐑩𐑕𐑦 𐑻𐑼
    parser.add_argument("--encoding", action="append", choices=["hex", "octal", "null", "base64", "compressed_base64"], help="Encoding format")
    parser.add_argument("--print-encoded", action="store_true", help="Print encoded data")

    args = parser.parse_args()
    
    # 𐑝𐑨𐑤𐑦𐑛𐑱𐑑 𐑸𐑜𐑿𐑥𐑩𐑯𐑑 𐑒𐑩𐑥𐑚𐑦𐑯𐑱𐑖𐑩𐑯
    if not args.input and not args.batch_directory and not args.menu:
        parser.error("Either input file, --batch-directory, or --menu must be provided")

    # 𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟 𐑒𐑪𐑯𐑓𐑦𐑜𐑘𐑼𐑱𐑖𐑩𐑯
    config = init_config(args.config)
    
    # 𐑣𐑨𐑯𐑛𐑩𐑤 𐑒𐑪𐑯𐑓𐑦𐑜 𐑝𐑨𐑤𐑦𐑛𐑱𐑖𐑩𐑯
    if args.validate_config:
        issues = config.validate_config()
        if issues:
            print("[!] Configuration validation failed:")
            for issue in issues:
                print(f"  - {issue}")
            return
        else:
            print("[+] Configuration validation passed")
            return
    
    # 𐑣𐑨𐑯𐑛𐑩𐑤 𐑒𐑪𐑯𐑓𐑦𐑜 𐑛𐑦𐑕𐑐𐑤𐑱
    if args.show_config:
        console = Console()
        console.print(Panel("Current Configuration", style="bold cyan"))
        
        # 𐑛𐑦𐑕𐑐𐑤𐑱 𐑒𐑰 𐑒𐑪𐑯𐑓𐑦𐑜 𐑕𐑧𐑒𐑖𐑩𐑯𐑟
        console.print(f"[cyan]Config File:[/cyan] {config.config_path}")
        console.print(f"[cyan]Framework Version:[/cyan] {config.framework.version}")
        console.print(f"[cyan]Debug Mode:[/cyan] {config.framework.debug_mode}")
        console.print(f"[cyan]Max File Size:[/cyan] {config.framework.max_file_size_mb}MB")
        console.print(f"[cyan]Plugins Enabled:[/cyan] {config.plugins.enabled}")
        console.print(f"[cyan]Plugin Directory:[/cyan] {config.plugins.plugin_directory}")
        return
    
    # 𐑣𐑨𐑯𐑛𐑩𐑤 𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑥𐑧𐑯𐑿 𐑦𐑓 𐑮𐑦𐑒𐑢𐑧𐑕𐑜𐑦𐑛
    if args.menu:
        try:
            from .menu_system import launch_menu
        except ImportError:
            from menu_system import launch_menu
        
        launch_menu(config, args.input)
        return

    # 𐑣𐑨𐑯𐑛𐑩𐑤 𐑚𐑨𐑗 𐑐𐑮𐑩𐑕𐑧𐑕𐑦𐑙 𐑦𐑓 𐑮𐑦𐑒𐑢𐑧𐑕𐑜𐑦𐑛
    if args.batch or args.batch_directory or args.batch_pattern:
        handle_batch_processing(args, config)
        return

    # 𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟 𐑮𐑦𐑮𐑲𐑜𐑼 𐑢𐑦𐑞 𐑒𐑪𐑯𐑓𐑦𐑜 (𐑴𐑯𐑤𐑦 𐑓𐑹 𐑕𐑦𐑙𐑜𐑩𐑤-𐑓𐑲𐑤 𐑥𐑴𐑛)
    rewriter = BinaryRewriter(args.input, config)
    
    # 𐑩𐑐𐑤𐑲 𐑐𐑮𐑴𐑓𐑲𐑤 𐑒𐑪𐑯𐑓𐑦𐑜 𐑦𐑓 𐑕𐑐𐑧𐑕𐑦𐑓𐑲𐑛
    if args.profile:
        profile_config = config.get_profile_config(args.profile)
        if not profile_config:
            print(f"[-] Profile '{args.profile}' not found in configuration")
            return
        print(f"[*] Using profile: {args.profile}")
        if config.framework.verbose_logging:
            print(f"    Profile plugins: {profile_config.get('plugins', [])}")
            print(f"    Safety checks: {profile_config.get('safety_checks', False)}")

    if not rewriter.load_binary():
        return

    # 𐑤𐑴𐑛 𐑐𐑤𐑳𐑜𐑦𐑯𐑟 𐑦𐑓 𐑯𐑪𐑑 𐑛𐑦𐑟𐑱𐑚𐑩𐑤𐑛
    if not args.disable_plugins:
        loaded_plugins = rewriter.load_plugins()
        if config.framework.verbose_logging:
            print(f"[*] Loaded {loaded_plugins} plugin(s)")
    
    # 𐑣𐑨𐑯𐑛𐑩𐑤 𐑐𐑤𐑳𐑜𐑦𐑯 𐑤𐑦𐑕𐑑𐑦𐑙
    if args.list_plugins:
        rewriter.list_loaded_plugins()
        return
    
    # 𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟 𐑝𐑨𐑮𐑦𐑩𐑚𐑩𐑤𐑟 𐑓𐑹 𐑨𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑩𐑯 𐑕𐑩𐑡𐑧𐑕𐑗𐑩𐑯 𐑛𐑱𐑑𐑩
    analysis_results = {}
    suggestions = []

    # 𐑮𐑳𐑯 𐑒𐑪𐑥𐑐𐑮𐑦𐑣𐑧𐑯𐑕𐑦𐑝 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑦𐑓 𐑮𐑦𐑒𐑢𐑧𐑕𐑜𐑦𐑛
    if args.run_analysis:
        analysis_results = rewriter.run_plugin_analysis()
        
        # 𐑛𐑦𐑕𐑐𐑤𐑱 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑮𐑦𐑟𐑳𐑤𐑑𐑕
        console = Console()
        console.print(Panel("Plugin Analysis Results", style="bold cyan"))
        
        for plugin_name, result in analysis_results.items():
            if 'error' in result:
                console.print(f"[red]❌ {plugin_name}: {result['error']}[/red]")
            else:
                console.print(f"[green]✓ {plugin_name}: Analysis completed[/green]")
                if config.framework.debug_mode:
                    console.print(f"  Result keys: {list(result.keys())}")

    # 𐑮𐑳𐑯 𐑪𐑚𐑓𐑩𐑕𐑒𐑱𐑖𐑩𐑯 𐑕𐑩𐑡𐑧𐑕𐑗𐑩𐑯𐑟 𐑦𐑓 𐑮𐑦𐑒𐑢𐑧𐑕𐑜𐑦𐑛
    if args.suggest_obfuscation:
        suggestions = rewriter.suggest_obfuscation(return_suggestions=True)

    # 𐑦𐑓 𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑣𐑧𐑒𐑕 𐑝𐑿𐑼 𐑦𐑟 𐑮𐑦𐑒𐑢𐑧𐑕𐑜𐑦𐑛, 𐑡𐑧𐑯𐑼𐑱𐑑 𐑦𐑑 𐑢𐑦𐑞 𐑦𐑯𐑑𐑧𐑜𐑮𐑱𐑑𐑦𐑛 𐑨𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑞𐑨𐑑 𐑣𐑨𐑟 𐑚𐑰𐑯 𐑮𐑳𐑯
    if args.hex_view:
        try:
            from .hex_viewer import HexViewer
        except ImportError:
            from hex_viewer import HexViewer
        
        # 𐑣𐑨𐑯𐑛𐑩𐑤 𐑦𐑯𐑑𐑼𐑨𐑒𐑑𐑦𐑝 𐑕𐑧𐑤𐑧𐑒𐑖𐑩𐑯
        if args.hex_view_interactive:
            console = Console()
            if rewriter.binary and rewriter.binary.sections:
                console.print(Panel("Available Sections for Hex View", style="bold cyan"))
                
                sections_table = Table(show_header=True, header_style="bold")
                sections_table.add_column("Index", style="cyan")
                sections_table.add_column("Section", style="magenta")
                sections_table.add_column("Size", style="green")
                sections_table.add_column("File Offset", style="yellow")
                sections_table.add_column("Virtual Address", style="blue")
                
                for i, section in enumerate(rewriter.binary.sections):
                    file_offset = getattr(section, 'offset', getattr(section, 'virtual_address', 0))
                    size_str = f"{section.size} bytes" if section.size < 1024 else f"{section.size/1024:.1f} KB"
                    sections_table.add_row(
                        str(i),
                        section.name,
                        size_str,
                        f"0x{file_offset:x}",
                        f"0x{section.virtual_address:x}"
                    )
                
                console.print(sections_table)
                console.print("\nOptions:")
                console.print("• Enter section index (0-{}) to view specific section".format(len(rewriter.binary.sections)-1))
                console.print("• Enter 'all' to view all sections")
                console.print("• Enter offset range like '0x1000-0x2000' or '4096-8192'")
                console.print("• Press Enter for default view (first 2048 bytes)")
                
                choice = input("\nSelect option: ").strip()
                
                if choice.isdigit() and 0 <= int(choice) < len(rewriter.binary.sections):
                    # 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑕𐑧𐑒𐑖𐑩𐑯 𐑕𐑧𐑤𐑧𐑒𐑑𐑦𐑛
                    selected_section = rewriter.binary.sections[int(choice)]
                    args.hex_view_section = selected_section.name
                    args.hex_view_offset = getattr(selected_section, 'offset', 0)
                    args.hex_view_bytes = min(selected_section.size, 8192)  # 𐑤𐑦𐑥𐑦𐑑 𐑑 8KB 𐑓 𐑤𐑸𐑡 𐑕𐑧𐑒𐑖𐑩𐑯𐑟
                elif choice.lower() == 'all':
                    args.hex_view_bytes = min(len(open(args.input, 'rb').read()), 16384)  # 𐑤𐑦𐑥𐑦𐑑 𐑑 16KB
                elif '-' in choice:
                    # 𐑮𐑱𐑯𐑡 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒𐑱𐑖𐑩𐑯
                    try:
                        start, end = choice.split('-')
                        start = int(start, 0)  # 𐑨𐑤𐑬 𐑣𐑧𐑒𐑕 𐑹 𐑛𐑧𐑕𐑦𐑥𐑩𐑤
                        end = int(end, 0)
                        args.hex_view_offset = start
                        args.hex_view_bytes = end - start
                    except ValueError:
                        console.print("[red]Invalid range format. Using default.[/red]")
            
        print("[*] Generating interactive hex view with integrated analysis...")
        
        # 𐑤𐑴𐑛 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩
        with open(args.input, 'rb') as f:
            f.seek(args.hex_view_offset)
            binary_data = f.read(args.hex_view_bytes)
        
        # 𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟 𐑣𐑧𐑒𐑕 𐑝𐑿𐑼
        hex_viewer = HexViewer(config, base_offset=args.hex_view_offset)
        hex_viewer.load_binary_data(binary_data)
        hex_viewer.bytes_per_row = 16
        
        # 𐑨𐑛 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑓𐑮𐑩𐑥 𐑚𐑲𐑯𐑩𐑮𐑦 𐑕𐑧𐑒𐑖𐑩𐑯𐑟
        if rewriter.binary and rewriter.binary.sections:
            hex_viewer.add_section_annotations(rewriter.binary.sections)
        
        # 𐑨𐑛 𐑨𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑦𐑓 𐑩𐑝𐑱𐑤𐑩𐑚𐑩𐑤
        if analysis_results:
            hex_viewer.add_analysis_annotations(analysis_results)
            
        # 𐑨𐑛 𐑪𐑚𐑓𐑩𐑕𐑒𐑱𐑖𐑩𐑯 𐑕𐑩𐑡𐑧𐑕𐑗𐑩𐑯 𐑨𐑯𐑴𐑑𐑱𐑖𐑩𐑯𐑟 𐑦𐑓 𐑩𐑝𐑱𐑤𐑩𐑚𐑩𐑤
        if suggestions:
            hex_viewer.add_suggestion_annotations(suggestions)
        
        # 𐑡𐑧𐑯𐑼𐑱𐑑 HTML 𐑮𐑦𐑐𐑹𐑑 𐑢𐑦𐑞 𐑦𐑯𐑑𐑧𐑜𐑮𐑱𐑑𐑦𐑛 𐑣𐑧𐑒𐑕 𐑝𐑿𐑼
        report_generator = ReportGenerator(config)
        hex_report_data = {
            'metadata': {
                'target_file': args.input,
                'framework_version': config.framework.version,
                'analysis_type': 'hex_view_with_analysis'
            },
            'binary_data': binary_data[:args.hex_view_bytes],
            'sections': [{'name': s.name, 'virtual_address': s.virtual_address, 'size': s.size, 'offset': s.offset} 
                        for s in rewriter.binary.sections] if rewriter.binary else [],
            'analysis_results': analysis_results,
            'obfuscation_suggestions': suggestions,
            'hex_viewer': hex_viewer
        }
        
        # 𐑛𐑦𐑑𐑻𐑥𐑲𐑯 𐑬𐑑𐑐𐑫𐑑 𐑓𐑲𐑤 𐑯𐑱𐑥
        if args.hex_view_output:
            hex_output_file = args.hex_view_output
        else:
            base_name = os.path.splitext(args.input)[0]
            hex_output_file = f"{base_name}_hex.html"
        
        # 𐑡𐑧𐑯𐑼𐑱𐑑 𐑩𐑯 𐑕𐑱𐑝 𐑞 𐑣𐑧𐑒𐑕 𐑝𐑿 𐑮𐑦𐑐𐑹𐑑
        report_generator.generate_report(hex_report_data, 'html', hex_output_file)
        print(f"[+] Interactive hex view with integrated analysis saved to: {hex_output_file}")
        return

    # Check if we need a report generator for any of the following operations
    need_report_generator = (
        (args.hex_view and args.run_analysis) or
        (args.run_analysis and (args.generate_report or args.report_output))
    )
    
    if need_report_generator:
        report_generator = ReportGenerator(config)

    # 𐑡𐑧𐑯𐑼𐑱𐑑 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑮𐑦𐑐𐑹𐑑 𐑦𐑓 𐑮𐑦𐑒𐑢𐑧𐑕𐑜𐑦𐑛 (𐑩𐑯 𐑯𐑪𐑑 𐑣𐑧𐑒𐑕 𐑝𐑿)
    if args.run_analysis and (args.generate_report or args.report_output):
        # 𐑒𐑮𐑦𐑱𐑑 𐑩 𐑒𐑩𐑥𐑐𐑮𐑦𐑣𐑧𐑯𐑕𐑦𐑝 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑮𐑦𐑐𐑹𐑑
        basic_analysis = rewriter.analyze_binary()
        report_data = report_generator.create_analysis_report(
            args.input, 
            basic_analysis, 
            analysis_results
        )
        
        if args.report_output:
            report_generator.generate_report(report_data, args.report_format, args.report_output)
        else:
            # 𐑦𐑓 𐑯𐑴 𐑬𐑑𐑐𐑫𐑑 𐑓𐑲𐑤 𐑕𐑐𐑧𐑕𐑦𐑓𐑲𐑛, 𐑐𐑮𐑦𐑯𐑑 𐑞 𐑮𐑦𐑐𐑹𐑑
            report_content = report_generator.generate_report(report_data, args.report_format)
            print("\n" + "="*50)
            print("ANALYSIS REPORT")
            print("="*50)
            print(report_content)

    # 𐑦𐑓 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑹 𐑕𐑩𐑡𐑧𐑕𐑗𐑩𐑯 𐑢𐑻 𐑮𐑳𐑯 𐑚𐑳𐑑 𐑯𐑪𐑑 𐑣𐑧𐑒𐑕 𐑝𐑿, 𐑮𐑦𐑑𐑻𐑯 𐑣𐑽
    if args.run_analysis or args.suggest_obfuscation:
        return

    # 𐑣𐑨𐑯𐑛𐑩𐑤 𐑕𐑧𐑒𐑖𐑩𐑯 𐑩𐑯𐑨𐑤𐑦𐑟𐑦𐑕 𐑦𐑓 𐑮𐑦𐑒𐑢𐑧𐑕𐑜𐑦𐑛
    if args.analyze_sections:
        rewriter.analyze_sections()
        return

    # 𐑣𐑨𐑯𐑛𐑤 𐑪𐑚𐑓𐑩𐑕𐑒𐑱𐑖𐑩𐑯 𐑕𐑩𐑡𐑧𐑕𐑗𐑩𐑯𐑟 𐑦𐑓 𐑮𐑦𐑒𐑢𐑧𐑕𐑜𐑦𐑛
    if args.suggest_obfuscation:
        rewriter.suggest_obfuscation()
        return

    # 𐑣𐑨𐑯𐑛𐑩𐑤 𐑚𐑨𐑗 𐑐𐑮𐑩𐑕𐑧𐑕𐑦𐑙 𐑦𐑓 𐑮𐑦𐑒𐑢𐑧𐑕𐑜𐑦𐑛
    if args.batch or args.batch_directory or args.batch_pattern:
        handle_batch_processing(args, config)
        return

    # 𐑣𐑨𐑯𐑛𐑤 𐑦𐑯𐑒𐑴𐑛𐑦𐑙 𐑦𐑓 𐑮𐑦𐑒𐑢𐑧𐑕𐑜𐑦𐑛
    if args.encode_section and args.encoding:
        encoding_plugin = EncodingPlugin()

        # 𐑦𐑯𐑖𐑫𐑼 𐑢𐑰 𐑣𐑨𐑝 𐑥𐑨𐑗𐑦𐑙 𐑯𐑳𐑥𐑚𐑼𐑟 𐑝 𐑐𐑨𐑮𐑨𐑥𐑦𐑜𐑼𐑟
        num_operations = len(args.encode_section)
        encodings = args.encoding if len(args.encoding) == num_operations else [args.encoding[0]] * num_operations
        offsets = args.encode_offset if args.encode_offset and len(args.encode_offset) == num_operations else [args.encode_offset[0] if args.encode_offset else 0] * num_operations
        # 𐑣𐑨𐑯𐑛𐑩𐑤 𐑚𐑴𐑔 --encode-length 𐑯 --encoding-length
        encode_lengths = args.encode_length or args.encoding_length
        lengths = encode_lengths if encode_lengths and len(encode_lengths) == num_operations else [encode_lengths[0] if encode_lengths else None] * num_operations

        # 𐑐𐑮𐑩𐑕𐑧𐑕 𐑰𐑗 𐑦𐑯𐑒𐑴𐑛𐑦𐑙 𐑪𐑐𐑼𐑱𐑖𐑩𐑯
        for i, section_spec in enumerate(args.encode_section):
            encoding_type = encodings[i]
            offset = offsets[i]
            length = lengths[i]

            # 𐑣𐑨𐑯𐑛𐑤 𐑒𐑪𐑥𐑩-𐑕𐑧𐑐𐑼𐑱𐑜𐑦𐑛 𐑕𐑧𐑒𐑖𐑩𐑯 𐑯𐑱𐑥𐑟
            section_names = [name.strip() for name in section_spec.split(',')]

            print(f"[*] Processing encoding operation {i+1}: {section_spec} with {encoding_type}")

            for section_name in section_names:
                print(f"  [*] Processing section: {section_name}")

                # 𐑷𐑑𐑴-𐑛𐑦𐑑𐑻𐑥𐑦𐑯 𐑣𐑨𐑯𐑛𐑩𐑤𐑦𐑙 𐑝 𐑤𐑧𐑙𐑔 𐑑 𐑝 𐑕𐑧𐑒𐑖𐑩𐑯 𐑕𐑲𐑟 𐑦𐑓 𐑦𐑑 𐑦𐑟 𐑑 𐑚𐑦𐑜
                section_data = rewriter.get_section_data(section_name)
                if not length or length > len(section_data) - offset:
                    length = len(section_data) - offset
                    print(f"  [!] Adjusted length to {length} bytes for section size")

                # 𐑦𐑯𐑒𐑴𐑛 𐑞 𐑕𐑧𐑒𐑖𐑩𐑯 𐑐𐑹𐑖𐑩𐑯
                encoded_data = encoding_plugin.encode_section_portion(
                    rewriter,
                    section_name,
                    offset,
                    length,
                    encoding_type
                )

                if not encoded_data:
                    print(f"  [-] Failed to encode section {section_name}")
                    continue

                if args.print_encoded:
                    print(f"  [+] Encoded data for {section_name} ({encoding_type}): {encoded_data}")

                # To preserve functionality, the encoded data must not expand the section,
                # which would corrupt the binary. We will truncate oversized data and pad undersized data.
                encoded_bytes = encoded_data.encode('utf-8')
                original_data_portion = rewriter.get_section_data(section_name)[offset:offset+length]

                if len(encoded_bytes) > len(original_data_portion):
                    print(f"[!] WARNING: Encoded data ({len(encoded_bytes)} bytes) is larger than original space ({len(original_data_portion)} bytes).")
                    print(f"[!] Truncating encoded data to fit. The binary structure will be preserved, but the encoded data is incomplete.")
                    encoded_bytes = encoded_bytes[:len(original_data_portion)]
                
                # Pad with null bytes if encoded data is smaller to ensure we overwrite the exact original portion.
                if len(encoded_bytes) < len(original_data_portion):
                    encoded_bytes += b'\x00' * (len(original_data_portion) - len(encoded_bytes))

                success = rewriter.modify_section_data(
                    section_name,
                    offset,
                    encoded_bytes
                )

                if success:
                    print(f"  [+] Successfully wrote encoded data to section {section_name}")
                else:
                    print(f"  [-] Failed to apply encoded data to section {section_name}")

            print()  # 𐑨𐑛 𐑕𐑐𐑱𐑕𐑦𐑙 𐑚𐑦𐑑𐑢𐑰𐑯 𐑪𐑐𐑼𐑱𐑖𐑩𐑯𐑟

    # 𐑐𐑤𐑳𐑜𐑦𐑯-𐑚𐑱𐑕𐑑 𐑩𐑯𐑨𐑤𐑦𐑕𐑦𐑕 (𐑴𐑯𐑤𐑦 𐑦𐑓 𐑢𐑰 𐑣𐑨𐑝 𐑩 𐑝𐑨𐑤𐑦𐑛 𐑚𐑲𐑯𐑩𐑮𐑦)
    if rewriter.binary is not None:
        plugin = RewriterPlugin()
        plugin.analyze(rewriter)

        # 𐑦𐑜𐑟𐑭𐑥𐑐𐑩𐑤: 𐑛𐑦𐑕𐑩𐑕𐑧𐑥𐑚𐑩𐑤 .text 𐑕𐑧𐑒𐑖𐑩𐑯
        # text_section = rewriter.disassemble_section(".text")

        # 𐑦𐑜𐑟𐑭𐑥𐑐𐑩𐑤 𐑥𐑪𐑛𐑦𐑓𐑦𐑒𐑱𐑖𐑩𐑯: 𐑨𐑛 𐑩 𐑐𐑨𐑗
        rewriter.add_modification(
            patch_type="code_patch",
            address=0x1234,
            new_bytes=b"\x90\x90\x90"  # NOP 𐑕𐑤𐑧𐑛 𐑦𐑜𐑟𐑭𐑥𐑐𐑩𐑤
        )
    else:
        print("[-] Skipping analysis and modifications due to binary load failure")
        return

    # 𐑩𐑐𐑤𐑲 𐑐𐑨𐑗𐑦𐑟
    print("[*] Applying modifications...")
    if not rewriter.apply_patches():
        print("[-] Failed to apply all patches")
        return

    # 𐑝𐑨𐑤𐑦𐑛𐑱𐑑
    if not rewriter.validate_binary():
        print("[-] Binary validation failed")
        return

    # Save
    output_file = args.output or f"modified_{os.path.basename(args.input)}"
    if not rewriter.save_binary(output_file):
        return

    print("[+] Binary rewriting complete!")


if __name__ == "__main__":
    main()
