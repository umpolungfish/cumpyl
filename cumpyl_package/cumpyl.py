import lief
import capstone
import binascii
import codecs
from typing import Dict, List

class BinaryRewriter:
    def __init__(self, input_file: str):
        """Initialize the binary rewriter with target file"""
        self.input_file = input_file
        self.binary = None  # Holds parsed binary
        self.modifications = []  # Track all modifications
        self.analysis_results = {}  # Store analysis data

    def load_binary(self) -> bool:
        """Load and parse the input binary file"""
        try:
            self.binary = lief.parse(self.input_file)
            print(f"[+] Successfully loaded {self.input_file}")
            return True
        except Exception as e:
            print(f"[-] Failed to load binary: {e}")
            return False

    def analyze_binary(self) -> Dict:
        """Perform static analysis on the binary"""
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
        """Disassemble a specific section"""
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
        """Queue a modification to be applied"""
        self.modifications.append({
            'type': patch_type,
            'data': kwargs,
            'applied': False
        })

    def apply_patches(self) -> bool:
        """Apply all queued modifications"""
        for mod in self.modifications:
            try:
                if mod['type'] == 'code_patch':
                    # Apply code patch using Keystone
                    # addr = mod['data']['address']
                    # new_bytes = mod['data']['new_bytes']
                    # In real implementation, this would modify the binary in memory
                    mod['applied'] = True
                elif mod['type'] == 'data_patch':
                    # Modify data section
                    # section_name = mod['data']['section']
                    # offset = mod['data']['offset']
                    # value = mod['data']['value']
                    # In real implementation, this would modify the binary in memory
                    mod['applied'] = True
                elif mod['type'] == 'function_hook':
                    # Hook a function
                    # func_name = mod['data']['function']
                    # hook_code = mod['data']['hook_code']
                    # In real implementation, this would hook the function
                    mod['applied'] = True
            except Exception as e:
                print(f"[-] Failed to apply patch: {e}")
                return False
        return True

    def validate_binary(self) -> bool:
        """Validate the modified binary"""
        # Perform basic validation
        try:
            # Check for valid architecture (works for PE, ELF, Mach-O)
            if hasattr(self.binary, 'header') and hasattr(self.binary.header, 'machine'):
                # For PE files, check if it's a valid machine type
                if hasattr(lief, 'PE') and isinstance(self.binary, lief.PE.Binary):
                    # Use the correct LIEF PE machine type constants
                    try:
                        valid_machines = [lief.PE.MACHINE_TYPES.AMD64, lief.PE.MACHINE_TYPES.I386]
                        if self.binary.header.machine not in valid_machines:
                            print("[-] Invalid PE architecture")
                            return False
                    except AttributeError:
                        # If we can't validate, just continue
                        pass

            # Check for valid entry point
            try:
                entry_point = getattr(self.binary, 'entrypoint', getattr(self.binary, 'entrypoint_address', None))
                if entry_point is not None and entry_point == 0:
                    print("[-] Invalid entry point")
                    return False
            except AttributeError:
                # Entry point validation not available for this binary type
                pass

            return True
        except Exception as e:
            print(f"[-] Validation failed: {e}")
            return False

    def save_binary(self, output_file: str) -> bool:
        """Save the modified binary"""
        try:
            self.binary.write(output_file)
            print(f"[+] Successfully saved to {output_file}")
            return True
        except Exception as e:
            print(f"[-] Failed to save binary: {e}")
            return False

    def encode_bytes(self, data: bytes, encoding: str) -> str:
        """Encode bytes to a specified format"""
        if encoding == "hex":
            return binascii.hexlify(data).decode()
        elif encoding == "octal":
            return "".join(f"\\{oct(b)[2:].zfill(3)}" for b in data)
        elif encoding == "null":
            # Replace with null bytes
            return "\\x00" * len(data)
        elif encoding == "base64":
            return codecs.encode(data, "base64").decode().strip()
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")

    def decode_bytes(self, encoded_data: str, encoding: str) -> bytes:
        """Decode data from a specified format back to bytes"""
        if encoding == "hex":
            # Remove any spaces or prefixes
            encoded_data = encoded_data.replace(" ", "").replace("0x", "")
            return binascii.unhexlify(encoded_data)
        elif encoding == "octal":
            # Parse octal string like \\123\\456
            octal_values = encoded_data.split("\\\\")[1:]  # Split by \\ and remove first empty element
            return bytes([int(oct_val, 8) for oct_val in octal_values])
        elif encoding == "null":
            # This would just be null bytes of the same length
            # Since we don't know the original length, we'll need to specify it
            raise ValueError("Cannot decode null encoding without knowing the original length")
        elif encoding == "base64":
            return codecs.decode(encoded_data.encode(), "base64")
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")

    def get_section_data(self, section_name: str) -> bytes:
        """Extract raw bytes from a section"""
        try:
            section = next((s for s in self.binary.sections if s.name == section_name), None)
            if not section:
                raise ValueError(f"Section '{section_name}' not found")
            return bytes(section.content)  # Use content instead of data for mutable bytes
        except Exception as e:
            print(f"[-] Failed to get section data: {e}")
            return b""

    def modify_section_data(self, section_name: str, offset: int, new_data: bytes) -> bool:
        """Modify data in a section at a specific offset"""
        try:
            section = next((s for s in self.binary.sections if s.name == section_name), None)
            if not section:
                raise ValueError(f"Section '{section_name}' not found")

            # Get the current content
            content = list(section.content)

            # Ensure we have enough space, expand if necessary
            if offset + len(new_data) > len(content):
                # Expand content to accommodate new data
                content.extend([0] * (offset + len(new_data) - len(content)))
                print(f"[*] Expanded section to accommodate {len(new_data)} bytes")

            # Apply the modification
            for i, byte in enumerate(new_data):
                content[offset + i] = byte

            # Update the section content
            section.content = content
            return True
        except Exception as e:
            print(f"[-] Failed to modify section data: {e}")
            return False

    def analyze_sections(self) -> None:
        """Analyze and display detailed section information"""
        print(f"\n[*] Section Analysis for {self.input_file}")
        print("=" * 60)

        for section in self.binary.sections:
            try:
                content = bytes(section.content)
                content_preview = content[:32]  # First 32 bytes

                # Try to determine section type
                section_type = "Unknown"
                if section.name in ['.text', '.code']:
                    section_type = "Executable Code"
                elif section.name in ['.data', '.bss']:
                    section_type = "Data"
                elif section.name in ['.rdata', '.rodata']:
                    section_type = "Read-only Data"
                elif section.name in ['.idata']:
                    section_type = "Import Data"
                elif section.name in ['.reloc']:
                    section_type = "Relocation Data"
                elif section.name in ['.pdata']:
                    section_type = "Exception Data"
                elif section.name in ['.xdata']:
                    section_type = "Exception Unwind Data"
                elif section.name.startswith('/'):
                    section_type = "Resource/Debug Data"

                print(f"Section: {section.name}")
                print(f"  Type: {section_type}")
                print(f"  Size: {len(content)} bytes")
                print(f"  Virtual Address: 0x{section.virtual_address:x}")
                if hasattr(section, 'characteristics'):
                    print(f"  Characteristics: 0x{section.characteristics:x}")

                # Show content preview
                if content:
                    hex_preview = ' '.join(f'{b:02x}' for b in content_preview)
                    print(f"  Content Preview: {hex_preview}")

                    # Try to show printable characters
                    printable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in content_preview)
                    print(f"  ASCII Preview: {printable}")
                else:
                    print("  Content: Empty")

                print()

            except Exception as e:
                print(f"  Error analyzing section {section.name}: {e}")
                print()


class RewriterPlugin:
    def __init__(self):
        self.name = "base_plugin"

    def analyze(self, rewriter: BinaryRewriter):
        """Plugin analysis phase"""
        # Example: Detect potential vulnerabilities
        # Check if binary has functions attribute before using it
        if hasattr(rewriter.binary, 'functions'):
            for func in rewriter.binary.functions:
                if "strcpy" in func.name or "sprintf" in func.name:
                    rewriter.analysis_results['vulnerabilities'].append({
                        'function': func.name,
                        'type': 'buffer_overflow',
                        'address': func.address
                    })
        else:
            # Fallback for binaries that don't have functions attribute
            print("[-] Binary format does not support function analysis")

    def transform(self, rewriter: BinaryRewriter):
        """Plugin transformation phase"""
        # Example: Add a NOP sled to a vulnerable function
        for vuln in rewriter.analysis_results['vulnerabilities']:
            rewriter.add_modification(
                patch_type='code_patch',
                address=vuln['address'],
                new_bytes=b'\x90' * 16  # NOP sled
            )


class EncodingPlugin(RewriterPlugin):
    def __init__(self):
        self.name = "encoding_plugin"
        self.encoded_data = {}

    def analyze(self, rewriter: BinaryRewriter):
        """Analyze and prepare for encoding operations"""
        # Nothing to do in analyze phase for this plugin
        pass

    def transform(self, rewriter: BinaryRewriter):
        """Apply encoding transformations"""
        # This will be called externally with specific parameters
        pass

    def encode_section_portion(self, rewriter: BinaryRewriter, section_name: str, offset: int, length: int, encoding: str) -> str:
        """Encode a portion of a section and store it"""
        try:
            # Get the section data
            section_data = rewriter.get_section_data(section_name)

            # 𐑸𐑑𐑴-𐑨𐑛𐑡𐑳𐑕𐑑 𐑤𐑧𐑙𐑔 𐑦𐑓 𐑑 𐑚𐑦𐑜
            original_length = length
            if offset + length > len(section_data):
                length = len(section_data) - offset
                print(f"  [!] Adjusted encode length from {original_length} to {length} bytes for section {section_name}")

            data_portion = section_data[offset:offset+length]

            # Encode the data
            encoded = rewriter.encode_bytes(data_portion, encoding)

            # Store for later use
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
        """Decode data and apply it back to the binary"""
        try:
            # Decode the data
            if encoding == "null":
                # Special case for null encoding - we need the original length
                section_data = rewriter.get_section_data(section_name)
                if offset > len(section_data):
                    raise ValueError("Offset exceeds section size")
                decoded_data = b"\x00" * len(self.encoded_data.get(f"{section_name}_{offset}_{len(section_data)-offset}_null", {}).get("original_data", b""))
            else:
                decoded_data = rewriter.decode_bytes(encoded_data, encoding)

            # Apply the modification
            return rewriter.modify_section_data(section_name, offset, decoded_data)
        except Exception as e:
            print(f"[-] Failed to decode and apply: {e}")
            return False

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Binary Rewriting Tool")
    parser.add_argument("input", help="Input binary file")
    parser.add_argument("-o", "--output", help="Output file")

    # Add analysis arguments
    parser.add_argument("--analyze-sections", action="store_true", help="Analyze and display section information")

    # Add encoding/decoding arguments
    parser.add_argument("--encode-section", action="append", help="Section name(s) to encode. Use comma-separated list for same encoding (e.g., '.text,.data'), or multiple flags for different encodings")
    parser.add_argument("--encode-offset", type=int, action="append", help="Offset within section to start encoding (default: 0)")
    parser.add_argument("--encode-length", type=int, action="append", help="Number of bytes to encode (default: entire section from offset)")
    parser.add_argument("--encoding-length", type=int, action="append", help="Alias for --encode-length")  # 𐑣𐑨𐑯𐑛𐑤 𐑤𐑮𐑑 𐑧𐑮𐑼
    parser.add_argument("--encoding", action="append", choices=["hex", "octal", "null", "base64"], help="Encoding format")
    parser.add_argument("--print-encoded", action="store_true", help="Print encoded data")

    args = parser.parse_args()

    # Initialize rewriter
    rewriter = BinaryRewriter(args.input)

    if not rewriter.load_binary():
        return

    # Handle section analysis if requested
    if args.analyze_sections:
        rewriter.analyze_sections()
        return

    # Handle encoding if requested
    if args.encode_section and args.encoding:
        encoding_plugin = EncodingPlugin()

        # Ensure we have matching numbers of parameters
        num_operations = len(args.encode_section)
        encodings = args.encoding if len(args.encoding) == num_operations else [args.encoding[0]] * num_operations
        offsets = args.encode_offset if args.encode_offset and len(args.encode_offset) == num_operations else [args.encode_offset[0] if args.encode_offset else 0] * num_operations
        # 𐑚𐑨𐑯𐑛𐑤 𐑚𐑴𐑔 --encode-length 𐑯 --encoding-length
        encode_lengths = args.encode_length or args.encoding_length
        lengths = encode_lengths if encode_lengths and len(encode_lengths) == num_operations else [encode_lengths[0] if encode_lengths else None] * num_operations

        # Process each encoding operation
        for i, section_spec in enumerate(args.encode_section):
            encoding_type = encodings[i]
            offset = offsets[i]
            length = lengths[i]

            # Handle comma-separated section names
            section_names = [name.strip() for name in section_spec.split(',')]

            print(f"[*] Processing encoding operation {i+1}: {section_spec} with {encoding_type}")

            for section_name in section_names:
                print(f"  [*] Processing section: {section_name}")

                # 𐑸𐑑𐑴-𐑛𐑧𐑑𐑧𐑯 𐑣𐑨𐑯𐑛𐑤𐑯 𐑓 𐑤𐑧𐑙𐑔 𐑑 𐑓 𐑕𐑧𐑒𐑖𐑯 𐑿 𐑦𐑓 𐑑 𐑦𐑟 𐑑 𐑚𐑦𐑜
                section_data = rewriter.get_section_data(section_name)
                if not length or length > len(section_data) - offset:
                    length = len(section_data) - offset
                    print(f"  [!] Adjusted length to {length} bytes for section size")

                # Encode the section portion
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

                # Apply the encoded string as bytes to the section
                # Convert encoded string to bytes and apply to section
                encoded_bytes = encoded_data.encode('utf-8')
                success = rewriter.modify_section_data(
                    section_name,
                    offset,
                    encoded_bytes
                )

                if success:
                    print(f"  [+] Successfully encoded section {section_name}")
                else:
                    print(f"  [-] Failed to apply encoded data to section {section_name}")

            print()  # Add spacing between operations

    # Plugin-based analysis (only if we have a valid binary)
    if rewriter.binary is not None:
        plugin = RewriterPlugin()
        plugin.analyze(rewriter)

        # Example: Disassemble .text section
        # text_section = rewriter.disassemble_section(".text")

        # Example modification: Add a patch
        rewriter.add_modification(
            patch_type="code_patch",
            address=0x1234,
            new_bytes=b"\x90\x90\x90"  # NOP sled example
        )
    else:
        print("[-] Skipping analysis and modifications due to binary load failure")
        return

    # Apply patches
    print("[*] Applying modifications...")
    if not rewriter.apply_patches():
        print("[-] Failed to apply all patches")
        return

    # Validate
    if not rewriter.validate_binary():
        print("[-] Binary validation failed")
        return

    # Save
    output_file = args.output or f"modified_{args.input}"
    if not rewriter.save_binary(output_file):
        return

    print("[+] Binary rewriting complete!")


if __name__ == "__main__":
    main()
