import lief
import capstone
import keystone
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
        self.analysis_results = {
            'architecture': self.binary.header.machine,
            'endianness': 'little' if self.binary.header.is_little_endian else 'big',
            'entry_point': self.binary.entrypoint_address,
            'sections': [section.name for section in self.binary.sections],
            'functions': [func.name for func in self.binary.get_functions()],
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
            for i in md.disasm(section.data, section.virtual_address):
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
                    addr = mod['data']['address']
                    new_bytes = mod['data']['new_bytes']
                    # In real implementation, this would modify the binary in memory
                    mod['applied'] = True
                elif mod['type'] == 'data_patch':
                    # Modify data section
                    section_name = mod['data']['section']
                    offset = mod['data']['offset']
                    value = mod['data']['value']
                    # In real implementation, this would modify the binary in memory
                    mod['applied'] = True
                elif mod['type'] == 'function_hook':
                    # Hook a function
                    func_name = mod['data']['function']
                    hook_code = mod['data']['hook_code']
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
            # Check for valid architecture
            if self.binary.header.machine not in [lief.PE.FILE_MACHINE_TYPE.IMAGE_FILE_MACHINE_AMD64,
                                                  lief.PE.FILE_MACHINE_TYPE.IMAGE_FILE_MACHINE_I386]:
                print("[-] Invalid architecture")
                return False

            # Check for valid entry point
            if self.binary.entrypoint_address == 0:
                print("[-] Invalid entry point")
                return False

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
            
            # Ensure we have enough space
            if offset + len(new_data) > len(content):
                print(f"[-] Not enough space in section for modification")
                return False
                
            # Apply the modification
            for i, byte in enumerate(new_data):
                content[offset + i] = byte
                
            # Update the section content
            section.content = content
            return True
        except Exception as e:
            print(f"[-] Failed to modify section data: {e}")
            return False

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
            
            # Extract the portion to encode
            if offset + length > len(section_data):
                raise ValueError("Offset and length exceed section size")
                
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
    
    # Add encoding/decoding arguments
    parser.add_argument("--encode-section", help="Section name to encode")
    parser.add_argument("--encode-offset", type=int, default=0, help="Offset within section to start encoding")
    parser.add_argument("--encode-length", type=int, help="Number of bytes to encode")
    parser.add_argument("--encoding", choices=["hex", "octal", "null", "base64"], help="Encoding format")
    parser.add_argument("--print-encoded", action="store_true", help="Print encoded data")
    
    args = parser.parse_args()

    # Initialize rewriter
    rewriter = BinaryRewriter(args.input)

    if not rewriter.load_binary():
        return

    # Handle encoding if requested
    if args.encode_section and args.encoding:
        encoding_plugin = EncodingPlugin()
        
        # If length not specified, encode the entire section from offset
        if not args.encode_length:
            section_data = rewriter.get_section_data(args.encode_section)
            args.encode_length = len(section_data) - args.encode_offset
            
        # Encode the section portion
        encoded_data = encoding_plugin.encode_section_portion(
            rewriter, 
            args.encode_section, 
            args.encode_offset, 
            args.encode_length, 
            args.encoding
        )
        
        if args.print_encoded:
            print(f"[+] Encoded data ({args.encoding}): {encoded_data}")
        
        # For demonstration, let's also apply it back (in a real scenario, you might modify this)
        # Only do this if not printing, to avoid overwriting
        if not args.print_encoded:
            success = encoding_plugin.decode_and_apply(
                rewriter,
                args.encode_section,
                args.encode_offset,
                encoded_data,
                args.encoding
            )
            
            if not success:
                print("[-] Failed to apply encoded data back to binary")
                return

    # Plugin-based analysis (only if we have a valid binary)
    if rewriter.binary is not None:
        plugin = RewriterPlugin()
        plugin.analyze(rewriter)

        # Example: Disassemble .text section
        text_section = rewriter.disassemble_section(".text")

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