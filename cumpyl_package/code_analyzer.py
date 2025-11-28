#!/usr/bin/env python3
"""
Code Analyzer for Cumpyl
Analyzes code sections to find string references and patch them
"""

import lief
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass
import logging

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    logging.warning("Capstone not available - code analysis will be limited")

logger = logging.getLogger(__name__)


@dataclass
class StringReference:
    """Represents a reference to a string in code"""
    code_rva: int          # RVA of the instruction referencing the string
    string_rva: int        # RVA of the string being referenced
    reference_type: str    # Type: 'push_imm', 'mov_imm', 'lea_rip', 'mov_direct'
    instruction_size: int  # Size of the instruction in bytes
    instruction_bytes: bytes  # Original instruction bytes
    offset_in_instruction: int  # Offset of the RVA within the instruction


@dataclass
class FunctionInfo:
    """Information about a function"""
    start_rva: int
    end_rva: int
    name: Optional[str]
    string_refs: List[StringReference]


class CodeAnalyzer:
    """
    Analyzes PE binary code sections to find string references

    Features:
    - Disassembles code sections using Capstone
    - Identifies different types of string references
    - Tracks cross-references
    - Prepares for reference patching
    """

    def __init__(self, binary: lief.PE.Binary):
        """Initialize code analyzer with a PE binary"""
        self.binary = binary
        self.references = []  # List of StringReference objects
        self.functions = {}   # RVA -> FunctionInfo
        self.string_rvas = set()  # Known string RVAs

        # Determine architecture
        self.is_x64 = (binary.header.machine == lief.PE.MACHINE_TYPES.AMD64)

        # Initialize Capstone if available
        if CAPSTONE_AVAILABLE:
            if self.is_x64:
                self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

            self.cs.detail = True  # Enable detailed analysis
        else:
            self.cs = None
            logger.warning("Code analysis will use pattern matching instead of disassembly")

    def register_string(self, string_rva: int):
        """Register a string RVA that we're looking for references to"""
        self.string_rvas.add(string_rva)

    def register_strings(self, string_rvas: List[int]):
        """Register multiple string RVAs"""
        self.string_rvas.update(string_rvas)

    def analyze_code_sections(self) -> int:
        """
        Analyze all executable code sections for string references

        Returns number of references found
        """
        try:
            logger.info("Starting code section analysis...")

            # Find code sections
            code_sections = [s for s in self.binary.sections
                           if s.characteristics & lief.PE.SECTION_CHARACTERISTICS.CNT_CODE]

            if not code_sections:
                logger.warning("No code sections found")
                return 0

            total_refs = 0
            for section in code_sections:
                logger.info(f"Analyzing section {section.name}...")

                if CAPSTONE_AVAILABLE and self.cs:
                    refs = self._analyze_section_with_capstone(section)
                else:
                    refs = self._analyze_section_with_patterns(section)

                total_refs += refs
                logger.info(f"  Found {refs} references in {section.name}")

            logger.info(f"Total string references found: {total_refs}")
            return total_refs

        except Exception as e:
            logger.error(f"Code analysis failed: {e}")
            return 0

    def _analyze_section_with_capstone(self, section: lief.PE.Section) -> int:
        """Analyze section using Capstone disassembler"""
        try:
            code = bytes(section.content)
            base_rva = section.virtual_address
            refs_found = 0

            # Disassemble the section
            for insn in self.cs.disasm(code, base_rva):
                # Check if instruction references any of our strings
                ref = self._check_instruction_for_string_ref(insn, base_rva)
                if ref:
                    self.references.append(ref)
                    refs_found += 1

            return refs_found

        except Exception as e:
            logger.error(f"Capstone analysis failed: {e}")
            return 0

    def _check_instruction_for_string_ref(self, insn, base_rva) -> Optional[StringReference]:
        """
        Check if an instruction references a known string

        Common patterns:
        - push 0x401000    (push immediate)
        - mov eax, 0x401000  (mov immediate)
        - lea rax, [rip+offset]  (RIP-relative LEA in x64)
        - mov eax, [0x401000]  (direct memory reference)
        """
        try:
            # Get operands
            if not insn.operands:
                return None

            # Check each operand for immediate values that match string RVAs
            for op in insn.operands:
                # Check immediate operands
                if op.type == capstone.x86.X86_OP_IMM:
                    target_rva = op.imm

                    # Check if this immediate value is a string RVA
                    if target_rva in self.string_rvas:
                        # Determine reference type
                        ref_type = self._determine_reference_type(insn)

                        # Find offset of the immediate in the instruction bytes
                        offset = self._find_imm_offset_in_instruction(insn, target_rva)

                        return StringReference(
                            code_rva=insn.address,
                            string_rva=target_rva,
                            reference_type=ref_type,
                            instruction_size=insn.size,
                            instruction_bytes=insn.bytes,
                            offset_in_instruction=offset
                        )

                # Check RIP-relative addressing (x64)
                elif op.type == capstone.x86.X86_OP_MEM:
                    if op.mem.base == capstone.x86.X86_REG_RIP:
                        # Calculate absolute RVA from RIP-relative
                        target_rva = insn.address + insn.size + op.mem.disp

                        if target_rva in self.string_rvas:
                            return StringReference(
                                code_rva=insn.address,
                                string_rva=target_rva,
                                reference_type='lea_rip',
                                instruction_size=insn.size,
                                instruction_bytes=insn.bytes,
                                offset_in_instruction=insn.size - 4  # Usually last 4 bytes
                            )

            return None

        except Exception as e:
            logger.debug(f"Error checking instruction at 0x{insn.address:x}: {e}")
            return None

    def _determine_reference_type(self, insn) -> str:
        """Determine the type of string reference"""
        mnemonic = insn.mnemonic.lower()

        if mnemonic == 'push':
            return 'push_imm'
        elif mnemonic in ['mov', 'movabs']:
            return 'mov_imm'
        elif mnemonic == 'lea':
            return 'lea_rip'
        elif mnemonic in ['call', 'jmp']:
            return 'call_imm'
        else:
            return 'other_imm'

    def _find_imm_offset_in_instruction(self, insn, target_value: int) -> int:
        """Find offset of immediate value within instruction bytes"""
        try:
            insn_bytes = insn.bytes

            # Try to find the target value as different sizes
            # Try as 32-bit (most common)
            target_bytes_32 = target_value.to_bytes(4, byteorder='little', signed=False)
            if target_bytes_32 in insn_bytes:
                return insn_bytes.index(target_bytes_32)

            # Try as 64-bit (for x64)
            if self.is_x64:
                target_bytes_64 = target_value.to_bytes(8, byteorder='little', signed=False)
                if target_bytes_64 in insn_bytes:
                    return insn_bytes.index(target_bytes_64)

            # Default to last 4 bytes (common for immediates)
            return len(insn_bytes) - 4

        except Exception as e:
            logger.debug(f"Could not find immediate offset: {e}")
            return 0

    def _analyze_section_with_patterns(self, section: lief.PE.Section) -> int:
        """
        Fallback: Analyze section using byte pattern matching
        (Used when Capstone is not available)
        """
        try:
            code = bytes(section.content)
            base_rva = section.virtual_address
            refs_found = 0

            # Pattern: Look for 4-byte values that match our string RVAs
            for i in range(len(code) - 3):
                # Extract potential RVA (little-endian)
                potential_rva = int.from_bytes(code[i:i+4], byteorder='little')

                if potential_rva in self.string_rvas:
                    # Found a potential reference
                    # Determine likely instruction type based on preceding bytes
                    ref_type = 'unknown'
                    if i > 0:
                        opcode = code[i-1]
                        if opcode == 0x68:  # push imm32
                            ref_type = 'push_imm'
                        elif opcode in [0xB8, 0xB9, 0xBA, 0xBB]:  # mov reg, imm32
                            ref_type = 'mov_imm'

                    ref = StringReference(
                        code_rva=base_rva + i,
                        string_rva=potential_rva,
                        reference_type=ref_type,
                        instruction_size=5 if ref_type == 'push_imm' else 6,
                        instruction_bytes=code[max(0,i-2):i+4],
                        offset_in_instruction=2 if i > 1 else 0
                    )

                    self.references.append(ref)
                    refs_found += 1

            return refs_found

        except Exception as e:
            logger.error(f"Pattern analysis failed: {e}")
            return 0

    def get_references_to_string(self, string_rva: int) -> List[StringReference]:
        """Get all code references to a specific string"""
        return [ref for ref in self.references if ref.string_rva == string_rva]

    def get_all_references(self) -> List[StringReference]:
        """Get all discovered string references"""
        return self.references

    def can_safely_patch(self, ref: StringReference) -> Tuple[bool, str]:
        """
        Determine if a reference can be safely patched

        Returns (can_patch, reason)
        """
        # Check if we have enough space to inject a call
        min_size_needed = 5  # call instruction is at least 5 bytes (E8 + 4 byte offset)

        if ref.instruction_size < min_size_needed:
            return False, f"Instruction too small ({ref.instruction_size} < {min_size_needed})"

        # Check reference type
        if ref.reference_type in ['push_imm', 'mov_imm', 'lea_rip']:
            return True, "Patchable reference type"

        # Unknown or complex reference types
        if ref.reference_type == 'unknown':
            return False, "Unknown reference type - risky to patch"

        return True, "Appears safe to patch"

    def generate_reference_report(self) -> Dict[str, Any]:
        """Generate a detailed report of all string references"""
        report = {
            'total_references': len(self.references),
            'references_by_type': {},
            'patchable_count': 0,
            'unpatchable_count': 0,
            'references': []
        }

        # Count by type
        for ref in self.references:
            ref_type = ref.reference_type
            report['references_by_type'][ref_type] = \
                report['references_by_type'].get(ref_type, 0) + 1

            # Check if patchable
            can_patch, reason = self.can_safely_patch(ref)
            if can_patch:
                report['patchable_count'] += 1
            else:
                report['unpatchable_count'] += 1

            # Add to reference list
            report['references'].append({
                'code_rva': f"0x{ref.code_rva:08x}",
                'string_rva': f"0x{ref.string_rva:08x}",
                'type': ref.reference_type,
                'size': ref.instruction_size,
                'patchable': can_patch,
                'reason': reason
            })

        return report


class ReferencePatcher:
    """
    Patches code references to use deobfuscation stubs
    """

    def __init__(self, binary: lief.PE.Binary, analyzer: CodeAnalyzer):
        """Initialize reference patcher"""
        self.binary = binary
        self.analyzer = analyzer
        self.patches_applied = []

    def patch_reference(self, ref: StringReference, stub_rva: int,
                       key_data: bytes = b'') -> bool:
        """
        Patch a single reference to call deobfuscation stub instead

        Strategy:
        1. Replace original instruction with call to stub
        2. Stub deobfuscates string and returns pointer
        3. NOP-fill any remaining bytes
        """
        try:
            # Check if patchable
            can_patch, reason = self.analyzer.can_safely_patch(ref)
            if not can_patch:
                logger.warning(f"Cannot patch reference at 0x{ref.code_rva:08x}: {reason}")
                return False

            # Find section containing this code
            section = self._find_section_for_rva(ref.code_rva)
            if not section:
                logger.error(f"Cannot find section for RVA 0x{ref.code_rva:08x}")
                return False

            # Calculate offset within section
            offset_in_section = ref.code_rva - section.virtual_address

            # Generate call instruction
            # call stub_rva (E8 + rel32 offset)
            call_insn = self._generate_call_instruction(ref.code_rva, stub_rva)

            if not call_insn:
                logger.error(f"Failed to generate call instruction")
                return False

            # NOP-fill remaining bytes
            nop_fill = bytes([0x90] * (ref.instruction_size - len(call_insn)))
            patch_bytes = call_insn + nop_fill

            # Apply patch to section
            section_content = list(section.content)
            for i, byte in enumerate(patch_bytes):
                section_content[offset_in_section + i] = byte

            section.content = section_content

            # Track patch
            self.patches_applied.append({
                'rva': ref.code_rva,
                'original': ref.instruction_bytes,
                'patched': patch_bytes,
                'stub_rva': stub_rva
            })

            logger.debug(f"Patched reference at 0x{ref.code_rva:08x} to call stub at 0x{stub_rva:08x}")
            return True

        except Exception as e:
            logger.error(f"Failed to patch reference at 0x{ref.code_rva:08x}: {e}")
            return False

    def _find_section_for_rva(self, rva: int) -> Optional[lief.PE.Section]:
        """Find section containing the given RVA"""
        for section in self.binary.sections:
            start = section.virtual_address
            end = start + section.virtual_size
            if start <= rva < end:
                return section
        return None

    def _generate_call_instruction(self, from_rva: int, to_rva: int) -> bytes:
        """
        Generate a call instruction from from_rva to to_rva

        Format: E8 [4-byte relative offset]
        """
        try:
            # Calculate relative offset
            # offset = target - (current + 5)
            # where 5 is the size of the call instruction
            rel_offset = to_rva - (from_rva + 5)

            # Generate call instruction
            call_insn = bytes([0xE8])  # call opcode
            call_insn += struct.pack('<i', rel_offset)  # signed 32-bit offset

            return call_insn

        except Exception as e:
            logger.error(f"Failed to generate call: {e}")
            return bytes()

    def patch_all_references(self, stub_rva_map: Dict[int, int]) -> int:
        """
        Patch all references using provided stub RVA map

        Args:
            stub_rva_map: Dict mapping string_rva -> stub_rva

        Returns number of successfully patched references
        """
        patched_count = 0

        for ref in self.analyzer.get_all_references():
            stub_rva = stub_rva_map.get(ref.string_rva)
            if stub_rva:
                if self.patch_reference(ref, stub_rva):
                    patched_count += 1

        logger.info(f"Patched {patched_count} / {len(self.analyzer.references)} references")
        return patched_count

    def get_patch_report(self) -> Dict[str, Any]:
        """Generate report of applied patches"""
        return {
            'total_patches': len(self.patches_applied),
            'patches': self.patches_applied
        }


# Helper functions
def analyze_binary_for_strings(binary: lief.PE.Binary,
                               string_rvas: List[int]) -> Optional[CodeAnalyzer]:
    """
    Analyze a binary for string references

    Args:
        binary: LIEF PE binary
        string_rvas: List of string RVAs to look for

    Returns:
        Configured CodeAnalyzer or None on failure
    """
    try:
        analyzer = CodeAnalyzer(binary)
        analyzer.register_strings(string_rvas)
        analyzer.analyze_code_sections()
        return analyzer
    except Exception as e:
        logger.error(f"Binary analysis failed: {e}")
        return None
