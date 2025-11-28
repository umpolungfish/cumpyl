#!/usr/bin/env python3
"""
Debug rotation functions separately
"""

def _rotl(value: int, shift: int, bits: int = 8) -> int:
    """Rotate left operation"""
    shift = shift % bits
    return ((value << shift) | (value >> (bits - shift))) & ((1 << bits) - 1)

def _rotr(value: int, shift: int, bits: int = 8) -> int:
    """Rotate right operation"""
    shift = shift % bits
    return ((value >> shift) | (value << (bits - shift))) & ((1 << bits) - 1)

def test_rotation():
    """Test rotation functions"""
    print("Testing rotation functions...")
    
    value = 0x48  # 'H' in ASCII
    shift_amount = 3
    
    print(f"Original value: 0x{value:02x} ({chr(value)})")
    
    # Test rotate left
    rotated_left = _rotl(value, shift_amount)
    print(f"After left rotation by {shift_amount}: 0x{rotated_left:02x}")
    
    # Test rotate right (reverse)
    rotated_right = _rotr(rotated_left, shift_amount)
    print(f"After right rotation by {shift_amount}: 0x{rotated_right:02x} ({chr(rotated_right) if 32 <= rotated_right <= 126 else 'non-printable'})")
    
    print(f"Match: {value == rotated_right}")
    
    # Test with multiple values
    print("\nTesting with multiple values:")
    test_values = [0x48, 0x65, 0x6C, 0x6C, 0x6F]  # b'Hello'
    for val in test_values:
        rotated = _rotl(val, 3)
        unrotated = _rotr(rotated, 3)
        match = val == unrotated
        print(f"0x{val:02x} -> 0x{rotated:02x} -> 0x{unrotated:02x} -> Match: {match}")

if __name__ == "__main__":
    test_rotation()