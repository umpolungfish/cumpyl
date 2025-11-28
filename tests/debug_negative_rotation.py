#!/usr/bin/env python3
"""
Debug rotation with negative amounts
"""

def _rotl(value: int, shift: int, bits: int = 8) -> int:
    """Rotate left operation"""
    shift = shift % bits
    return ((value << shift) | (value >> (bits - shift))) & ((1 << bits) - 1)

def _rotr(value: int, shift: int, bits: int = 8) -> int:
    """Rotate right operation"""
    shift = shift % bits
    return ((value >> shift) | (value << (bits - shift))) & ((1 << bits) - 1)

def _apply_rotation_pos(data: bytes, amount: int) -> bytes:
    """Apply rotation using left rotation only (positive amounts)"""
    if amount >= 0:
        return bytes(_rotl(b, amount) for b in data)
    else:
        # Convert negative rotation to right rotation
        right_amount = -amount % 8
        return bytes(_rotr(b, right_amount) for b in data)

def test_rotation_with_negative():
    """Test rotation with negative amounts"""
    print("Testing rotation with negative amounts...")
    
    test_data = b"Hello"
    shift_amount = 3
    
    print(f"Test data: {test_data}")
    
    # Apply positive rotation
    rotated = _apply_rotation_pos(test_data, shift_amount)
    print(f"After rotation by +{shift_amount}: {rotated.hex()}")
    
    # Apply negative rotation (reverse)
    unrotated = _apply_rotation_pos(rotated, -shift_amount)
    print(f"After rotation by -{shift_amount}: {unrotated.hex()}")
    
    print(f"Match: {test_data == unrotated}")
    
    # Test step by step
    print("\nStep by step for 'H' (0x48):")
    h_value = 0x48
    print(f"Original: 0x{h_value:02x}")
    
    # Rotate left by 3
    rotated_h = _rotl(h_value, 3)
    print(f"After _rotl(0x{h_value:02x}, 3): 0x{rotated_h:02x}")
    
    # Rotate right by 3 using _apply_rotation with negative amount
    unrotated_h = _rotr(rotated_h, 3)
    print(f"After _rotr(0x{rotated_h:02x}, 3): 0x{unrotated_h:02x}")
    print(f"Step by step Match: {h_value == unrotated_h}")

if __name__ == "__main__":
    test_rotation_with_negative()