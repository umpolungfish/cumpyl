#!/usr/bin/env python3
"""
Verification script to check that all key CA-Packer files exist.
"""

import os
import sys

def check_file_exists(file_path):
    """Check if a file exists and print status."""
    if os.path.exists(file_path):
        print(f"✅ {os.path.basename(file_path)}")
        return True
    else:
        print(f"❌ {os.path.basename(file_path)}")
        return False

def main():
    print("CA-Packer File Verification")
    print("=" * 40)
    
    # Get the project root directory
    project_root = os.path.dirname(os.path.abspath(__file__))
    
    # Define key files to check (actual files that exist)
    key_files = [
        # Main implementation
        "ca_packer/packer.py",
        "ca_packer/ca_engine.py",
        "ca_packer/crypto_engine.py",
        
        # Assembly stubs
        "ca_packer/complete_unpacking_stub.s",
        "ca_packer/ca_evolution_complete.s",
        "ca_packer/chacha20_core.s",
        "ca_packer/poly1305_core.s",
        "ca_packer/chacha20_poly1305_combined.s",
        "ca_packer/chacha20_poly1305_minimal.s",
        
        # Compilation and testing
        "ca_packer/compile_complete_unpacking_stub.py",
        "ca_packer/test_complete_packer.py",
        
        # Documentation (in root directory)
        "README.md",
        "LICENSE",
        "requirements.txt",
        "CA_PACKER_FINAL_SUMMARY.md",
        "CA_PACKER_DEVELOPMENT_SUMMARY.md",
        "CA_PACKER_TODO.md",
        "PROJECT_COMPLETION_ANNOUNCEMENT.md",
        "CA_PACKER_FINAL_IMPACT.md",
        
        # Demo scripts
        "test_ca_packer.py",
        "presentation.py",
        "verify_files.py"
    ]
    
    # Check each file
    existing_files = 0
    total_files = len(key_files)
    
    for file_path in key_files:
        full_path = os.path.join(project_root, file_path)
        if check_file_exists(full_path):
            existing_files += 1
    
    print("\n" + "=" * 40)
    print(f"Files verified: {existing_files}/{total_files}")
    
    if existing_files == total_files:
        print("🎉 All key files exist!")
        return 0
    else:
        print("⚠️  Some key files are missing!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
