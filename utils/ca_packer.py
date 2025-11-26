#!/usr/bin/env python3
"""
Cellular Automata-based Binary Packer
Command-line interface for the CA-based packer implementation.
"""

import sys
import os
import argparse
import logging
from typing import Optional

# Add the project root to the Python path so we can import other modules
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

try:
    # Import the CA packer modules from the ca_packer directory
    from utils import ca_engine
    from utils import crypto_engine
    from utils import packer_fixed_final
except ImportError as e:
    # Try importing from plugins directory as fallback
    try:
        from plugins import ca_engine
        from plugins import crypto_engine
        from plugins import packer_fixed_final
    except ImportError:
        # If both fail, try relative imports
        try:
            import ca_engine
            import crypto_engine
            import packer_fixed_final
        except ImportError:
            logging.error(f"Failed to import CA packer modules: {e}")
            print("Error: CA packer modules not available. Please ensure ca_engine, crypto_engine, and packer_fixed_final modules are installed.")
            sys.exit(1)

def main():
    """Main function to handle command-line interface"""
    parser = argparse.ArgumentParser(description="Cellular Automata-based Binary Packer")
    parser.add_argument("input_file", help="Input binary file to pack")
    parser.add_argument("output_file", help="Output packed binary file")
    parser.add_argument("--ca-steps", type=int, default=100, help="Number of CA steps for packing (default: 100)")
    parser.add_argument("--ca-iterations", type=int, default=1, help="Number of CA iterations (default: 1)")
    parser.add_argument("--compression-level", type=int, default=6, help="Compression level (1-9, default: 6)")
    parser.add_argument("--encrypt", action="store_true", help="Enable encryption of packed binary")
    parser.add_argument("--key-file", type=str, help="Path to encryption key file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    logger = logging.getLogger(__name__)
    
    # Validate input file exists
    if not os.path.exists(args.input_file):
        print(f"Error: Input file '{args.input_file}' does not exist.")
        sys.exit(1)
    
    # Set CA steps
    ca_engine.NUM_STEPS = args.ca_steps
    logger.debug(f"Set CA steps to {args.ca_steps}")
    
    # Configure packer_fixed_final with parameters
    packer_fixed_final.ca_steps = args.ca_steps
    packer_fixed_final.ca_iterations = args.ca_iterations
    packer_fixed_final.compression_level = args.compression_level
    packer_fixed_final.encrypt = args.encrypt
    packer_fixed_final.key_file = args.key_file
    
    try:
        # Execute the packing process
        logger.info(f"Starting CA-based packing of '{args.input_file}' -> '{args.output_file}'")
        logger.info(f"Using {args.ca_steps} CA steps, {args.ca_iterations} iterations, compression level {args.compression_level}")
        
        # Call the main packing function from packer_fixed_final
        success = packer_fixed_final.pack_binary(args.input_file, args.output_file)
        
        if success:
            logger.info("CA packing completed successfully!")
            print(f"Successfully packed '{args.input_file}' -> '{args.output_file}'")
            sys.exit(0)
        else:
            logger.error("CA packing failed!")
            print("CA packing failed!")
            sys.exit(1)
            
    except Exception as e:
        logger.error(f"CA packing failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()