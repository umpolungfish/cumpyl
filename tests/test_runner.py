#!/usr/bin/env python3
"""
𐑑𐑧𐑕𐑑 𐑮𐑳𐑯𐑼 𐑓𐑹 𐑞 𐑒𐑫𐑥𐑐𐑦𐑤 𐑓𐑮𐑱𐑥𐑢𐑻𐑒
"""

import unittest
import sys
import os
from pathlib import Path

# 𐑨𐑛 𐑞 𐑐𐑸𐑧𐑯𐑑 𐑛𐑲𐑮𐑧𐑒𐑑𐑼𐑦 𐑑 𐑞 𐑐𐑭𐑔 𐑓𐑹 𐑦𐑥𐑐𐑹𐑑𐑦𐑙
sys.path.insert(0, str(Path(__file__).parent.parent))


def run_all_tests():
    """𐑮𐑳𐑯 𐑷𐑤 𐑑𐑧𐑕𐑑𐑟 𐑦𐑯 𐑞 𐑑𐑧𐑕𐑑 𐑕𐑢𐑰𐑑"""
    # 𐑛𐑦𐑕𐑒𐑳𐑝𐑼 𐑷𐑤 𐑑𐑧𐑕𐑑 𐑓𐑲𐑤𐑟
    test_dir = os.path.dirname(__file__)
    loader = unittest.TestLoader()
    suite = loader.discover(test_dir, pattern='test_*.py')
    
    # 𐑮𐑳𐑯 𐑞 𐑑𐑧𐑕𐑑𐑟
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # 𐑮𐑦𐑑𐑻𐑯 0 𐑦𐑓 𐑷𐑤 𐑑𐑧𐑕𐑑𐑟 𐑐𐑭𐑕𐑑, 1 𐑦𐑓 𐑧𐑯𐑦 𐑓𐑱𐑤𐑛
    return 0 if result.wasSuccessful() else 1


def run_specific_test(test_name):
    """𐑮𐑳𐑯 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑑𐑧𐑕𐑑 𐑥𐑪𐑛𐑿𐑤"""
    try:
        # 𐑦𐑥𐑐𐑹𐑑 𐑞 𐑑𐑧𐑕𐑑 𐑥𐑪𐑛𐑿𐑤
        test_module = __import__(test_name)
        
        # 𐑤𐑴𐑛 𐑯 𐑮𐑳𐑯 𐑞 𐑑𐑧𐑕𐑑𐑟
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromModule(test_module)
        
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        return 0 if result.wasSuccessful() else 1
        
    except ImportError as e:
        print(f"Could not import test module '{test_name}': {e}")
        return 1


def main():
    """𐑥𐑱𐑯 𐑑𐑧𐑕𐑑 𐑮𐑳𐑯𐑼 𐑓𐑳𐑙𐑒𐑖𐑩𐑯"""
    if len(sys.argv) > 1:
        # 𐑮𐑳𐑯 𐑩 𐑕𐑐𐑧𐑕𐑦𐑓𐑦𐑒 𐑑𐑧𐑕𐑑
        test_name = sys.argv[1]
        return run_specific_test(test_name)
    else:
        # 𐑮𐑳𐑯 𐑷𐑤 𐑑𐑧𐑕𐑑𐑟
        return run_all_tests()


if __name__ == '__main__':
    sys.exit(main())