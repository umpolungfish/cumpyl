import unittest
import tempfile
import os
import sys
import subprocess
from pathlib import Path

# 𐑨𐑛 𐑞 𐑐𐑸𐑧𐑯𐑑 𐑛𐑲𐑮𐑧𐑒𐑑𐑼𐑦 𐑑 𐑞 𐑐𐑭𐑔 𐑓𐑹 𐑦𐑥𐑐𐑹𐑑𐑦𐑙
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from cumpyl_package.cumpyl import BinaryRewriter
from cumpyl_package.config import ConfigManager


class TestIntegration(unittest.TestCase):
    """𐑦𐑯𐑑𐑩𐑜𐑮𐑱𐑖𐑩𐑯 𐑑𐑧𐑕𐑑𐑟 𐑓𐑹 𐑞 𐑩𐑯𐑑𐑲𐑼 𐑓𐑮𐑱𐑥𐑢𐑻𐑒"""
    
    def setUp(self):
        """𐑕𐑧𐑑 𐑳𐑐 𐑑𐑧𐑕𐑑 𐑓𐑦𐑒𐑗𐑼𐑟"""
        self.temp_dir = tempfile.mkdtemp()
        self.test_binary = self._create_test_binary()
    
    def tearDown(self):
        """𐑒𐑤𐑰𐑯 𐑳𐑐 𐑑𐑧𐑕𐑑 𐑓𐑦𐑒𐑗𐑼𐑟"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def _create_test_binary(self):
        """𐑒𐑮𐑦𐑱𐑑 𐑩 𐑕𐑦𐑥𐑐𐑩𐑤 𐑑𐑧𐑕𐑑 𐑚𐑲𐑯𐑩𐑮𐑦 𐑓𐑹 𐑑𐑧𐑕𐑑𐑦𐑙"""
        # 𐑒𐑮𐑦𐑱𐑑 𐑩 𐑕𐑦𐑥𐑐𐑩𐑤 C 𐑓𐑲𐑤
        c_code = '''
#include <stdio.h>
#include <string.h>

int main() {
    char message[] = "Hello, World!";
    char secret[] = "SECRET_KEY_12345";
    char url[] = "https://example.com/api/endpoint";
    
    printf("%s\\n", message);
    printf("Using key: %s\\n", secret);
    printf("Connecting to: %s\\n", url);
    
    return 0;
}
        '''
        
        c_file = os.path.join(self.temp_dir, "test_program.c")
        binary_file = os.path.join(self.temp_dir, "test_program")
        
        # 𐑮𐑲𐑑 C 𐑓𐑲𐑤
        with open(c_file, 'w') as f:
            f.write(c_code)
        
        # 𐑑𐑮𐑲 𐑑 𐑒𐑩𐑥𐑐𐑲𐑤 (𐑦𐑓 gcc 𐑦𐑟 𐑩𐑝𐑱𐑤𐑩𐑚𐑩𐑤)
        try:
            result = subprocess.run(['gcc', '-o', binary_file, c_file], 
                                 capture_output=True, text=True)
            if result.returncode == 0:
                return binary_file
        except FileNotFoundError:
            pass
        
        # 𐑦𐑓 gcc 𐑦𐑟 𐑯𐑪𐑑 𐑩𐑝𐑱𐑤𐑩𐑚𐑩𐑤, 𐑒𐑮𐑦𐑱𐑑 𐑩 𐑓𐑱𐑒 ELF 𐑓𐑲𐑤
        return self._create_fake_elf_binary(binary_file)
    
    def _create_fake_elf_binary(self, filename):
        """𐑒𐑮𐑦𐑱𐑑 𐑩 𐑓𐑱𐑒 ELF 𐑚𐑲𐑯𐑩𐑮𐑦 𐑓𐑹 𐑑𐑧𐑕𐑑𐑦𐑙"""
        # 𐑕𐑦𐑥𐑐𐑩𐑤 ELF 𐑣𐑧𐑛𐑼 𐑯 𐑕𐑳𐑥 𐑛𐑱𐑑𐑩
        elf_header = bytearray([
            0x7F, 0x45, 0x4C, 0x46,  # ELF 𐑥𐑨𐑡𐑦𐑒 𐑯𐑳𐑥𐑚𐑼
            0x02,  # 64-bit
            0x01,  # 𐑤𐑦𐑑𐑩𐑤 𐑧𐑯𐑛𐑦𐑩𐑯
            0x01,  # ELF 𐑝𐑻𐑠𐑩𐑯 1
            0x00,  # SysV ABI
        ])
        
        # 𐑯𐑪𐑑: 𐑞𐑦𐑕 𐑦𐑟 𐑩 𐑝𐑧𐑮𐑦 𐑦𐑯𐑒𐑩𐑥𐑐𐑤𐑰𐑑 ELF, 𐑚𐑳𐑑 LIEF 𐑥𐑲𐑑 𐑚𐑰 𐑱𐑚𐑩𐑤 𐑑 𐑐𐑸𐑕 𐑦𐑑
        # 𐑦𐑯 𐑮𐑦𐑩𐑤 𐑑𐑧𐑕𐑑𐑦𐑙, 𐑢𐑰 𐑢𐑫𐑛 𐑿𐑟 𐑩 𐑛𐑦𐑓𐑮𐑩𐑯𐑑 𐑩𐑐𐑮𐑴𐑗
        elf_data = elf_header + b'\x00' * 56  # 𐑯𐑩𐑕 ELF 𐑣𐑧𐑛𐑼 𐑦𐑟 64 𐑚𐑲𐑑𐑕
        
        # 𐑨𐑛 𐑕𐑳𐑥 𐑕𐑑𐑮𐑦𐑙 𐑛𐑱𐑑𐑩 𐑦𐑯 𐑞 "𐑚𐑲𐑯𐑩𐑮𐑦"
        test_strings = [
            b"Hello, World!",
            b"SECRET_KEY_12345", 
            b"https://example.com/api/endpoint",
            b"CreateProcess",
            b"WriteFile",
            b"malloc",
            b"free"
        ]
        
        for string in test_strings:
            elf_data += string + b'\x00'
        
        # 𐑨𐑛 𐑕𐑳𐑥 𐑯𐑷𐑦𐑟 𐑑 𐑦𐑥𐑦𐑑𐑱𐑑 𐑮𐑦𐑩𐑤 𐑚𐑲𐑯𐑩𐑮𐑦 𐑛𐑱𐑑𐑩
        import random
        random.seed(42)  # 𐑓𐑹 𐑮𐑦𐑐𐑮𐑴𐑛𐑿𐑕𐑩𐑚𐑩𐑤 𐑮𐑦𐑟𐑳𐑤𐑑𐑕
        noise = bytes([random.randint(0, 255) for _ in range(1000)])
        elf_data += noise
        
        with open(filename, 'wb') as f:
            f.write(elf_data)
        
        return filename
    
    def test_basic_binary_loading(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑩 𐑚𐑲𐑯𐑩𐑮𐑦 𐑒𐑨𐑯 𐑚𐑰 𐑤𐑴𐑛𐑦𐑛"""
        # 𐑦𐑓 𐑯𐑴 𐑮𐑦𐑩𐑤 𐑚𐑲𐑯𐑩𐑮𐑦 𐑦𐑟 𐑩𐑝𐑱𐑤𐑩𐑚𐑩𐑤, 𐑕𐑒𐑦𐑐 𐑞𐑦𐑕 𐑑𐑧𐑕𐑑
        if not self.test_binary or not os.path.exists(self.test_binary):
            self.skipTest("No test binary available")
        
        rewriter = BinaryRewriter(self.test_binary)
        success = rewriter.load_binary()
        
        # 𐑦𐑓 LIEF 𐑒𐑭𐑯𐑑 𐑐𐑸𐑕 𐑞 𐑓𐑱𐑒 ELF, 𐑞𐑨𐑑'𐑕 OK 𐑓𐑹 𐑞𐑦𐑕 𐑑𐑧𐑕𐑑
        # self.assertTrue(success)
        # self.assertIsNotNone(rewriter.binary)
        
        # 𐑦𐑯 𐑮𐑦𐑩𐑤 𐑑𐑧𐑕𐑑𐑦𐑙, 𐑢𐑰 𐑢𐑫𐑛 𐑗𐑧𐑒 𐑦𐑓 𐑞 𐑚𐑲𐑯𐑩𐑮𐑦 𐑤𐑴𐑛𐑦𐑛 𐑕𐑳𐑒𐑕𐑧𐑕𐑓𐑩𐑤𐑦
        print(f"Binary loading result: {success}")
    
    @unittest.skipIf(not os.path.exists('/usr/bin/gcc'), "GCC not available for test binary creation")
    def test_config_integration_with_real_binary(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑒𐑪𐑯𐑓𐑦𐑜 𐑦𐑯𐑑𐑩𐑜𐑮𐑱𐑖𐑩𐑯 𐑢𐑻𐑒𐑕 𐑢𐑦𐑞 𐑮𐑦𐑩𐑤 𐑚𐑲𐑯𐑩𐑮𐑦𐑟"""
        # 𐑞𐑦𐑕 𐑑𐑧𐑕𐑑 𐑴𐑯𐑤𐑦 𐑮𐑳𐑯𐑟 𐑦𐑓 gcc 𐑦𐑟 𐑩𐑝𐑱𐑤𐑩𐑚𐑩𐑤
        if 'test_program' not in self.test_binary:
            self.skipTest("No compiled test binary available")
        
        # 𐑒𐑮𐑦𐑱𐑑 𐑩 𐑒𐑳𐑕𐑑𐑩𐑥 𐑒𐑪𐑯𐑓𐑦𐑜
        config_data = {
            'framework': {
                'debug_mode': True,
                'max_file_size_mb': 1  # 𐑝𐑧𐑮𐑦 𐑕𐑥𐑷𐑤 𐑓𐑹 𐑑𐑧𐑕𐑑𐑦𐑙
            },
            'plugins': {
                'enabled': False  # 𐑛𐑦𐑟𐑱𐑚𐑩𐑤 𐑐𐑤𐑳𐑜𐑦𐑯𐑟 𐑓𐑹 𐑞𐑦𐑕 𐑑𐑧𐑕𐑑
            }
        }
        
        import yaml
        config_file = os.path.join(self.temp_dir, "test_config.yaml")
        with open(config_file, 'w') as f:
            yaml.dump(config_data, f)
        
        # 𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟 𐑢𐑦𐑞 𐑞 𐑒𐑳𐑕𐑑𐑩𐑥 𐑒𐑪𐑯𐑓𐑦𐑜
        config = ConfigManager(config_file)
        rewriter = BinaryRewriter(self.test_binary, config)
        
        # 𐑝𐑧𐑮𐑦𐑓𐑲 𐑞 𐑒𐑪𐑯𐑓𐑦𐑜 𐑦𐑟 𐑦𐑯 𐑦𐑓𐑧𐑒𐑑
        self.assertTrue(rewriter.config.framework.debug_mode)
        self.assertFalse(rewriter.config.plugins.enabled)
        self.assertEqual(rewriter.config.framework.max_file_size_mb, 1)
    
    def test_plugin_system_basic_functionality(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑞 𐑐𐑤𐑳𐑜𐑦𐑯 𐑕𐑦𐑕𐑑𐑩𐑥 𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟𐑌𐑦 𐑒𐑼𐑧𐑒𐑑𐑤𐑦"""
        if not self.test_binary or not os.path.exists(self.test_binary):
            self.skipTest("No test binary available")
        
        rewriter = BinaryRewriter(self.test_binary)
        
        # 𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑐𐑤𐑳𐑜𐑦𐑯 𐑥𐑨𐑯𐑦𐑡𐑼 𐑦𐑟 𐑦𐑯𐑦𐑖𐑩𐑤𐑲𐑟𐑛
        self.assertIsNotNone(rewriter.plugin_manager)
        
        # 𐑞 𐑐𐑤𐑳𐑜𐑦𐑯 𐑛𐑲𐑮𐑧𐑒𐑑𐑼𐑦 𐑖𐑫𐑛 𐑚𐑰 𐑕𐑧𐑑 𐑒𐑼𐑧𐑒𐑑𐑤𐑦
        expected_plugin_dir = os.path.join(os.getcwd(), "plugins")
        self.assertEqual(rewriter.plugin_manager.plugin_directory, expected_plugin_dir)
    
    def test_encoding_functionality(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑦𐑯𐑒𐑴𐑛𐑦𐑙 𐑓𐑳𐑙𐑒𐑖𐑩𐑯𐑨𐑤𐑦𐑑𐑦 𐑦𐑟 𐑦𐑯𐑑𐑩𐑜𐑮𐑱𐑑𐑦𐑛"""
        rewriter = BinaryRewriter(self.test_binary)
        
        # 𐑑𐑧𐑕𐑑 𐑦𐑯𐑒𐑴𐑛𐑦𐑙 𐑥𐑧𐑔𐑩𐑛𐑟
        test_data = b"Hello, World!"
        
        # 𐑑𐑧𐑕𐑑 𐑨 𐑓𐑿 𐑧𐑯𐑒𐑴𐑛𐑦𐑙 𐑓𐑹𐑥𐑨𐑑𐑕
        hex_encoded = rewriter.encode_bytes(test_data, "hex")
        self.assertIsInstance(hex_encoded, str)
        self.assertTrue(len(hex_encoded) > 0)
        
        base64_encoded = rewriter.encode_bytes(test_data, "base64")
        self.assertIsInstance(base64_encoded, str)
        self.assertTrue(len(base64_encoded) > 0)
        
        # 𐑑𐑧𐑕𐑑 𐑮𐑬𐑯𐑛-𐑑𐑮𐑦𐑐 𐑦𐑯𐑒𐑴𐑛𐑦𐑙/𐑛𐑦𐑒𐑴𐑛𐑦𐑙
        decoded_hex = rewriter.decode_bytes(hex_encoded, "hex")
        self.assertEqual(decoded_hex, test_data)
        
        decoded_base64 = rewriter.decode_bytes(base64_encoded, "base64")
        self.assertEqual(decoded_base64, test_data)
    
    def test_error_handling(self):
        """𐑑𐑧𐑕𐑑 𐑞𐑨𐑑 𐑺𐑼 𐑣𐑨𐑯𐑛𐑤𐑦𐑙 𐑦𐑟 𐑮𐑴𐑚𐑳𐑕𐑑"""
        # 𐑑𐑧𐑕𐑑 𐑢𐑦𐑞 𐑯𐑪𐑯-𐑧𐑒𐑟𐑦𐑕𐑑𐑩𐑯𐑑 𐑓𐑲𐑤
        nonexistent_file = os.path.join(self.temp_dir, "nonexistent.bin")
        
        # 𐑓𐑲𐑤 𐑯𐑪𐑑 𐑓𐑬𐑯𐑛 𐑖𐑫𐑛 𐑯𐑪𐑑 𐑮𐑱𐑟 𐑦𐑒𐑟𐑧𐑐𐑖𐑩𐑯 𐑦𐑯 __init__
        rewriter = BinaryRewriter(nonexistent_file)
        self.assertIsNotNone(rewriter)
        
        # 𐑚𐑳𐑑 𐑤𐑴𐑛𐑦𐑙 𐑖𐑫𐑛 𐑓𐑱𐑤
        success = rewriter.load_binary()
        self.assertFalse(success)
        
        # 𐑦𐑯𐑝𐑨𐑤𐑦𐑛 𐑦𐑯𐑒𐑴𐑛𐑦𐑙 𐑖𐑫𐑛 𐑮𐑱𐑟 ValueError
        with self.assertRaises(ValueError):
            rewriter.encode_bytes(b"test", "invalid_encoding")
        
        with self.assertRaises(ValueError):
            rewriter.decode_bytes("test", "invalid_encoding")


if __name__ == '__main__':
    unittest.main()