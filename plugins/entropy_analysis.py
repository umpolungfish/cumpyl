import math
import numpy as np
from typing import Dict, Any, List, Tuple
import sys
import os

# 𐑨𐑛 𐑞 𐑐𐑸𐑧𐑯𐑑 𐑛𐑲𐑮𐑧𐑒𐑑𐑼𐑦 𐑑 𐑞 𐑐𐑭𐑔 𐑓𐑹 𐑦𐑥𐑐𐑹𐑑𐑦𐑙
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

try:
    from cumpyl_package.plugin_manager import AnalysisPlugin
except ImportError:
    import sys
    import os
    sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'cumpyl_package'))
    from plugin_manager import AnalysisPlugin


class EntropyAnalysisPlugin(AnalysisPlugin):
    """𐑩𐑯𐑨𐑤𐑲𐑟 𐑧𐑯𐑑𐑮𐑩𐑐𐑦 𐑝 𐑚𐑲𐑯𐑩𐑮𐑦 𐑕𐑧𐑒𐑖𐑩𐑯𐑟 𐑑 𐑛𐑦𐑑𐑧𐑒𐑑 𐑐𐑨𐑒𐑦𐑙/𐑦𐑯𐑒𐑮𐑦𐑐𐑖𐑩𐑯"""
    
    def __init__(self, config):
        super().__init__(config)
        self.name = "entropy_analysis"
        self.version = "1.0.0"
        self.description = "Analyzes binary sections for entropy to detect packing/encryption"
        self.author = "Cumpyl Framework"
        self.dependencies = []
        
        # 𐑜𐑧𐑑 𐑒𐑪𐑯𐑓𐑦𐑜 𐑝𐑨𐑤𐑿𐑟
        plugin_config = self.get_config()
        self.block_size = plugin_config.get('block_size', 256)
        self.threshold_high = plugin_config.get('threshold_high', 7.5)
        self.threshold_low = plugin_config.get('threshold_low', 1.0)
    
    def calculate_entropy(self, data: bytes) -> float:
        """𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑑 𐑖𐑨𐑯𐑩𐑯 𐑧𐑯𐑑𐑮𐑩𐑐𐑦 𐑝 𐑩 𐑚𐑲𐑑 𐑕𐑦𐑒𐑢𐑩𐑯𐑕"""
        if not data:
            return 0.0
        
        # 𐑒𐑬𐑯𐑑 𐑞 𐑓𐑮𐑦𐑒𐑢𐑩𐑯𐑕𐑦 𐑝 𐑰𐑗 𐑚𐑲𐑑
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # 𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑑 𐑧𐑯𐑑𐑮𐑩𐑐𐑦
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_section_blocks(self, data: bytes) -> List[Dict[str, Any]]:
        """𐑩𐑯𐑨𐑤𐑲𐑟 𐑞 𐑧𐑯𐑑𐑮𐑩𐑐𐑦 𐑝 𐑚𐑤𐑪𐑒𐑕 𐑦𐑯 𐑩 𐑕𐑧𐑒𐑖𐑩𐑯"""
        blocks = []
        
        for i in range(0, len(data), self.block_size):
            block_data = data[i:i + self.block_size]
            if len(block_data) > 0:
                entropy = self.calculate_entropy(block_data)
                
                # 𐑒𐑨𐑑𐑩𐑜𐑼𐑲𐑟 𐑚𐑱𐑕𐑑 𐑪𐑯 𐑧𐑯𐑑𐑮𐑩𐑐𐑦
                if entropy >= self.threshold_high:
                    category = "high_entropy"
                    risk_level = "high"
                    description = "Likely packed/encrypted"
                elif entropy <= self.threshold_low:
                    category = "low_entropy"
                    risk_level = "low"
                    description = "Likely zero-filled or repetitive"
                else:
                    category = "normal_entropy"
                    risk_level = "medium"
                    description = "Normal entropy range"
                
                blocks.append({
                    'offset': i,
                    'size': len(block_data),
                    'entropy': round(entropy, 3),
                    'category': category,
                    'risk_level': risk_level,
                    'description': description
                })
        
        return blocks
    
    def detect_packing_indicators(self, section_data: bytes, entropy_blocks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """𐑛𐑦𐑑𐑧𐑒𐑑 𐑦𐑯𐑛𐑦𐑒𐑱𐑑𐑼𐑟 𐑝 𐑐𐑨𐑒𐑦𐑙"""
        high_entropy_blocks = [b for b in entropy_blocks if b['category'] == 'high_entropy']
        low_entropy_blocks = [b for b in entropy_blocks if b['category'] == 'low_entropy']
        
        # 𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑑 𐑩𐑝𐑼𐑦𐑡 𐑧𐑯𐑑𐑮𐑩𐑐𐑦
        if entropy_blocks:
            avg_entropy = sum(b['entropy'] for b in entropy_blocks) / len(entropy_blocks)
        else:
            avg_entropy = 0.0
        
        # 𐑛𐑦𐑑𐑻𐑥𐑦𐑯 𐑦𐑓 𐑞 𐑕𐑧𐑒𐑖𐑩𐑯 𐑦𐑟 𐑤𐑲𐑒𐑤𐑦 𐑐𐑨𐑒𐑑
        packing_indicators = {
            'is_likely_packed': False,
            'confidence': 0.0,
            'reasons': []
        }
        
        # 𐑗𐑧𐑒 𐑓𐑹 𐑣𐑲 𐑧𐑯𐑑𐑮𐑩𐑐𐑦 (> 7.5)
        if avg_entropy > self.threshold_high:
            packing_indicators['is_likely_packed'] = True
            packing_indicators['confidence'] += 0.4
            packing_indicators['reasons'].append(f"High average entropy: {avg_entropy:.2f}")
        
        # 𐑗𐑧𐑒 𐑓𐑹 𐑩 𐑣𐑲 𐑐𐑼𐑕𐑧𐑯𐑑𐑦𐑡 𐑝 𐑣𐑲 𐑧𐑯𐑑𐑮𐑩𐑐𐑦 𐑚𐑤𐑪𐑒𐑕
        high_entropy_ratio = len(high_entropy_blocks) / len(entropy_blocks) if entropy_blocks else 0
        if high_entropy_ratio > 0.6:
            packing_indicators['is_likely_packed'] = True
            packing_indicators['confidence'] += 0.3
            packing_indicators['reasons'].append(f"High entropy blocks: {high_entropy_ratio:.1%}")
        
        # 𐑗𐑧𐑒 𐑓𐑹 𐑤𐑲𐑒 𐑝 𐑝𐑨𐑯𐑩𐑱𐑖𐑩𐑯 (𐑩𐑤 𐑚𐑤𐑪𐑒𐑕 𐑣𐑨𐑝 𐑕𐑦𐑥𐑦𐑤𐑼 𐑧𐑯𐑑𐑮𐑩𐑐𐑦)
        if len(entropy_blocks) > 5:
            entropies = [b['entropy'] for b in entropy_blocks]
            entropy_variance = np.var(entropies)
            if entropy_variance < 0.5 and avg_entropy > 7.0:
                packing_indicators['is_likely_packed'] = True
                packing_indicators['confidence'] += 0.2
                packing_indicators['reasons'].append(f"Low entropy variance: {entropy_variance:.2f}")
        
        # 𐑗𐑧𐑒 𐑓𐑹 𐑦𐑛𐑧𐑯𐑑𐑦𐑓𐑲𐑩𐑚𐑩𐑤 𐑯𐑳𐑤 𐑮𐑦𐑡𐑦𐑩𐑯𐑟 (𐑐𐑪𐑕𐑦𐑚𐑩𐑤 𐑦𐑯𐑛𐑦𐑒𐑱𐑑𐑼 𐑝 𐑩𐑯𐑐𐑨𐑒𐑦𐑙)
        null_ratio = len(low_entropy_blocks) / len(entropy_blocks) if entropy_blocks else 0
        if null_ratio > 0.3:
            packing_indicators['confidence'] += 0.1
            packing_indicators['reasons'].append(f"Potential overlay data: {null_ratio:.1%}")
        
        # 𐑒𐑩𐑯𐑕𐑩𐑮𐑝 𐑒𐑪𐑯𐑓𐑦𐑛𐑩𐑯𐑕 𐑦𐑯 𐑮𐑱𐑯𐑡 [0, 1]
        packing_indicators['confidence'] = min(packing_indicators['confidence'], 1.0)
        
        return packing_indicators
    
    def analyze(self, rewriter) -> Dict[str, Any]:
        """𐑩𐑯𐑨𐑤𐑲𐑟 𐑧𐑯𐑑𐑮𐑩𐑐𐑦 𐑓𐑹 𐑷𐑤 𐑕𐑧𐑒𐑖𐑩𐑯𐑟 𐑦𐑯 𐑞 𐑚𐑲𐑯𐑩𐑮𐑦"""
        results = {
            'sections': {},
            'overall_assessment': {
                'likely_packed': False,
                'high_entropy_sections': [],
                'suspicious_patterns': []
            }
        }
        
        try:
            # 𐑩𐑯𐑨𐑤𐑲𐑟 𐑰𐑗 𐑕𐑧𐑒𐑖𐑩𐑯
            for section in rewriter.binary.sections:
                section_name = section.name
                section_data = bytes(section.content)
                
                if len(section_data) == 0:
                    continue
                
                # 𐑒𐑨𐑤𐑒𐑿𐑤𐑱𐑑 𐑴𐑝𐑼𐑷𐑤 𐑧𐑯𐑑𐑮𐑩𐑐𐑦
                overall_entropy = self.calculate_entropy(section_data)
                
                # 𐑩𐑯𐑨𐑤𐑲𐑟 𐑚𐑤𐑪𐑒 𐑚𐑲 𐑚𐑤𐑪𐑒
                entropy_blocks = self.analyze_section_blocks(section_data)
                
                # 𐑛𐑦𐑑𐑧𐑒𐑑 𐑐𐑨𐑒𐑦𐑙 𐑦𐑯𐑛𐑦𐑒𐑱𐑑𐑼𐑟
                packing_indicators = self.detect_packing_indicators(section_data, entropy_blocks)
                
                # 𐑨𐑯𐑨𐑤𐑲𐑟 𐑚𐑲𐑑 𐑛𐑦𐑕𐑑𐑮𐑦𐑚𐑿𐑖𐑩𐑯
                byte_freq = [0] * 256
                for byte in section_data:
                    byte_freq[byte] += 1
                
                # 𐑓𐑲𐑯𐑛 𐑞 𐑥𐑴𐑕𐑑 𐑒𐑪𐑥𐑩𐑯 𐑚𐑲𐑑𐑕
                sorted_bytes = sorted(enumerate(byte_freq), key=lambda x: x[1], reverse=True)
                most_common = [(byte_val, count) for byte_val, count in sorted_bytes[:5] if count > 0]
                
                section_result = {
                    'size': len(section_data),
                    'overall_entropy': round(overall_entropy, 3),
                    'entropy_blocks': entropy_blocks,
                    'packing_indicators': packing_indicators,
                    'byte_distribution': {
                        'most_common_bytes': most_common,
                        'unique_bytes': sum(1 for count in byte_freq if count > 0),
                        'null_bytes': byte_freq[0],
                        'printable_ascii': sum(byte_freq[32:127])
                    }
                }
                
                results['sections'][section_name] = section_result
                
                # 𐑨𐑛 𐑑 𐑴𐑝𐑼𐑷𐑤 𐑩𐑕𐑧𐑕𐑥𐑩𐑯𐑑
                if packing_indicators['is_likely_packed']:
                    results['overall_assessment']['likely_packed'] = True
                    results['overall_assessment']['high_entropy_sections'].append(section_name)
                
                if overall_entropy > self.threshold_high:
                    results['overall_assessment']['suspicious_patterns'].append({
                        'section': section_name,
                        'pattern': 'high_entropy',
                        'value': overall_entropy,
                        'description': f"Section {section_name} has high entropy ({overall_entropy:.2f})"
                    })
        
        except Exception as e:
            results['error'] = str(e)
        
        return results