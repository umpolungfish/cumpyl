"""Custom exceptions for the binary analysis framework."""
class BinaryAnalysisError(Exception):
    """Base exception for all binary analysis errors."""
    pass

class PluginError(BinaryAnalysisError):
    """Plugin-related errors."""
    pass

class ConfigurationError(PluginError):
    """Configuration-related errors."""
    pass

class TransformationError(PluginError):
    """Transformation-related errors."""
    pass

class CryptoError(BinaryAnalysisError):
    """Cryptography-related errors."""
    pass

class FormatDetectionError(BinaryAnalysisError):
    """Binary format detection errors."""
    pass

class SectionAnalysisError(BinaryAnalysisError):
    """Section analysis errors."""
    pass