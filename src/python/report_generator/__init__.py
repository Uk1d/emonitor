"""
报告生成模块
"""

from .generator import (
    ReportGenerator,
    ReportGeneratorConfig,
    SecurityReport,
    ReportFormat,
    ReportMetadata,
    ReportSummary,
    EventAnalysis,
    AlertAnalysis,
    ChainAnalysis,
    AIAnalysis,
    Recommendation
)

__all__ = [
    'ReportGenerator',
    'ReportGeneratorConfig',
    'SecurityReport',
    'ReportFormat',
    'ReportMetadata',
    'ReportSummary',
    'EventAnalysis',
    'AlertAnalysis',
    'ChainAnalysis',
    'AIAnalysis',
    'Recommendation'
]
