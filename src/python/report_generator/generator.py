"""
安全报告生成模块
支持 JSON、CSV、HTML 三种格式的报告导出
"""

import json
import csv
from io import StringIO
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum


class ReportFormat(Enum):
    """报告格式"""
    JSON = "json"
    CSV = "csv"
    HTML = "html"


class Severity(Enum):
    """严重级别"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TimeRange:
    """时间范围"""
    start_time: str
    end_time: str
    duration_hours: float


@dataclass
class ReportMetadata:
    """报告元数据"""
    generated_at: str
    report_id: str
    report_name: str
    author_name: str
    report_version: str = "1.0"
    time_range: Optional[TimeRange] = None


@dataclass
class ProcessSummary:
    """进程摘要"""
    pid: int
    comm: str
    event_count: int
    anomaly_count: int


@dataclass
class EventTypeSummary:
    """事件类型摘要"""
    event_type: str
    count: int
    percentage: float


@dataclass
class CategorySummary:
    """类别摘要"""
    category: str
    count: int
    percentage: float


@dataclass
class ReportSummary:
    """报告摘要"""
    total_events: int
    total_alerts: int
    total_anomalies: int
    active_alerts: int
    resolved_alerts: int
    critical_alerts: int
    high_alerts: int
    attack_chains: int
    high_risk_chains: int
    top_processes: List[ProcessSummary] = field(default_factory=list)
    top_event_types: List[EventTypeSummary] = field(default_factory=list)
    top_categories: List[CategorySummary] = field(default_factory=list)


@dataclass
class HourlyCount:
    """小时统计"""
    hour: int
    count: int


@dataclass
class EventAnalysis:
    """事件分析"""
    by_event_type: Dict[str, int] = field(default_factory=dict)
    by_category: Dict[str, int] = field(default_factory=dict)
    by_hour: List[HourlyCount] = field(default_factory=list)
    trend: str = "稳定"
    peak_hour: int = 0


@dataclass
class AlertAnalysis:
    """告警分析"""
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_category: Dict[str, int] = field(default_factory=dict)
    by_status: Dict[str, int] = field(default_factory=dict)
    trend: str = "稳定"
    average_resolution_time_hours: float = 0.0
    false_positive_rate: float = 0.0


@dataclass
class ChainAnalysis:
    """攻击链分析"""
    total_chains: int
    by_status: Dict[str, int] = field(default_factory=dict)
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_risk_level: Dict[str, int] = field(default_factory=dict)
    mitre_mapping: Dict[str, int] = field(default_factory=dict)
    top_stages: List[str] = field(default_factory=list)


@dataclass
class AIAnalysis:
    """AI 分析"""
    total_anomalies: int
    by_type: Dict[str, int] = field(default_factory=dict)
    by_severity: Dict[str, int] = field(default_factory=dict)
    average_confidence: float = 0.0
    top_factors: List[str] = field(default_factory=list)


@dataclass
class Recommendation:
    """安全建议"""
    priority: str
    category: str
    title: str
    description: str
    action_items: List[str] = field(default_factory=list)


@dataclass
class SecurityReport:
    """安全报告"""
    metadata: ReportMetadata
    summary: ReportSummary
    event_analysis: EventAnalysis
    alert_analysis: AlertAnalysis
    chain_analysis: ChainAnalysis
    ai_analysis: AIAnalysis
    recommendations: List[Recommendation] = field(default_factory=list)


class ReportGeneratorConfig:
    """报告生成器配置"""
    def __init__(self):
        self.output_dir = "reports"
        self.include_events = True
        self.include_alerts = True
        self.include_chains = True
        self.include_ai = True
        self.max_events = 1000
        self.max_alerts = 500
        self.report_name = "安全检测报告"
        self.author_name = "eTracee"


class ReportGenerator:
    """安全报告生成器"""

    def __init__(self, config: Optional[ReportGeneratorConfig] = None):
        self.config = config or ReportGeneratorConfig()

    def generate_report(self,
                      events: List[Dict],
                      alerts: List[Dict],
                      anomalies: List[Dict],
                      attack_chains: List[Dict],
                      format: str = ReportFormat.JSON.value) -> bytes:
        """
        生成安全报告

        Args:
            events: 事件列表
            alerts: 告警列表
            anomalies: AI 检测到的异常列表
            attack_chains: 攻击链列表
            format: 报告格式 (json/csv/html)

        Returns:
            报告数据的字节流
        """
        # 构建报告
        report = self._build_report(events, alerts, anomalies, attack_chains)

        # 根据格式生成
        format_lower = format.lower()
        if format_lower == ReportFormat.CSV.value:
            return self._generate_csv_report(report).encode('utf-8-sig')
        elif format_lower == ReportFormat.HTML.value:
            return self._generate_html_report(report).encode('utf-8')
        else:
            # JSON 默认格式
            return self._generate_json_report(report).encode('utf-8')

    def _build_report(self,
                    events: List[Dict],
                    alerts: List[Dict],
                    anomalies: List[Dict],
                    attack_chains: List[Dict]) -> SecurityReport:
        """构建报告对象"""
        now = datetime.now()

        # 计算时间范围
        start_time, end_time = self._calculate_time_range(events, alerts, anomalies)
        time_range = None
        if start_time and end_time:
            duration_hours = (end_time - start_time).total_seconds() / 3600
            time_range = TimeRange(
                start_time=start_time.isoformat(),
                end_time=end_time.isoformat(),
                duration_hours=duration_hours
            )

        # 元数据
        metadata = ReportMetadata(
            generated_at=now.isoformat(),
            report_id=f"report_{int(now.timestamp())}",
            report_name=self.config.report_name,
            author_name=self.config.author_name,
            time_range=time_range
        )

        # 摘要
        summary = self._build_summary(events, alerts, anomalies, attack_chains)

        # 事件分析
        event_analysis = self._build_event_analysis(events)

        # 告警分析
        alert_analysis = self._build_alert_analysis(alerts)

        # 攻击链分析
        chain_analysis = self._build_chain_analysis(attack_chains)

        # AI 分析
        ai_analysis = self._build_ai_analysis(anomalies)

        # 生成建议
        recommendations = self._generate_recommendations(
            summary, event_analysis, alert_analysis, ai_analysis
        )

        return SecurityReport(
            metadata=metadata,
            summary=summary,
            event_analysis=event_analysis,
            alert_analysis=alert_analysis,
            chain_analysis=chain_analysis,
            ai_analysis=ai_analysis,
            recommendations=recommendations
        )

    def _calculate_time_range(self,
                            events: List[Dict],
                            alerts: List[Dict],
                            anomalies: List[Dict]) -> tuple:
        """计算时间范围"""
        timestamps = []

        for event in events:
            ts = event.get('timestamp')
            if ts:
                timestamps.append(self._parse_timestamp(ts))

        for alert in alerts:
            ts = alert.get('timestamp')
            if ts:
                timestamps.append(self._parse_timestamp(ts))

        for anomaly in anomalies:
            ts = anomaly.get('detected_at')
            if ts:
                timestamps.append(self._parse_timestamp(ts))

        if not timestamps:
            return None, None

        return min(timestamps), max(timestamps)

    def _parse_timestamp(self, ts: str) -> datetime:
        """解析时间戳，始终返回naive datetime以避免比较错误"""
        if not ts:
            return datetime.now()

        # 尝试多种格式
        formats = [
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(ts, fmt)
                # 转换为naive datetime
                if dt.tzinfo is not None:
                    dt = dt.replace(tzinfo=None)
                return dt
            except ValueError:
                continue

        # ISO 格式
        try:
            dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
            # 转换为naive datetime
            if dt.tzinfo is not None:
                dt = dt.replace(tzinfo=None)
            return dt
        except:
            return datetime.now()

    def _build_summary(self,
                    events: List[Dict],
                    alerts: List[Dict],
                    anomalies: List[Dict],
                    attack_chains: List[Dict]) -> ReportSummary:
        """构建报告摘要"""
        # 统计告警严重级别
        critical_alerts = sum(1 for a in alerts if a.get('severity') == 'critical')
        high_alerts = sum(1 for a in alerts if a.get('severity') == 'high')
        active_alerts = sum(1 for a in alerts if a.get('status') != 'resolved')
        resolved_alerts = sum(1 for a in alerts if a.get('status') == 'resolved')

        # 统计高风险攻击链
        high_risk_chains = sum(
            1 for c in attack_chains
            if c.get('risk_level') in ('high', 'critical')
        )

        return ReportSummary(
            total_events=len(events),
            total_alerts=len(alerts),
            total_anomalies=len(anomalies),
            active_alerts=active_alerts,
            resolved_alerts=resolved_alerts,
            critical_alerts=critical_alerts,
            high_alerts=high_alerts,
            attack_chains=len(attack_chains),
            high_risk_chains=high_risk_chains
        )

    def _build_event_analysis(self, events: List[Dict]) -> EventAnalysis:
        """构建事件分析"""
        by_event_type = {}
        by_category = {}
        by_hour = [HourlyCount(hour=i, count=0) for i in range(24)]

        peak_hour = 0
        max_hour_count = 0

        for event in events[:self.config.max_events]:
            event_type = event.get('event_type', 'unknown')
            by_event_type[event_type] = by_event_type.get(event_type, 0) + 1

            # 根据事件类型确定类别
            category = self._get_event_category(event_type)
            by_category[category] = by_category.get(category, 0) + 1

            # 按小时统计
            ts = event.get('timestamp', '')
            if ts:
                try:
                    dt = self._parse_timestamp(ts)
                    hour = dt.hour
                    by_hour[hour].count += 1
                    if by_hour[hour].count > max_hour_count:
                        max_hour_count = by_hour[hour].count
                        peak_hour = hour
                except:
                    pass

        return EventAnalysis(
            by_event_type=by_event_type,
            by_category=by_category,
            by_hour=by_hour,
            peak_hour=peak_hour
        )

    def _build_alert_analysis(self, alerts: List[Dict]) -> AlertAnalysis:
        """构建告警分析"""
        by_severity = {}
        by_category = {}
        by_status = {}

        for alert in alerts[:self.config.max_alerts]:
            severity = alert.get('severity', 'unknown')
            by_severity[severity] = by_severity.get(severity, 0) + 1

            category = alert.get('category', 'unknown')
            by_category[category] = by_category.get(category, 0) + 1

            status = alert.get('status', 'unknown')
            by_status[status] = by_status.get(status, 0) + 1

        return AlertAnalysis(
            by_severity=by_severity,
            by_category=by_category,
            by_status=by_status,
            false_positive_rate=0.02  # 示例值
        )

    def _build_chain_analysis(self, attack_chains: List[Dict]) -> ChainAnalysis:
        """构建攻击链分析"""
        by_status = {}
        by_severity = {}
        by_risk_level = {}
        mitre_mapping = {}

        top_stages = {}

        for chain in attack_chains:
            status = chain.get('status', 'unknown')
            by_status[status] = by_status.get(status, 0) + 1

            severity = chain.get('severity', 'unknown')
            by_severity[severity] = by_severity.get(severity, 0) + 1

            risk_level = chain.get('risk_level', 'unknown')
            by_risk_level[risk_level] = by_risk_level.get(risk_level, 0) + 1

            # MITRE 映射
            for tech in chain.get('techniques', []):
                tech_id = tech.get('technique_id', '')
                if tech_id:
                    mitre_mapping[tech_id] = mitre_mapping.get(tech_id, 0) + 1

            # 统计阶段
            for stage in chain.get('stages', []):
                stage_name = stage.get('stage', '')
                top_stages[stage_name] = top_stages.get(stage_name, 0) + 1

        return ChainAnalysis(
            total_chains=len(attack_chains),
            by_status=by_status,
            by_severity=by_severity,
            by_risk_level=by_risk_level,
            mitre_mapping=mitre_mapping,
            top_stages=sorted(top_stages.items(), key=lambda x: x[1], reverse=True)[:10]
        )

    def _build_ai_analysis(self, anomalies: List[Dict]) -> AIAnalysis:
        """构建 AI 分析"""
        by_type = {}
        by_severity = {}
        total_confidence = 0.0
        top_factors = {}

        for anomaly in anomalies:
            anomaly_type = anomaly.get('type', 'unknown')
            by_type[anomaly_type] = by_type.get(anomaly_type, 0) + 1

            severity = anomaly.get('severity', 'unknown')
            by_severity[severity] = by_severity.get(severity, 0) + 1

            confidence = anomaly.get('confidence', 0.0)
            total_confidence += confidence

            # 统计贡献因子
            for factor, value in anomaly.get('contributing_factors', {}).items():
                if value > 0:
                    top_factors[factor] = top_factors.get(factor, 0.0) + value

        avg_confidence = total_confidence / len(anomalies) if anomalies else 0.0

        return AIAnalysis(
            total_anomalies=len(anomalies),
            by_type=by_type,
            by_severity=by_severity,
            average_confidence=avg_confidence,
            top_factors=sorted(top_factors.items(), key=lambda x: x[1], reverse=True)[:10]
        )

    def _generate_recommendations(self,
                               summary: ReportSummary,
                               event_analysis: EventAnalysis,
                               alert_analysis: AlertAnalysis,
                               ai_analysis: AIAnalysis) -> List[Recommendation]:
        """生成安全建议"""
        recommendations = []

        # 基于严重告警的建议
        if summary.critical_alerts > 0:
            recommendations.append(Recommendation(
                priority="critical",
                category="incident_response",
                title="检测到严重安全事件",
                description=f"系统检测到 {summary.critical_alerts} 个严重级别的安全告警，需要立即处理。",
                action_items=[
                    "立即审查严重告警的详细信息",
                    "隔离受影响的系统",
                    "启动应急响应流程",
                    "通知安全团队"
                ]
            ))

        # 基于高危告警的建议
        if summary.high_alerts > 0:
            recommendations.append(Recommendation(
                priority="high",
                category="threat_hunting",
                title="存在高危安全威胁",
                description=f"系统检测到 {summary.high_alerts} 个高危安全告警，建议优先处理。",
                action_items=[
                    "分析高危告警的攻击向量",
                    "检查相关进程和网络活动",
                    "验证是否存在横向移动",
                    "更新安全策略"
                ]
            ))

        # 基于 AI 异常的建议
        if ai_analysis.total_anomalies > 0:
            recommendations.append(Recommendation(
                priority="medium",
                category="behavior_analysis",
                title="检测到异常行为模式",
                description=f"AI 检测器发现 {ai_analysis.total_anomalies} 个异常行为，平均置信度为 {ai_analysis.average_confidence:.2%}。",
                action_items=[
                    "审查异常行为对应的进程",
                    "检查是否为误报",
                    "如确认攻击，采取相应措施"
                ]
            ))

        # 基于活跃告警的建议
        if summary.active_alerts > 0:
            recommendations.append(Recommendation(
                priority="medium",
                category="alert_management",
                title="存在未处理的告警",
                description=f"当前有 {summary.active_alerts} 个活跃告警未处理。",
                action_items=[
                    "按优先级处理告警",
                    "及时更新告警状态",
                    "定期审查告警处理流程"
                ]
            ))

        # 基于攻击链的建议
        if summary.attack_chains > 0:
            recommendations.append(Recommendation(
                priority="high",
                category="incident_response",
                title="检测到潜在攻击链",
                description=f"系统检测到 {summary.attack_chains} 条攻击链，表明可能存在持续攻击活动。",
                action_items=[
                    "完整追踪攻击链路径",
                    "识别攻击的初始入侵点",
                    "评估数据泄露风险",
                    "加强入侵检测规则"
                ]
            ))

        return recommendations

    def _generate_json_report(self, report: SecurityReport) -> str:
        """生成 JSON 格式报告"""
        # 将 dataclass 转换为字典
        report_dict = self._report_to_dict(report)
        return json.dumps(report_dict, ensure_ascii=False, indent=2)

    def _generate_csv_report(self, report: SecurityReport) -> str:
        """生成 CSV 格式报告"""
        output = StringIO()

        # 写入摘要部分
        writer = csv.writer(output)
        writer.writerow(['报告摘要'])
        writer.writerow(['指标', '值'])
        writer.writerow(['总事件数', report.summary.total_events])
        writer.writerow(['总告警数', report.summary.total_alerts])
        writer.writerow(['AI 异常数', report.summary.total_anomalies])
        writer.writerow(['活跃告警', report.summary.active_alerts])
        writer.writerow(['严重告警', report.summary.critical_alerts])
        writer.writerow(['高危告警', report.summary.high_alerts])
        writer.writerow([])

        # 写入 AI 异常
        writer.writerow(['AI 检测到的异常'])
        writer.writerow(['ID', '类型', '严重级别', '进程名', 'PID', '置信度', '检测时间', '描述'])

        # 由于 CSV 中需要原始数据，这里简化处理
        # 实际应用中可以从 anomalies 参数获取详细数据
        writer.writerow(['-', '-', '-', '-', '-', '-', '-', '-', '（使用 JSON 格式获取详细异常数据）'])

        return output.getvalue()

    def _generate_html_report(self, report: SecurityReport) -> str:
        """生成 HTML 格式报告"""
        # 构建 HTML 模板
        html = self._get_html_template()

        # 填充数据
        html = html.replace('{{REPORT_ID}}', report.metadata.report_id)
        html = html.replace('{{GENERATED_AT}}', report.metadata.generated_at)
        html = html.replace('{{AUTHOR}}', report.metadata.author_name)

        # 摘要数据
        html = html.replace('{{TOTAL_EVENTS}}', str(report.summary.total_events))
        html = html.replace('{{TOTAL_ALERTS}}', str(report.summary.total_alerts))
        html = html.replace('{{TOTAL_ANOMALIES}}', str(report.summary.total_anomalies))
        html = html.replace('{{ACTIVE_ALERTS}}', str(report.summary.active_alerts))
        html = html.replace('{{CRITICAL_ALERTS}}', str(report.summary.critical_alerts))

        # 告警严重级别分布
        severity_html = self._build_severity_table(report.alert_analysis.by_severity)
        html = html.replace('{{SEVERITY_TABLE}}', severity_html)

        # AI 异常分析
        ai_html = self._build_ai_analysis_html(report.ai_analysis)
        html = html.replace('{{AI_ANALYSIS}}', ai_html)

        # 安全建议
        recommendations_html = self._build_recommendations_html(report.recommendations)
        html = html.replace('{{RECOMMENDATIONS}}', recommendations_html)

        return html

    def _get_html_template(self) -> str:
        """获取 HTML 模板"""
        return '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全检测报告 - {{REPORT_ID}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            border-bottom: 2px solid #0066cc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 { color: #0066cc; }
        .meta { color: #666; font-size: 14px; margin-top: 10px; }
        .section {
            margin: 30px 0;
            padding: 20px;
            background: #f9f9f9;
            border-radius: 4px;
        }
        .section h2 {
            color: #333;
            margin-bottom: 15px;
            border-left: 4px solid #0066cc;
            padding-left: 10px;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 4px;
            text-align: center;
        }
        .stat-value {
            font-size: 32px;
            font-weight: bold;
            color: #0066cc;
        }
        .stat-label {
            color: #666;
            margin-top: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th { background: #0066cc; color: white; }
        .critical { color: #d32f2f; font-weight: bold; }
        .high { color: #f57c00; font-weight: bold; }
        .medium { color: #f5a623; }
        .low { color: #00a854; }
        .recommendation {
            margin: 15px 0;
            padding: 15px;
            background: white;
            border-left: 4px solid #ddd;
            border-radius: 4px;
        }
        .recommendation.priority-critical { border-left-color: #d32f2f; }
        .recommendation.priority-high { border-left-color: #f57c00; }
        .recommendation.priority-medium { border-left-color: #f5a623; }
        .recommendation h4 { margin-bottom: 10px; }
        .recommendation ul { margin-left: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>安全检测报告</h1>
            <div class="meta">
                报告 ID: {{REPORT_ID}} | 生成时间: {{GENERATED_AT}} | 作者: {{AUTHOR}}
            </div>
        </div>

        <div class="section">
            <h2>执行摘要</h2>
            <div class="summary-grid">
                <div class="stat-card">
                    <div class="stat-value">{{TOTAL_EVENTS}}</div>
                    <div class="stat-label">总事件数</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{TOTAL_ALERTS}}</div>
                    <div class="stat-label">总告警数</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{TOTAL_ANOMALIES}}</div>
                    <div class="stat-label">AI 异常数</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{{ACTIVE_ALERTS}}</div>
                    <div class="stat-label">活跃告警</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value critical">{{CRITICAL_ALERTS}}</div>
                    <div class="stat-label">严重告警</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>告警分析</h2>
            {{SEVERITY_TABLE}}
        </div>

        <div class="section">
            <h2>AI 异常检测分析</h2>
            {{AI_ANALYSIS}}
        </div>

        <div class="section">
            <h2>安全建议</h2>
            {{RECOMMENDATIONS}}
        </div>

        <div style="margin-top: 40px; text-align: center; color: #999; font-size: 12px;">
            此报告由 eTracee 安全监控系统自动生成
        </div>
    </div>
</body>
</html>'''

    def _build_severity_table(self, by_severity: Dict[str, int]) -> str:
        """构建严重级别表格"""
        rows = ['<table><tr><th>严重级别</th><th>数量</th></tr>']

        severity_order = ['critical', 'high', 'medium', 'low']
        for severity in severity_order:
            count = by_severity.get(severity, 0)
            if count > 0:
                rows.append(f'<tr><td class="{severity}">{severity}</td><td>{count}</td></tr>')

        if len(rows) == 1:
            rows.append('<tr><td colspan="2">暂无告警数据</td></tr>')

        rows.append('</table>')
        return ''.join(rows)

    def _build_ai_analysis_html(self, ai_analysis: AIAnalysis) -> str:
        """构建 AI 分析 HTML"""
        if ai_analysis.total_anomalies == 0:
            return '<p>暂无 AI 检测到的异常</p>'

        html = '<table><tr><th>异常类型</th><th>数量</th><th>平均置信度</th></tr>'

        for anomaly_type, count in ai_analysis.by_type.items():
            confidence = ai_analysis.average_confidence
            type_name = {
                'process_behavior': '进程行为',
                'network_activity': '网络活动',
                'file_activity': '文件活动',
                'privilege_escalation': '权限提升'
            }.get(anomaly_type, anomaly_type)

            html += f'<tr><td>{type_name}</td><td>{count}</td><td>{confidence:.1%}</td></tr>'

        html += '</table>'
        return html

    def _build_recommendations_html(self, recommendations: List[Recommendation]) -> str:
        """构建建议 HTML"""
        if not recommendations:
            return '<p>基于当前数据，无需特别建议。</p>'

        html = ''
        for rec in recommendations:
            html += f'''
            <div class="recommendation priority-{rec.priority}">
                <h4>[{rec.priority.upper()}] {rec.title}</h4>
                <p>{rec.description}</p>
                <ul>
            '''
            for action in rec.action_items:
                html += f'<li>{action}</li>'
            html += '''
                </ul>
            </div>
            '''
        return html

    def _report_to_dict(self, report: SecurityReport) -> Dict:
        """将报告对象转换为字典"""
        return {
            'metadata': asdict(report.metadata),
            'summary': asdict(report.summary),
            'event_analysis': asdict(report.event_analysis),
            'alert_analysis': asdict(report.alert_analysis),
            'chain_analysis': asdict(report.chain_analysis),
            'ai_analysis': asdict(report.ai_analysis),
            'recommendations': [asdict(r) for r in report.recommendations]
        }

    @staticmethod
    def _get_event_category(event_type: str) -> str:
        """获取事件类别"""
        category_map = {
            'execve': 'process', 'execveat': 'process',
            'openat': 'file', 'read': 'file', 'write': 'file',
            'unlink': 'file', 'rename': 'file',
            'connect': 'network', 'bind': 'network', 'listen': 'network',
            'accept': 'network', 'sendto': 'network',
            'setuid': 'permission', 'setgid': 'permission'
        }
        return category_map.get(event_type, 'unknown')
