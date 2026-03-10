"""
AI 异常检测模块
使用统计方法和机器学习进行安全事件异常检测
"""

import numpy as np
import pandas as pd
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class AnomalyType(Enum):
    """异常类型"""
    PROCESS_BEHAVIOR = "process_behavior"
    NETWORK_ACTIVITY = "network_activity"
    FILE_ACTIVITY = "file_activity"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class Severity(Enum):
    """严重级别"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AnomalyEvidence:
    """异常证据"""
    evidence_type: str
    value: any
    timestamp: datetime
    context: str


@dataclass
class Anomaly:
    """异常事件"""
    id: str
    anomaly_type: AnomalyType
    severity: Severity
    confidence: float
    description: str
    detected_at: datetime
    pid: int
    process_name: str
    category: str
    evidence: List[AnomalyEvidence] = field(default_factory=list)
    anomaly_score: float = 0.0
    contributing_factors: Dict[str, float] = field(default_factory=dict)


@dataclass
class ProcessStats:
    """进程统计信息"""
    pid: int
    comm: str
    start_time: datetime
    last_activity: datetime
    exec_count: int = 0
    file_read_count: int = 0
    file_write_count: int = 0
    file_delete_count: int = 0
    net_connect_count: int = 0
    net_accept_count: int = 0
    net_bind_count: int = 0
    syscall_stats: Dict[str, int] = field(default_factory=dict)
    files_accessed: List[str] = field(default_factory=list)
    network_connections: List[Dict] = field(default_factory=list)
    child_processes: List[int] = field(default_factory=list)


@dataclass
class BaselineData:
    """基线数据"""
    average_process_rate: float = 0.0
    process_rate_std: float = 0.0
    common_process_names: Dict[str, int] = field(default_factory=dict)
    average_connection_rate: float = 0.0
    connection_rate_std: float = 0.0
    common_remote_hosts: Dict[str, int] = field(default_factory=dict)
    average_file_access_rate: float = 0.0
    file_access_rate_std: float = 0.0
    sensitive_file_access: Dict[str, int] = field(default_factory=dict)
    last_updated: Optional[datetime] = None


class AIDetectorConfig:
    """AI 检测器配置"""
    def __init__(self):
        self.statistics_window = timedelta(minutes=5)
        self.min_samples_for_baseline = 10  # 降低基线建立门槛，从50降到10
        self.process_rate_threshold = 2.0   # 降低阈值，使检测更敏感
        self.network_threshold = 2.0
        self.file_threshold = 2.0
        self.anomaly_score_threshold = 0.4  # 降低异常分数阈值，从0.6降到0.4
        self.high_risk_threshold = 0.6      # 相应降低高危阈值
        self.critical_threshold = 0.75      # 相应降低严重阈值
        self.max_history_size = 1000
        self.suspicious_process_names = {".", "null", "random", "unknown", "test", "sh", "bash", "nc", "ncat", "netcat"}
        self.suspicious_ports = {4444, 5555, 6666, 31337, 1337, 1234, 4443, 8888, 9999}
        self.sensitive_files = [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "/root/.ssh/", "/home/.ssh/",
            "/var/log/auth.log", "/var/log/secure",
            "/etc/hosts", "/etc/resolv.conf", "/proc/self",
            "/.ssh/", "/id_rsa", "/id_dsa", "/.bash_history"
        ]


class AIDetector:
    """AI 异常检测器"""

    def __init__(self, config: Optional[AIDetectorConfig] = None):
        self.config = config or AIDetectorConfig()
        self.statistics: Dict[int, ProcessStats] = {}
        self.anomaly_history: Dict[int, deque] = defaultdict(lambda: deque(maxlen=100))
        self.detected_anomalies: List[Anomaly] = []
        self.baseline = BaselineData()

    def process_event(self, event: Dict) -> Optional[Anomaly]:
        """
        处理事件并进行异常检测

        Args:
            event: 事件字典，包含 pid, comm, event_type, timestamp 等字段

        Returns:
            检测到的异常对象，如果没有异常则返回 None
        """
        self._update_statistics(event)

        # 基本异常检测（即使基线未建立）
        anomaly = self._detect_basic_anomaly(event)
        if anomaly:
            self._record_anomaly(anomaly)
            return anomaly

        # 基线建立后的统计异常检测
        if self._is_baseline_ready():
            anomaly = self._detect_anomaly(event)
            if anomaly:
                self._record_anomaly(anomaly)
                return anomaly

        return None

    def update_baselines(self):
        """更新基线数据"""
        if len(self.statistics) < self.config.min_samples_for_baseline:
            return

        # 计算进程行为基线
        exec_counts = [stats.exec_count for stats in self.statistics.values()]
        avg_process_rate = np.mean(exec_counts) if exec_counts else 0.0
        process_rate_std = np.std(exec_counts) if len(exec_counts) > 1 else 0.0

        # 计算进程名分布
        process_names = defaultdict(int)
        for stats in self.statistics.values():
            process_names[stats.comm] += 1

        self.baseline.average_process_rate = avg_process_rate
        self.baseline.process_rate_std = process_rate_std
        self.baseline.common_process_names = dict(process_names)
        self.baseline.last_updated = datetime.now()

    def get_recent_anomalies(self, limit: int = 100) -> List[Anomaly]:
        """获取最近的异常列表"""
        anomalies = sorted(
            self.detected_anomalies,
            key=lambda a: a.detected_at,
            reverse=True
        )
        return anomalies[:limit]

    def clear_old_statistics(self, max_age: timedelta = timedelta(minutes=30)):
        """清理旧的统计数据"""
        cutoff = datetime.now() - max_age
        to_remove = []

        for pid, stats in self.statistics.items():
            if stats.last_activity < cutoff:
                to_remove.append(pid)

        for pid in to_remove:
            del self.statistics[pid]
            if pid in self.anomaly_history:
                del self.anomaly_history[pid]

        # 限制异常历史大小
        if len(self.detected_anomalies) > self.config.max_history_size:
            self.detected_anomalies = self.detected_anomalies[-self.config.max_history_size:]

    def _is_baseline_ready(self) -> bool:
        """检查基线是否已建立"""
        if self.baseline.last_updated is None:
            return False

        age = datetime.now() - self.baseline.last_updated
        return age < self.config.statistics_window

    def _update_statistics(self, event: Dict):
        """更新事件统计信息"""
        pid = event.get('pid', 0)
        comm = event.get('comm', '')
        event_type = event.get('event_type', '')

        # 获取或创建进程统计
        if pid not in self.statistics:
            now = datetime.now()
            self.statistics[pid] = ProcessStats(
                pid=pid,
                comm=comm,
                start_time=now,
                last_activity=now
            )

        stats = self.statistics[pid]
        stats.last_activity = datetime.now()

        # 根据事件类型更新统计
        event_type_lower = event_type.lower()
        if event_type_lower in ('execve', 'execveat'):
            stats.exec_count += 1
        elif event_type_lower in ('openat', 'read'):
            stats.file_read_count += 1
        elif event_type_lower == 'write':
            stats.file_write_count += 1
        elif event_type_lower == 'unlink':
            stats.file_delete_count += 1
        elif event_type_lower == 'connect':
            stats.net_connect_count += 1
        elif event_type_lower == 'accept':
            stats.net_accept_count += 1
        elif event_type_lower == 'bind':
            stats.net_bind_count += 1

        # 记录系统调用
        stats.syscall_stats[event_type] = stats.syscall_stats.get(event_type, 0) + 1

        # 记录文件访问
        filename = event.get('filename', '')
        if filename and filename not in stats.files_accessed:
            stats.files_accessed.append(filename)

        # 记录网络连接
        dst_addr = event.get('dst_addr')
        if dst_addr:
            stats.network_connections.append({
                'remote_addr': dst_addr.get('ip', ''),
                'remote_port': dst_addr.get('port', 0),
                'protocol': 'tcp',
                'start_time': datetime.now().isoformat()
            })

    def _detect_basic_anomaly(self, event: Dict) -> Optional[Anomaly]:
        """
        基本异常检测（不依赖基线）

        Args:
            event: 事件字典

        Returns:
            检测到的异常对象，如果没有异常则返回 None
        """
        pid = event.get('pid', 0)
        comm = event.get('comm', '')
        event_type = event.get('event_type', '')
        filename = event.get('filename', '')
        dst_addr = event.get('dst_addr')

        evidences = []
        anomaly_score = 0.0
        factors = {}

        # 1. 检查可疑进程名
        if comm in self.config.suspicious_process_names:
            anomaly_score += 0.8
            factors['suspicious_name'] = 0.8
            evidences.append(AnomalyEvidence(
                evidence_type='suspicious_name',
                value=comm,
                timestamp=datetime.now(),
                context='可疑进程名'
            ))

        # 2. 检查敏感文件访问
        if filename:
            for sensitive in self.config.sensitive_files:
                if filename.startswith(sensitive):
                    anomaly_score += 0.9
                    factors['sensitive_file'] = 0.9
                    evidences.append(AnomalyEvidence(
                        evidence_type='sensitive_file_access',
                        value=filename,
                        timestamp=datetime.now(),
                        context='访问敏感文件'
                    ))
                    break

        # 3. 检查连接到可疑端口
        if dst_addr:
            remote_port = dst_addr.get('port', 0)
            if remote_port in self.config.suspicious_ports:
                anomaly_score += 0.7
                factors['suspicious_port'] = 0.7
                evidences.append(AnomalyEvidence(
                    evidence_type='suspicious_port',
                    value=remote_port,
                    timestamp=datetime.now(),
                    context='连接到可疑端口'
                ))

        # 确定严重级别
        severity = Severity.LOW
        if anomaly_score >= 0.85:
            severity = Severity.CRITICAL
        elif anomaly_score >= 0.6:
            severity = Severity.HIGH
        elif anomaly_score >= 0.4:
            severity = Severity.MEDIUM

        # 如果异常分数超过阈值，创建异常
        if anomaly_score >= self.config.anomaly_score_threshold:
            return Anomaly(
                id=f'anomaly_{pid}_{datetime.now().timestamp()}',
                anomaly_type=AnomalyType.PROCESS_BEHAVIOR,
                severity=severity,
                confidence=min(anomaly_score, 1.0),
                description=f'基本异常检测: 可疑行为 (分数: {anomaly_score:.2f})',
                detected_at=datetime.now(),
                pid=pid,
                process_name=comm,
                category='security',
                evidence=evidences,
                anomaly_score=anomaly_score,
                contributing_factors=factors
            )

        return None

    def _detect_anomaly(self, event: Dict) -> Optional[Anomaly]:
        """
        检测异常

        Args:
            event: 事件字典

        Returns:
            检测到的异常对象，如果没有异常则返回 None
        """
        pid = event.get('pid', 0)
        stats = self.statistics.get(pid)

        if not stats:
            return None

        anomaly_score = 0.0
        factors = {}
        evidences = []

        # 1. 检测进程行为异常 (30% 权重)
        factor, evidence = self._check_process_behavior(stats, event)
        if factor > 0:
            factors['process_behavior'] = factor
            anomaly_score += factor * 0.3
            evidences.extend(evidence)

        # 2. 检测网络活动异常 (25% 权重)
        factor, evidence = self._check_network_activity(stats, event)
        if factor > 0:
            factors['network_activity'] = factor
            anomaly_score += factor * 0.25
            evidences.extend(evidence)

        # 3. 检测文件活动异常 (25% 权重)
        factor, evidence = self._check_file_activity(stats, event)
        if factor > 0:
            factors['file_activity'] = factor
            anomaly_score += factor * 0.25
            evidences.extend(evidence)

        # 4. 检测权限变更异常 (20% 权重)
        factor, evidence = self._check_privilege_change(event)
        if factor > 0:
            factors['privilege_change'] = factor
            anomaly_score += factor * 0.2
            evidences.extend(evidence)

        # 如果异常分数超过阈值，创建异常
        if anomaly_score >= self.config.anomaly_score_threshold:
            return self._create_anomaly(stats, anomaly_score, factors, evidences)

        return None

    def _check_process_behavior(self, stats: ProcessStats, event: Dict) -> Tuple[float, List[AnomalyEvidence]]:
        """检测进程行为异常"""
        score = 0.0
        evidences = []

        # 检查异常的系统调用组合
        if stats.syscall_stats.get('execve', 0) > 10 and stats.syscall_stats.get('connect', 0) > 5:
            score += 0.6
            evidences.append(AnomalyEvidence(
                evidence_type='high_exec_rate',
                value=stats.syscall_stats.get('execve', 0),
                timestamp=datetime.now(),
                context='进程频繁执行'
            ))

        # 检查可疑的进程名
        if stats.comm in self.config.suspicious_process_names:
            score += 0.8
            evidences.append(AnomalyEvidence(
                evidence_type='suspicious_name',
                value=stats.comm,
                timestamp=datetime.now(),
                context='可疑进程名'
            ))

        # 检查异常高的执行速率
        if stats.exec_count > 0 and self.baseline.average_process_rate > 0:
            z_score = (stats.exec_count - self.baseline.average_process_rate) / (self.baseline.process_rate_std + 0.001)
            if z_score > self.config.process_rate_threshold:
                score += min(z_score / 10, 0.7)
                evidences.append(AnomalyEvidence(
                    evidence_type='high_execution_rate',
                    value=stats.exec_count,
                    timestamp=datetime.now(),
                    context=f'执行速率异常 (Z-score: {z_score:.2f})'
                ))

        return score, evidences

    def _check_network_activity(self, stats: ProcessStats, event: Dict) -> Tuple[float, List[AnomalyEvidence]]:
        """检测网络活动异常"""
        score = 0.0
        evidences = []

        # 检查过多的连接
        if stats.net_connect_count > 20:
            score += 0.7
            evidences.append(AnomalyEvidence(
                evidence_type='excessive_connections',
                value=stats.net_connect_count,
                timestamp=datetime.now(),
                context='过多的网络连接'
            ))

        # 检查连接到非常见端口
        dst_addr = event.get('dst_addr')
        if dst_addr:
            remote_port = dst_addr.get('port', 0)
            if remote_port in self.config.suspicious_ports:
                score += 0.5
                evidences.append(AnomalyEvidence(
                    evidence_type='suspicious_port',
                    value=remote_port,
                    timestamp=datetime.now(),
                    context='连接到可疑端口'
                ))

        return score, evidences

    def _check_file_activity(self, stats: ProcessStats, event: Dict) -> Tuple[float, List[AnomalyEvidence]]:
        """检测文件活动异常"""
        score = 0.0
        evidences = []

        filename = event.get('filename', '')

        # 检查敏感文件访问
        if filename:
            for sensitive in self.config.sensitive_files:
                if filename.startswith(sensitive):
                    score += 0.9
                    evidences.append(AnomalyEvidence(
                        evidence_type='sensitive_file_access',
                        value=filename,
                        timestamp=datetime.now(),
                        context='访问敏感文件'
                    ))
                    break

        # 检查频繁的文件删除
        if stats.file_delete_count > 10:
            score += 0.5
            evidences.append(AnomalyEvidence(
                evidence_type='excessive_file_deletion',
                value=stats.file_delete_count,
                timestamp=datetime.now(),
                context='频繁删除文件'
            ))

        return score, evidences

    def _check_privilege_change(self, event: Dict) -> Tuple[float, List[AnomalyEvidence]]:
        """检测权限变更异常"""
        score = 0.0
        evidences = []

        # 检查可疑的权限变更
        event_type = event.get('event_type', '').lower()
        if event_type in ('setuid', 'setgid'):
            old_uid = event.get('uid', 0)
            new_uid = event.get('new_uid', 0)
            if new_uid != 0 and new_uid != old_uid:
                score += 0.8
                evidences.append(AnomalyEvidence(
                    evidence_type='privilege_escalation',
                    value={'old': old_uid, 'new': new_uid},
                    timestamp=datetime.now(),
                    context='权限提升'
                ))

        return score, evidences

    def _create_anomaly(self, stats: ProcessStats, anomaly_score: float,
                        factors: Dict[str, float], evidences: List[AnomalyEvidence]) -> Anomaly:
        """创建异常对象"""
        # 确定严重级别
        if anomaly_score >= self.config.critical_threshold:
            severity = Severity.CRITICAL
        elif anomaly_score >= self.config.high_risk_threshold:
            severity = Severity.HIGH
        elif anomaly_score >= 0.7:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        # 确定异常类型（权重最大的因子）
        anomaly_type = AnomalyType.PROCESS_BEHAVIOR
        if factors:
            max_factor = max(factors.values())
            for factor_type, factor_value in factors.items():
                if factor_value == max_factor:
                    if factor_type == 'process_behavior':
                        anomaly_type = AnomalyType.PROCESS_BEHAVIOR
                    elif factor_type == 'network_activity':
                        anomaly_type = AnomalyType.NETWORK_ACTIVITY
                    elif factor_type == 'file_activity':
                        anomaly_type = AnomalyType.FILE_ACTIVITY
                    elif factor_type == 'privilege_change':
                        anomaly_type = AnomalyType.PRIVILEGE_ESCALATION
                    break

        # 生成描述
        description = self._generate_description(anomaly_type)

        # 获取类别
        category = self._get_category(anomaly_type)

        return Anomaly(
            id=f"anomaly_{datetime.now().timestamp()}",
            anomaly_type=anomaly_type,
            severity=severity,
            confidence=anomaly_score,
            description=description,
            detected_at=datetime.now(),
            pid=stats.pid,
            process_name=stats.comm,
            category=category,
            evidence=evidences,
            anomaly_score=anomaly_score,
            contributing_factors=factors
        )

    def _generate_description(self, anomaly_type: AnomalyType) -> str:
        """生成异常描述"""
        descriptions = {
            AnomalyType.PROCESS_BEHAVIOR: "检测到异常的进程行为模式",
            AnomalyType.NETWORK_ACTIVITY: "检测到异常的网络活动",
            AnomalyType.FILE_ACTIVITY: "检测到异常的文件访问行为",
            AnomalyType.PRIVILEGE_ESCALATION: "检测到权限提升行为",
        }
        return descriptions.get(anomaly_type, "检测到异常行为")

    def _get_category(self, anomaly_type: AnomalyType) -> str:
        """获取异常类型对应的类别"""
        categories = {
            AnomalyType.PROCESS_BEHAVIOR: "process",
            AnomalyType.NETWORK_ACTIVITY: "network",
            AnomalyType.FILE_ACTIVITY: "file",
            AnomalyType.PRIVILEGE_ESCALATION: "permission",
        }
        return categories.get(anomaly_type, "unknown")

    def _record_anomaly(self, anomaly: Anomaly):
        """记录异常"""
        self.detected_anomalies.append(anomaly)
        self.anomaly_history[anomaly.pid].append(anomaly.anomaly_score)


def anomaly_to_dict(anomaly: Anomaly) -> Dict:
    """将异常对象转换为字典（用于 JSON 序列化）"""
    return {
        'id': anomaly.id,
        'anomaly_type': anomaly.anomaly_type.value,
        'severity': anomaly.severity.value,
        'confidence': anomaly.confidence,
        'description': anomaly.description,
        'detected_at': anomaly.detected_at.isoformat(),
        'pid': anomaly.pid,
        'process_name': anomaly.process_name,
        'category': anomaly.category,
        'anomaly_score': anomaly.anomaly_score,
        'contributing_factors': anomaly.contributing_factors,
        'evidence': [
            {
                'type': e.evidence_type,
                'value': e.value,
                'timestamp': e.timestamp.isoformat(),
                'context': e.context
            }
            for e in anomaly.evidence
        ]
    }
