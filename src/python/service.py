"""
eTracee Python 后端服务
提供 AI 检测和报告导出功能的 HTTP API
"""

import json
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, Response
from flask_cors import CORS

from ai_detector import AIDetector, AIDetectorConfig, anomaly_to_dict
from report_generator import ReportGenerator, ReportGeneratorConfig

app = Flask(__name__)
# 限制 CORS 来源以避免频繁的外部访问
CORS(app, resources={r"/*": {"origins": ["http://localhost:8888", "http://127.0.0.1:8888"]}})

# 全局检测器和生成器实例
ai_detector: Optional[AIDetector] = None
report_generator: Optional[ReportGenerator] = None
events_buffer: List[Dict] = []
alerts_buffer: List[Dict] = []
attack_chains_buffer: List[Dict] = []
buffer_max_size = 10000


@app.route('/health', methods=['GET'])
def health_check():
    """健康检查"""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'services': {
            'ai_detector': ai_detector is not None,
            'report_generator': report_generator is not None
        }
    })


@app.route('/api/ai/detect', methods=['POST'])
def detect_anomaly():
    """
    接收事件并进行 AI 异常检测

    请求体格式:
    {
        "pid": 1234,
        "comm": "bash",
        "event_type": "execve",
        "timestamp": "2024-03-08T10:30:00",
        "uid": 1000,
        "gid": 0,
        "filename": "/bin/ls",
        "dst_addr": {"ip": "192.168.1.1", "port": 8080}
    }

    返回格式:
    {
        "anomaly": { ... },  # 检测到的异常，如果没有则为 null
        "processed": true
    }
    """
    if ai_detector is None:
        return jsonify({'error': 'AI detector not initialized'}), 503

    try:
        event = request.json
        if not event:
            return jsonify({'error': 'Invalid request body'}), 400

        # 将事件添加到缓冲区
        events_buffer.append(event)
        if len(events_buffer) > buffer_max_size:
            events_buffer.pop(0)

        # 执行异常检测
        anomaly = ai_detector.process_event(event)

        result = {
            'processed': True
        }

        if anomaly:
            result['anomaly'] = anomaly_to_dict(anomaly)
            # 如果检测到异常，创建告警
            _add_alert_from_anomaly(anomaly)

        return jsonify(result)

    except Exception as e:
        app.logger.error(f"Error in detect_anomaly: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/baselines/update', methods=['POST'])
def update_baselines():
    """更新 AI 检测器的基线数据"""
    if ai_detector is None:
        return jsonify({'error': 'AI detector not initialized'}), 503

    try:
        ai_detector.update_baselines()
        return jsonify({
            'status': 'success',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        app.logger.error(f"Error in update_baselines: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/anomalies', methods=['GET'])
def get_anomalies():
    """
    获取 AI 检测到的异常列表

    参数:
        limit: 限制返回数量（默认 100）
        severity: 过滤严重级别（可选）
        type: 过滤异常类型（可选）
    """
    if ai_detector is None:
        return jsonify({'error': 'AI detector not initialized'}), 503

    try:
        limit = request.args.get('limit', 100, type=int)
        limit = min(max(limit, 1), 1000)

        severity_filter = request.args.get('severity')
        type_filter = request.args.get('type')

        anomalies = ai_detector.get_recent_anomalies(limit)

        # 应用过滤器
        if severity_filter:
            anomalies = [a for a in anomalies if a.severity.value == severity_filter]
        if type_filter:
            anomalies = [a for a in anomalies if a.anomaly_type.value == type_filter]

        return jsonify({
            'anomalies': [anomaly_to_dict(a) for a in anomalies],
            'count': len(anomalies)
        })

    except Exception as e:
        app.logger.error(f"Error in get_anomalies: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/clear', methods=['POST'])
def clear_old_stats():
    """清理旧的统计数据"""
    if ai_detector is None:
        return jsonify({'error': 'AI detector not initialized'}), 503

    try:
        ai_detector.clear_old_statistics()
        return jsonify({
            'status': 'success',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        app.logger.error(f"Error in clear_old_stats: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/generate', methods=['GET'])
def generate_report():
    """
    生成安全报告

    参数:
        format: 报告格式 (json/csv/html，默认 json)
    """
    if report_generator is None:
        return jsonify({'error': 'Report generator not initialized'}), 503

    try:
        format_type = request.args.get('format', 'json')

        # 从缓冲区获取数据
        events = events_buffer[-report_generator.config.max_events:]
        alerts = alerts_buffer[-report_generator.config.max_alerts:]
        # 从 AI 检测器获取异常
        anomalies = [anomaly_to_dict(a)
                   for a in ai_detector.get_recent_anomalies(500)]
        chains = attack_chains_buffer

        # 生成报告
        report_data = report_generator.generate_report(
            events=events,
            alerts=alerts,
            anomalies=anomalies,
            attack_chains=chains,
            format=format_type
        )

        # 确定内容类型
        content_types = {
            'json': 'application/json',
            'csv': 'text/csv; charset=utf-8-sig',
            'html': 'text/html; charset=utf-8'
        }
        content_type = content_types.get(format_type, 'application/json')

        return Response(
            report_data,
            mimetype=content_type,
            headers={
                'Content-Disposition': f'attachment; filename="security_report_{datetime.now().strftime("%Y%m%d")}.{format_type}"'
            }
        )

    except Exception as e:
        app.logger.error(f"Error in generate_report: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/stats', methods=['GET'])
def get_report_stats():
    """获取可用于报告的统计数据"""
    return jsonify({
        'events_count': len(events_buffer),
        'alerts_count': len(alerts_buffer),
        'anomalies_count': len(ai_detector.get_recent_anomalies(1000)) if ai_detector else 0,
        'chains_count': len(attack_chains_buffer)
    })


@app.route('/api/data/events', methods=['POST'])
def receive_events():
    """
    接收批量事件数据（用于填充报告数据）

    请求体格式:
    {
        "events": [ ... ],  # 事件列表
        "alerts": [ ... ],  # 告警列表（可选）
        "chains": [ ... ]    # 攻击链列表（可选）
    }
    """
    try:
        data = request.json

        # 处理事件
        if 'events' in data:
            new_events = data['events']
            events_buffer.extend(new_events)

        # 处理告警
        if 'alerts' in data:
            alerts_buffer.extend(data['alerts'])

        # 处理攻击链
        if 'chains' in data:
            attack_chains_buffer.extend(data['chains'])

        # 限制缓冲区大小
        _trim_buffers()

        return jsonify({
            'status': 'success',
            'events_received': len(data.get('events', [])),
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        app.logger.error(f"Error in receive_events: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/data/clear', methods=['POST'])
def clear_data():
    """清空数据缓冲区"""
    global events_buffer, alerts_buffer, attack_chains_buffer
    events_buffer.clear()
    alerts_buffer.clear()
    attack_chains_buffer.clear()

    # 同时清理 AI 检测器的统计
    if ai_detector:
        ai_detector.clear_old_statistics(timedelta(hours=0))  # 立即清理

    return jsonify({'status': 'success'})


def _add_alert_from_anomaly(anomaly):
    """从异常创建告警并添加到缓冲区"""
    alert = {
        'rule_name': 'AI异常检测',
        'description': anomaly.description,
        'severity': anomaly.severity.value,
        'category': anomaly.category,
        'timestamp': anomaly.detected_at.isoformat(),
        'pid': anomaly.pid,
        'process_name': anomaly.process_name,
        'status': 'active'
    }
    alerts_buffer.append(alert)

    if len(alerts_buffer) > buffer_max_size:
        alerts_buffer.pop(0)


def _trim_buffers():
    """修剪缓冲区到最大大小"""
    global events_buffer, alerts_buffer, attack_chains_buffer

    if len(events_buffer) > buffer_max_size:
        events_buffer = events_buffer[-buffer_max_size:]

    if len(alerts_buffer) > buffer_max_size:
        alerts_buffer = alerts_buffer[-buffer_max_size:]

    if len(attack_chains_buffer) > buffer_max_size:
        attack_chains_buffer = attack_chains_buffer[-buffer_max_size:]


def init_services():
    """初始化服务"""
    global ai_detector, report_generator

    # 初始化 AI 检测器
    config = AIDetectorConfig()
    ai_detector = AIDetector(config)
    print(f"[+] AI 检测器已初始化")

    # 初始化报告生成器
    report_config = ReportGeneratorConfig()
    report_generator = ReportGenerator(report_config)
    print(f"[+] 报告生成器已初始化")


if __name__ == '__main__':
    init_services()

    # 从环境变量获取端口
    port = int(os.environ.get('PYTHON_SERVICE_PORT', 9900))
    # 从环境变量获取监听地址，默认为所有接口
    host = os.environ.get('PYTHON_SERVICE_HOST', '0.0.0.0')

    print(f"[*] Python 服务启动在 {host}:{port}")
    # 监听所有接口，允许外部访问
    app.run(host=host, port=port, debug=False, threaded=True)
