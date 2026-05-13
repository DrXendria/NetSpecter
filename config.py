#!/usr/bin/env python3
"""
NetSpecter — Sistem Konfigürasyonu
"""

CONFIG = {
    'suricata': {
        'config_path': '/etc/suricata/suricata.yaml',
        'eve_log':     '/var/log/suricata/eve.json',
        'log_dir':     '/var/log/suricata',
        'interface':   'wlan0',   # eth0 veya wlan0 — ağ arayüzünüze göre değiştirin
    },

    'blocking': {
        'enabled': True,
        'block_duration': 3600,             # 1 saat (saniye)
        'permanent_block_threshold': 5,     # 5 ihlal → kalıcı engel
        'whitelist': [
            '127.0.0.1',
            '::1',
            # Kendi IP'nizi buraya ekleyin: '192.168.1.x'
        ],
    },

    'thresholds': {
        'port_scan':   {'max_ports': 15, 'time_window': 10},
        'brute_force': {'max_attempts': 5,  'time_window': 60},
        'dos':         {'max_packets': 500, 'time_window': 5},
    },

    # Suricata severity → aksiyon
    'severity_action': {
        1: 'block',
        2: 'block',
        3: 'log',
        4: 'log',
    },

    'rule_update_interval': 86400,   # 24 saat
    'report_interval':       3600,   # 1 saat
    'cleanup_interval':        60,   # 1 dakika

    'reports': {
        'output_dir': '/var/log/netspecter/reports',
    },
}
