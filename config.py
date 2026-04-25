#!/usr/bin/env python3
"""
NetSpecter — Sistem Konfigürasyonu
"""
CONFIG = {
    'suricata': {
        'config_path': '/etc/suricata/suricata.yaml',
        'eve_log':     '/var/log/suricata/eve.json',
        'log_dir':     '/var/log/suricata',
        'interface':   'wlan0',
    },
    'blocking': {
        'enabled': True,
        'block_duration': 3600,
        'whitelist': [
            '127.0.0.1',
            '::1',
        ],
    },
    'rule_update_interval': 86400,
    'report_interval':       3600,
    'cleanup_interval':        60,
    'reports': {
        'output_dir': '/var/log/netspecter/reports',
    },
}
