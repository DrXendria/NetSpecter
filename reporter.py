#!/usr/bin/env python3
"""Rapor Modülü"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from config import CONFIG

logger = logging.getLogger(__name__)


class ReportGenerator:

    def __init__(self):
        self.dir        = Path(CONFIG['reports']['output_dir'])
        self.start_time = datetime.now()
        self.dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, stats: dict):
        ts   = datetime.now()
        path = self.dir / f"report_{ts.strftime('%Y%m%d_%H%M%S')}.json"
        data = {
            'timestamp':       ts.isoformat(),
            'uptime_hours':    (ts - self.start_time).total_seconds() / 3600,
            'stats':           stats,
        }
        try:
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        except Exception as e:
            logger.error(f"Rapor yazılamadı: {e}")
            return

        # Konsol özeti
        logger.info("─" * 55)
        logger.info(f"  RAPOR  {ts.strftime('%H:%M:%S')}")
        logger.info(f"  Toplam alert      : {stats.get('total_alerts', 0)}")
        logger.info(f"  Engellenen IP     : {stats.get('total_blocked', 0)}")
        logger.info(f"  Şu an engelli     : {stats.get('currently_blocked', 0)}")
        logger.info(f"  Kalıcı engel      : {stats.get('permanent_blocks', 0)}")
        for k, v in sorted(stats.get('attack_types', {}).items(),
                            key=lambda x: -x[1]):
            logger.info(f"    {k:<28} {v}")
        logger.info("─" * 55)
