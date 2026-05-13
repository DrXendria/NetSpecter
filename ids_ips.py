#!/usr/bin/env python3
"""
Raspberry Pi IDS/IPS Sistemi — Ana Modül (Düzeltilmiş)
Suricata'yı daemon değil, doğrudan subprocess olarak başlatır.
"""

import os
import sys
import time
import signal
import logging
import subprocess
import threading
from datetime import datetime
from pathlib import Path

from blocker  import IPBlocker
from monitor  import AlertMonitor
from reporter import ReportGenerator
from config   import CONFIG

# ── Logging ────────────────────────────────────────────────────────────
os.makedirs('/var/log/netspecter', exist_ok=True)
logging.basicConfig(
    level   = logging.INFO,
    format  = '%(asctime)s [%(levelname)s] %(message)s',
    handlers= [
        logging.FileHandler('/var/log/netspecter/system.log'),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger(__name__)


class IDSIPSSystem:

    def __init__(self):
        self.suricata_proc = None
        self.running       = False
        self.blocker       = IPBlocker()
        self.monitor       = AlertMonitor(self.blocker)
        self.reporter      = ReportGenerator()

        signal.signal(signal.SIGINT,  self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

        os.makedirs(CONFIG['suricata']['log_dir'], exist_ok=True)
        os.makedirs(CONFIG['reports']['output_dir'], exist_ok=True)

    # ------------------------------------------------------------------ #
    #  Suricata yönetimi                                                  #
    # ------------------------------------------------------------------ #

    def _configure_suricata(self) -> bool:
        """suricata.yaml'ı IPS/IDS için hazırla"""
        conf = Path(CONFIG['suricata']['config_path'])
        if not conf.exists():
            logger.error(f"suricata.yaml bulunamadı: {conf}")
            return False

        text = conf.read_text()

        # eve-log satırını etkinleştir (varsa yoruma alınmışsa aç)
        if 'eve-log' not in text:
            logger.warning("suricata.yaml'da eve-log bulunamadı; "
                           "lütfen elle kontrol edin.")

        logger.info(f"Suricata config: {conf}")
        logger.info(f"Ağ arayüzü: {CONFIG['suricata']['interface']}")
        return True

    def start_suricata(self) -> bool:
        """Suricata'yı foreground subprocess olarak başlat"""
        logger.info("Suricata başlatılıyor...")

        if not self._configure_suricata():
            return False

        # Önceki instance'ı öldür ve PID/socket dosyalarını temizle
        subprocess.run(['pkill', '-f', 'suricata'], capture_output=True)
        time.sleep(2)
        for f in ['/var/run/suricata.pid', '/var/run/suricata-command.socket']:
            try:
                os.remove(f)
            except FileNotFoundError:
                pass

        cmd = [
            'suricata',
            '-c', CONFIG['suricata']['config_path'],
            '-i', CONFIG['suricata']['interface'],
            '--pidfile', '/var/run/suricata.pid',
        ]

        try:
            self.suricata_proc = subprocess.Popen(
                cmd,
                stdout = subprocess.PIPE,
                stderr = subprocess.STDOUT,   # stderr'i stdout'a yönlendir
                text   = True,
                bufsize= 1,
            )
        except FileNotFoundError:
            logger.error("Suricata bulunamadı!  →  sudo apt install suricata")
            return False

        # Suricata hazır olana kadar bekle (max 15 sn)
        ready = False
        for _ in range(15):
            if self.suricata_proc.poll() is not None:
                # Process erken öldü
                out, _ = self.suricata_proc.communicate()
                logger.error(f"Suricata hemen kapandı:\n{out}")
                return False
            if os.path.exists(CONFIG['suricata']['eve_log']):
                ready = True
                break
            time.sleep(1)
            logger.debug("Suricata başlaması bekleniyor...")

        if not ready:
            logger.warning("Eve.json henüz oluşmadı ama Suricata çalışıyor, devam ediliyor.")

        logger.info(f"Suricata çalışıyor. PID={self.suricata_proc.pid}")

        # Suricata çıktısını arka planda logla
        t = threading.Thread(target=self._log_suricata_output, daemon=True)
        t.start()

        return True

    def _log_suricata_output(self):
        """Suricata stdout/stderr'ini sistem loguna aktar"""
        for line in self.suricata_proc.stdout:
            line = line.strip()
            if line:
                logger.debug(f"[SURICATA] {line}")

    def stop_suricata(self):
        if self.suricata_proc and self.suricata_proc.poll() is None:
            logger.info("Suricata durduruluyor...")
            self.suricata_proc.terminate()
            try:
                self.suricata_proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.suricata_proc.kill()
            logger.info("Suricata durduruldu.")

    def _watchdog(self):
        """Suricata çöktüğünde yeniden başlat"""
        while self.running:
            time.sleep(10)
            if self.suricata_proc and self.suricata_proc.poll() is not None:
                logger.error("Suricata beklenmedik biçimde kapandı, yeniden başlatılıyor...")
                self.start_suricata()

    # ------------------------------------------------------------------ #
    #  Periyodik görevler                                                 #
    # ------------------------------------------------------------------ #

    def _periodic(self, interval: int, fn, name: str):
        while self.running:
            time.sleep(interval)
            if self.running:
                try:
                    fn()
                except Exception as e:
                    logger.error(f"{name} hatası: {e}")

    def _update_rules(self):
        logger.info("Suricata kuralları güncelleniyor...")
        r = subprocess.run(['suricata-update'], capture_output=True, text=True, timeout=120)
        if r.returncode == 0:
            subprocess.run(['pkill', '-USR2', '-f', 'suricata'], capture_output=True)
            logger.info("Kurallar güncellendi.")
        else:
            logger.warning(f"Kural güncelleme uyarısı: {r.stderr[:200]}")

    # ------------------------------------------------------------------ #
    #  Kapatma                                                            #
    # ------------------------------------------------------------------ #

    def _shutdown(self, *_):
        logger.info("Sistem kapatılıyor...")
        self.running = False
        self.stop_suricata()
        self.reporter.generate_report(self.blocker.get_stats())
        logger.info("IDS/IPS sistemi kapatıldı.")
        sys.exit(0)

    # ------------------------------------------------------------------ #
    #  Ana giriş                                                          #
    # ------------------------------------------------------------------ #

    def run(self):
        logger.info("=" * 60)
        logger.info("  NetSpecter IDS/IPS Sistemi  v2.0")
        logger.info("=" * 60)
        logger.info(f"  Arayüz : {CONFIG['suricata']['interface']}")
        logger.info(f"  Eve log: {CONFIG['suricata']['eve_log']}")
        logger.info(f"  IPS mod: {CONFIG['blocking']['enabled']}")
        logger.info("=" * 60)

        # 1. iptables kur
        if not self.blocker.setup_initial_rules():
            logger.error("iptables kurulamadı, çıkılıyor.")
            sys.exit(1)

        # 2. Suricata başlat
        if not self.start_suricata():
            logger.error("Suricata başlatılamadı, çıkılıyor.")
            sys.exit(1)

        self.running = True

        # 3. Arka plan thread'leri
        threads = [
            (CONFIG['rule_update_interval'], self._update_rules,   "Kural güncelleme"),
            (CONFIG['report_interval'],      lambda: self.reporter.generate_report(
                                                 self.blocker.get_stats()), "Rapor"),
            (CONFIG['cleanup_interval'],     self.blocker.cleanup_expired_blocks, "Temizlik"),
        ]
        for interval, fn, name in threads:
            t = threading.Thread(target=self._periodic, args=(interval, fn, name), daemon=True)
            t.start()

        # Suricata watchdog
        threading.Thread(target=self._watchdog, daemon=True).start()

        logger.info("Sistem aktif. Çıkmak için CTRL+C\n")

        # 4. Ana döngü: eve.json izle (blocking call)
        self.monitor.watch_eve_log(CONFIG['suricata']['eve_log'])


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("Root yetkileri gerekli:  sudo python3 ids_ips.py")
        sys.exit(1)

    IDSIPSSystem().run()
