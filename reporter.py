#!/usr/bin/env python3
"""
NetSpecter — Gelişmiş PDF Raporlama Modülü (Türkçe Karakter Destekli)
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from config import CONFIG

# ReportLab bileşenleri
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        self.dir = Path(CONFIG['reports']['output_dir'])
        self.dir.mkdir(parents=True, exist_ok=True)
        if REPORTLAB_AVAILABLE:
            self._register_fonts()
            self.styles = getSampleStyleSheet()
            self._set_font('DejaVu')

    def _set_font(self, font_name):
        """Tüm stillere Türkçe destekli fontu uygular"""
        for style in self.styles.byName.values():
            style.fontName = font_name

    def _register_fonts(self):
        """Türkçe karakterler için sistem fontlarını kaydeder"""
        font_paths = [
            '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
            '/usr/share/fonts/truetype/freefont/FreeSans.ttf',
            '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf',
            'C:\\Windows\\Fonts\\arial.ttf'
        ]
        registered = False
        for path in font_paths:
            if os.path.exists(path):
                try:
                    pdfmetrics.registerFont(TTFont('DejaVu', path))
                    registered = True
                    break
                except:
                    continue
        if not registered:
            logger.warning("Türkçe font bulunamadı.")

    def _get_filename(self, prefix: str, ext: str = "pdf") -> str:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        return str(self.dir / f"{prefix}_{ts}.{ext}")

    def generate_ip_report(self, ip: str):
        """Belirli bir IP için profesyonel saldırı analiz raporu (PDF) oluşturur"""
        if not REPORTLAB_AVAILABLE: return None

        from database import get_ip_report_data
        try:
            data = get_ip_report_data(ip)
            filename = self._get_filename(f"attack_report_{ip.replace('.','_').replace(':','_')}")
            
            # PDF Başlığını set ediyoruz (Tarayıcıda görünmesi için)
            doc_title = f"{ip} Saldırı Raporu"
            doc = SimpleDocTemplate(filename, pagesize=A4, title=doc_title, author="NetSpecter")
            elements = []
            font_name = 'DejaVu' if pdfmetrics.getRegisteredFontNames() else 'Helvetica'

            # Başlık
            elements.append(Paragraph(f"NetSpecter Güvenlik Analiz Raporu", self.styles['Title']))
            elements.append(Paragraph(f"Saldırgan IP: {ip}", self.styles['Heading2']))
            elements.append(Spacer(1, 12))

            # Özet Bilgiler (Hata düzeltildi: total_alerts -> len(data['alerts']))
            summary_text = (
                f"<b>Rapor Tarihi:</b> {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}<br/>"
                f"<b>Toplam Saldırı Girişimi:</b> {len(data['alerts'])}<br/>"
                f"<b>Toplam Engellenme Sayısı:</b> {data['violation_count']}<br/>"
            )
            elements.append(Paragraph(summary_text, self.styles['Normal']))
            elements.append(Spacer(1, 20))

            # Alert Tablosu
            elements.append(Paragraph("Son Saldırı Girişimleri (Detay)", self.styles['Heading3']))
            table_data = [["Zaman", "Saldırı Tipi", "Hedef Port", "Önem"]]
            for a in data['alerts'][:40]:
                table_data.append([
                    str(a['created_at'])[5:19],
                    a['attack_type'],
                    str(a['dest_port']),
                    f"Sev {a['severity']}"
                ])

            if len(table_data) > 1:
                t = Table(table_data, colWidths=[120, 150, 80, 80])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                    ('FONTNAME', (0, 0), (-1, -1), font_name),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                ]))
                elements.append(t)
            else:
                elements.append(Paragraph("Kayıtlı alert bulunamadı.", self.styles['Normal']))
            
            doc.build(elements)
            return filename
        except Exception as e:
            logger.error(f"IP Rapor hatası: {e}")
            return None

    def generate_daily_report(self):
        """Tüm sistem için son 24 saatlik özet raporu (PDF) oluşturur"""
        if not REPORTLAB_AVAILABLE: return None

        from database import get_daily_report_data
        try:
            data = get_daily_report_data()
            filename = self._get_filename("daily_security_summary")
            
            # PDF Başlığını set ediyoruz
            current_date = datetime.now().strftime('%d.%m.%Y')
            doc_title = f"{current_date} Günlük Güvenlik Özeti"
            doc = SimpleDocTemplate(filename, pagesize=A4, title=doc_title, author="NetSpecter")
            elements = []
            font_name = 'DejaVu' if pdfmetrics.getRegisteredFontNames() else 'Helvetica'

            elements.append(Paragraph("NetSpecter Günlük Güvenlik Özeti", self.styles['Title']))
            elements.append(Paragraph(f"Tarih: {current_date}", self.styles['Heading2']))
            elements.append(Spacer(1, 12))

            # Genel İstatistikler
            stats_text = (
                f"<b>Son 24 Saatte Toplam Alert:</b> {data['alerts_count']}<br/>"
                f"<b>Yeni Engellenen IP Sayısı:</b> {data['blocked_today']}<br/>"
            )
            elements.append(Paragraph(stats_text, self.styles['Normal']))
            elements.append(Spacer(1, 12))

            # En Çok Saldıran IP'ler Tablosu
            elements.append(Paragraph("En Çok Saldıran IP Adresleri", self.styles['Heading3']))
            top_ips_table = [["Kaynak IP", "Saldırı Sayısı"]]
            for item in data['top_ips']:
                top_ips_table.append([str(item['src_ip']), str(item['cnt'])])
            
            if len(top_ips_table) > 1:
                t1 = Table(top_ips_table, colWidths=[200, 100])
                t1.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, -1), font_name),
                ]))
                elements.append(t1)
            else:
                elements.append(Paragraph("Son 24 saatte saldırı tespit edilmedi.", self.styles['Normal']))
            
            doc.build(elements)
            return filename
        except Exception as e:
            logger.error(f"Günlük Rapor hatası: {e}")
            return None

    def generate_json_report(self, stats: dict):
        path = self._get_filename("periodic_report", "json")
        try:
            with open(path, 'w') as f:
                json.dump({'timestamp': datetime.now().isoformat(), 'stats': stats}, f, indent=2)
            return path
        except Exception as e:
            logger.error(f"JSON Rapor hatası: {e}")
            return None

    def generate_report(self, stats: dict):
        """Periyodik / kapanış raporu (ids_ips.py tarafından çağrılır)."""
        path = self.generate_json_report(stats)
        if path:
            logger.info(f"Periyodik rapor oluşturuldu: {path}")
        return path
