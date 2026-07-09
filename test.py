# test.py
import unittest
from collections import Counter
from parser import parse_log_line
from analyzer import detect_brute_force, detect_5xx_spike, parse_log_time
from datetime import datetime


class TestLogParser(unittest.TestCase):
    """تست‌های مربوط به موتور تجزیه (پارس) لاگ‌ها"""

    def test_parse_valid_line(self):
        # بررسی یک خط لاگ کاملا سالم
        line = '203.0.113.42 - - [01/Jun/2026:09:14:22 +0000] "GET /products/1877 HTTP/1.1" 200 5324 "-" "Mozilla/5.0"'
        result = parse_log_line(line)

        self.assertIsNotNone(result)
        self.assertEqual(result["ip"], "203.0.113.42")
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["path"], "/products/1877")
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["bytes"], 5324)
        self.assertEqual(result["hour"], "09")
        self.assertEqual(result["minute_window"], "01/Jun/2026:09:14")

    def test_parse_malformed_line(self):
        # بررسی مقاومت در برابر خطوط خراب (نباید کرش کند)
        bad_line_1 = 'this is a corrupted log line with no valid structure'
        bad_line_2 = '192.168.1.1 - - [01/Jun/2026:09:14:22 +0000] "GET / HTTP/1.1" 200'  # ناقص

        self.assertIsNone(parse_log_line(bad_line_1))
        self.assertIsNone(parse_log_line(bad_line_2))

    def test_query_string_stripping(self):
        # بررسی حذف خودکار پارامترهای اضافی (Query String) از مسیر
        line = '10.0.0.1 - - [01/Jun/2026:10:00:00 +0000] "POST /api/login?user=admin&try=1 HTTP/1.1" 401 120 "-" "-"'
        result = parse_log_line(line)

        self.assertIsNotNone(result)
        self.assertEqual(result["path"], "/api/login")
        self.assertEqual(result["status"], 401)


class TestTrafficAnalyzer(unittest.TestCase):
    """تست‌های مربوط به ماژول تحلیلگر امنیتی و زیرساختی"""

    def test_detect_brute_force(self):
        # شبیه‌سازی تلاش‌های ناموفق لاگین
        login_failures = Counter({
            "192.168.1.10": 15,  # بالاتر از آستانه (مشکوک)
            "10.0.0.5": 4,  # پایین‌تر از آستانه (عادی)
            "172.16.0.2": 8  # بالاتر از آستانه (مشکوک)
        })

        # اجرای تابع با آستانه ۵ خطا
        suspects = detect_brute_force(login_failures, top_n=5, min_hits=5)

        # بررسی خروجی: باید فقط ۲ آی‌پی مشکوک برگرداند و به ترتیب نزولی باشد
        self.assertEqual(len(suspects), 2)
        self.assertEqual(suspects[0][0], "192.168.1.10")
        self.assertEqual(suspects[0][1], 15)
        self.assertEqual(suspects[1][0], "172.16.0.2")

    def test_detect_5xx_spike(self):
        # شبیه‌سازی توزیع ترافیک در ۳ دقیقه متوالی
        minute_distribution = Counter({
            "01/Jun/2026:10:00": 100,  # دقیقه اول: ترافیک عادی
            "01/Jun/2026:10:01": 100,  # دقیقه دوم: جهش خطا
            "01/Jun/2026:10:02": 8  # دقیقه سوم: ترافیک بسیار کم (زیر آستانه بررسی)
        })

        # شبیه‌سازی تعداد خطاهای 5xx در همان دقایق
        minute_5xx_counts = Counter({
            "01/Jun/2026:10:00": 2,  # نرخ خطا: ۲٪
            "01/Jun/2026:10:01": 35,  # نرخ خطا: ۳۵٪ (جهش ۳۳ درصدی)
            "01/Jun/2026:10:02": 4  # نرخ خطا: ۵۰٪ (اما ترافیک کل کمتر از ۱۰ است)
        })

        # اجرای تابع تشخیص جهش با حداقل پرش ۱۰ درصد و ترافیک پایه ۱۰ رکورد
        spikes = detect_5xx_spike(
            minute_distribution,
            minute_5xx_counts,
            min_delta=10.0,
            min_traffic_gate=10
        )

        # بررسی خروجی
        self.assertEqual(len(spikes), 1, "فقط باید یک جهش معتبر تشخیص داده شود")
        spike = spikes[0]

        self.assertEqual(spike["minute"], "01/Jun/2026:10:01")
        self.assertAlmostEqual(spike["previous_rate"], 2.0)
        self.assertAlmostEqual(spike["current_rate"], 35.0)
        self.assertAlmostEqual(spike["rate_jump"], 33.0)
        self.assertEqual(spike["count"], 35)

    def test_parse_log_time_valid(self):
        time_str = "01/Jun/2026:09:14"
        dt = parse_log_time(time_str)
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 6)
        self.assertEqual(dt.hour, 9)
        self.assertEqual(dt.minute, 14)

    def test_parse_log_time_invalid(self):
        # در صورت فرمت اشتباه باید datetime.min برگرداند تا منطق کرش نکند
        dt = parse_log_time("invalid_date_format")
        self.assertEqual(dt, datetime.min)


if __name__ == "__main__":
    unittest.main(verbosity=2)