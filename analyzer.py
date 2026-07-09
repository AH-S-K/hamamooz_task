# analyzer.py
from collections import Counter
from datetime import datetime


def detect_brute_force(login_failures: Counter, top_n: int = 5, min_hits: int = 5) -> list:
    """
    استخراج آی‌پی‌های مشکوک به حملات Brute-force روی مسیر لاگین.
    ابتدا N آی‌پی پرخطر استخراج شده و سپس فیلتر آستانه (Threshold) روی آن‌ها اعمال می‌شود.
    """
    top_suspects = login_failures.most_common(top_n)
    return [(ip, count) for ip, count in top_suspects if count >= min_hits]


def parse_log_time(time_str: str) -> datetime:
    """
    تبدیل رشته زمان به آبجکت datetime.
    در صورت نامعتبر بودن فرمت، یک زمان پیش‌فرض (min) برمی‌گرداند تا منطق محاسبه اختلاف زمانی مختل نشود.
    """
    try:
        return datetime.strptime(time_str, "%d/%b/%Y:%H:%M")
    except ValueError:
        return datetime.min


def detect_5xx_spike(minute_distribution: Counter, minute_5xx_counts: Counter,
                     min_delta: float = 10.0, min_traffic_gate: int = 10) -> list:
    """
    تشخیص جهش‌های ناگهانی (Spikes) در خطاهای 5xx.
    این تابع با بررسی کرونولوژیک (ترتیب زمانی) و در نظر گرفتن گپ‌های زمانی،
    دقایقی که نرخ خطا نسبت به دقیقه قبل افزایش چشمگیری داشته را پیدا می‌کند.
    """
    detected_spikes = []

    if not minute_distribution:
        return []

    # کَش کردن تبدیل رشته به datetime برای جلوگیری از پردازش تکراری
    dt_cache = {m: parse_log_time(m) for m in minute_distribution.keys()}

    # مرتب‌سازی کلیدها بر اساس زمان
    sorted_minutes = sorted(dt_cache.keys(), key=lambda k: dt_cache[k])

    # محاسبه نرخ خطای هر دقیقه
    minute_rates = {}
    for m in sorted_minutes:
        total_m = minute_distribution[m]
        errors_m = minute_5xx_counts[m]
        minute_rates[m] = (errors_m / total_m * 100) if total_m > 0 else 0.0

    for i in range(1, len(sorted_minutes)):
        current_min = sorted_minutes[i]
        prev_min = sorted_minutes[i - 1]

        current_rate = minute_rates[current_min]

        # سنجش مستقیم نسبت به آخرین وضعیت فعال بدون در نظر گرفتن گپ زمانی
        prev_rate = minute_rates[prev_min]

        total_requests_current = minute_distribution[current_min]
        delta = current_rate - prev_rate

        if delta >= min_delta and total_requests_current >= min_traffic_gate:
            detected_spikes.append({
                "minute": current_min,
                "rate_jump": delta,
                "current_rate": current_rate,
                "previous_rate": prev_rate,
                "count": minute_5xx_counts[current_min],
                "total_volume": total_requests_current
            })

    # مرتب‌سازی بر اساس شدت جهش خطا (نزولی)
    detected_spikes.sort(key=lambda x: x["rate_jump"], reverse=True)
    return detected_spikes