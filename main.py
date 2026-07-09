# main.py
import argparse
import gzip
import os
import sys
import time
from collections import Counter
from parser import parse_log_line


def print_dashboard(total_lines, total_valid, malformed_lines, unique_ips,
                    errors_4xx, errors_5xx, error_rate, top_endpoints,
                    hourly_distribution, execution_time):
    """
    رندر کردن داشبورد نهایی در ترمینال با جداول خوانا و هیستوگرام متنی پویا.
    """
    os.system('')  # فعال‌سازی پشتیبانی از رنگ‌های ANSI در ترمینال ویندوز

    print("\n" + "=" * 65)
    print(" 📊 LOGSPHERE METRICS DASHBOARD ".center(65, "="))
    print("=" * 65)

    # ۱. جدول گزارش پایه (Core Metrics)
    print(f"  📌 General Summary:")
    print(f"    ├── Total Lines Read:          {total_lines:,}")
    print(f"    ├── Valid Requests Processed:  {total_valid:,}")
    print(f"    └── Malformed/Skipped Lines:   {malformed_lines:,}")
    print(f"  📌 Traffic Overview:")
    print(f"    ├── Unique Client IPs:         {len(unique_ips):,}")
    print(f"    ├── HTTP 4xx Client Errors:    {errors_4xx:,}")
    print(f"    ├── HTTP 5xx Server Errors:    {errors_5xx:,}")
    print(f"    └── Overall Error Rate:        {error_rate:.2f}%")

    # ۲. جدول ۱۰ آدرس پرترافیک (Top 10 Endpoints)
    print("\n" + "-" * 65)
    print(f" 📈 TOP 10 MOST VISITED ENDPOINTS ".center(65, "-"))
    print("-" * 65)
    print(f"  {'#':<3} | {'Endpoint Path':<42} | {'Hits':<12}")
    print("  " + "-" * 61)

    for idx, (path, count) in enumerate(top_endpoints.most_common(10), 1):
        # کوتاه کردن مسیرهای خیلی طولانی برای خراب نشدن استایل جدول
        display_path = path if len(path) <= 40 else path[:37] + "..."
        print(f"  {idx:<3} | {display_path:<42} | {count:<12,}")
    print("-" * 65)

    # ۳. هیستوگرام توزیع زمانی ۲۴ ساعته (Hourly Distribution Histogram)
    print("\n" + "-" * 65)
    print(" 🕒 24-HOUR TRAFFIC DISTRIBUTION ".center(65, "-"))
    print("-" * 65)

    max_traffic_hour = max(hourly_distribution.values()) if hourly_distribution else 0
    max_bar_length = 35  # حداکثر طول میله اسکی برای جا شدن در انواع ترمینال

    for hour in sorted(hourly_distribution.keys()):
        count = hourly_distribution[hour]

        # محاسبه طول میله به صورت نسبی (نسبت به شلوغ‌ترین ساعت روز)
        if max_traffic_hour > 0:
            bar_length = int((count / max_traffic_hour) * max_bar_length)
        else:
            bar_length = 0

        bar = "█" * bar_length
        print(f"  {hour}:00 | {count:7,} hits | {bar}")

    print("-" * 65)
    print(f"✨ Analysis completed in {execution_time:.2f} seconds.")
    print("=" * 65 + "\n")


def main():
    # تنظیم آرگومان‌های خط فرمان با argparse
    parser = argparse.ArgumentParser(
        description="LogSphere: A high-performance CLI tool for analyzing access log files."
    )
    parser.add_argument(
        "logfile",
        type=str,
        help="Path to the access log file (supports standard text logs or .gz compressed files)"
    )

    args = parser.parse_args()
    log_path = args.logfile

    # اعتبارسنجی وجود و صحت مسیر فایل روی دیسک
    if not os.path.exists(log_path) or not os.path.isfile(log_path):
        print(f"❌ Error: The file '{log_path}' is invalid or does not exist.", file=sys.stderr)
        sys.exit(1)

    is_gzip = log_path.endswith('.gz')
    open_func = gzip.open if is_gzip else open
    file_mode = 'rt' if is_gzip else 'r'

    print(f"[*] Starting analysis on: {os.path.basename(log_path)}")
    print("⏳ Processing log stream, please wait...")

    start_time = time.time()
    total_lines = 0
    malformed_lines = 0

    # ساختارهای داده متمرکز برای تجمیع اطلاعات آماری
    total_valid = 0
    errors_4xx = 0
    errors_5xx = 0
    unique_ips = set()
    top_endpoints = Counter()
    hourly_distribution = {f"{i:02d}": 0 for i in range(24)}

    try:
        with open_func(log_path, file_mode, encoding='utf-8', errors='replace') as file:
            for line in file:
                total_lines += 1

                parsed_data = parse_log_line(line)
                if parsed_data is None:
                    malformed_lines += 1
                    continue

                total_valid += 1
                unique_ips.add(parsed_data["ip"])
                top_endpoints[parsed_data["path"]] += 1

                status = parsed_data["status"]
                if 400 <= status < 500:
                    errors_4xx += 1
                elif 500 <= status < 600:
                    errors_5xx += 1

                hourly_distribution[parsed_data["hour"]] += 1

    except KeyboardInterrupt:
        print("\n🛑 Operation cancelled by user.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

    execution_time = time.time() - start_time

    # محاسبه نرخ نهایی خطا
    total_errors = errors_4xx + errors_5xx
    error_rate = (total_errors / total_valid * 100) if total_valid > 0 else 0.0

    # رندر کردن داشبورد نهایی زیبا
    print_dashboard(
        total_lines, total_valid, malformed_lines, unique_ips,
        errors_4xx, errors_5xx, error_rate, top_endpoints,
        hourly_distribution, execution_time
    )


if __name__ == "__main__":
    main()