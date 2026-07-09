# main.py
import argparse
import gzip
import tarfile
import io
import json
import os
import sys
import time
from collections import Counter
from parser import parse_log_line
from analyzer import detect_brute_force, detect_5xx_spike


def print_dashboard(total_lines, total_valid, malformed_lines, unique_ips_count,
                    errors_4xx, errors_5xx, error_rate, top_endpoints,
                    hourly_distribution, top_login_failures, detected_spikes, execution_time):
    """
    نمایش داشبورد متنی شامل خلاصه‌ی ترافیک، توزیع زمانی، کدهای وضعیت و آنومالی‌های امنیتی.
    """
    os.system('')  # فعال‌سازی پشتیبانی از رنگ‌های ANSI در ترمینال ویندوز

    CLR_RESET = "\033[0m"
    CLR_RED = "\033[91m"
    CLR_YELLOW = "\033[93m"
    CLR_CYAN = "\033[96m"

    # محاسبه امن درصدها برای جلوگیری از ZeroDivisionError
    pct_4xx = (errors_4xx / total_valid * 100) if total_valid > 0 else 0.0
    pct_5xx = (errors_5xx / total_valid * 100) if total_valid > 0 else 0.0

    print("\n" + "=" * 65)
    print(" 📊 LOGSPHERE ADVANCED METRICS DASHBOARD ".center(65, "="))
    print("=" * 65)

    # ۱. جدول گزارش پایه (Core Metrics)
    print(f"  -- General Summary:")
    print(f"    ├── Total Lines Read:          {total_lines:,}")
    print(f"    ├── Valid Requests Processed:  {total_valid:,}")
    print(f"    └── Malformed/Skipped Lines:   {malformed_lines:,}")
    print(f"  -- Traffic Overview:")
    print(f"    ├── Unique Client IPs:         {unique_ips_count:,}")
    print(f"    ├── HTTP 4xx Client Errors:    {CLR_YELLOW}{errors_4xx:,} ({pct_4xx:.2f}%){CLR_RESET}")
    print(f"    ├── HTTP 5xx Server Errors:    {CLR_RED}{errors_5xx:,} ({pct_5xx:.2f}%){CLR_RESET}")
    print(f"    └── Overall Error Rate:        {CLR_CYAN}{error_rate:.2f}%{CLR_RESET}")

    # ۲. رادار امنیتی هوشمند (تشخیص Brute-Force روی /login)
    print("\n" + "-" * 65)
    print(f" 🛡️ SECURITY ANOMALIES (SUSPICIOUS LOGIN ATTEMPTS) ".center(65, "-"))
    print("-" * 65)
    if top_login_failures:
        print(f"  {'#':<3} | {'Attacker IP Address':<20} | {'Failed Logins (401/403 on /login)':<25}")
        print("  " + "-" * 61)
        for idx, (ip, bad_hits) in enumerate(top_login_failures, 1):
            print(f"  {idx:<3} | {CLR_RED}{ip:<20}{CLR_RESET} | {bad_hits:<25,}")
    else:
        print("  ✅ Nominal Status: No brute-force attempts detected on /login.")
    print("-" * 65)

    # ۳. رادار هوشمند شناسایی تمام جهش‌های خطا (Multi-Spike Radar)
    print("\n" + "-" * 65)
    print(" 🚨 DETECTED 5xx ERROR SPIKES ".center(65, "-"))
    print("-" * 65)
    if detected_spikes:
        print(f"  ⚠️  {len(detected_spikes)} ANOMALOUS JUMPS DETECTED (Sorted by Severity):")
        print("  " + "-" * 61)
        for idx, spike in enumerate(detected_spikes[:5], 1):
            print(f"  [{idx}] Minute Window: {spike['minute']} | Jump: {CLR_RED}+{spike['rate_jump']:.2f}%{CLR_RESET}")
            print(f"      ├── Error Rate: {spike['previous_rate']:.2f}% -> {spike['current_rate']:.2f}%")
            print(f"      └── Window Volume: {spike['count']:,} errors out of {spike['total_volume']:,} total hits")
            if idx < len(detected_spikes[:5]):
                print("      " + "." * 40)
    else:
        print("  ✅ Server health nominal. No 5xx error spikes observed.")
    print("-" * 65)

    # ۴. جدول ۱۰ آدرس پرترافیک
    print("\n" + "-" * 65)
    print(f" 📈 TOP 10 MOST VISITED ENDPOINTS ".center(65, "-"))
    print("-" * 65)
    print(f"  {'#':<3} | {'Endpoint Path':<42} | {'Hits':<12}")
    print("  " + "-" * 61)

    for idx, (path, count) in enumerate(top_endpoints.most_common(10), 1):
        display_path = path if len(path) <= 40 else path[:37] + "..."
        print(f"  {idx:<3} | {display_path:<42} | {count:<12,}")
    print("-" * 65)

    # ۵. هیستوگرام توزیع زمانی ۲۴ ساعته
    print("\n" + "-" * 65)
    print(" 🕒 24-HOUR TRAFFIC DISTRIBUTION ".center(65, "-"))
    print("-" * 65)

    max_traffic_hour = max(hourly_distribution.values()) if hourly_distribution else 0
    max_bar_length = 35

    for hour in sorted(hourly_distribution.keys()):
        count = hourly_distribution[hour]
        bar_length = int((count / max_traffic_hour) * max_bar_length) if max_traffic_hour > 0 else 0
        bar = "█" * bar_length
        print(f"  {hour}:00 | {count:7,} hits | {CLR_CYAN}{bar}{CLR_RESET}")

    print("-" * 65)
    print(f"[*] Analysis completed in {execution_time:.2f} seconds.")
    print("=" * 65 + "\n")


def export_to_json(export_path, total_lines, total_valid, malformed_lines, ip_counts,
                   errors_4xx, errors_5xx, error_rate, top_endpoints,
                   hourly_distribution, top_login_failures, detected_spikes):
    """
    ذخیره داده‌های غنی‌شده تحلیل در فرمت JSON.
    """
    report_data = {
        "summary": {
            "total_lines_read": total_lines,
            "valid_requests": total_valid,
            "malformed_lines_skipped": malformed_lines
        },
        "traffic": {
            "unique_ips_count": len(ip_counts),
            "http_4xx_errors": errors_4xx,
            "http_5xx_errors": errors_5xx,
            "overall_error_rate_percent": round(error_rate, 2)
        },
        "security_anomalies": {
            "brute_force_login_attempts": [
                {"ip": ip, "failed_attempts": count} for ip, count in top_login_failures
            ]
        },
        "infrastructure_health": {
            "detected_5xx_error_spikes": detected_spikes
        },
        "top_endpoints": [
            {"path": path, "hits": count} for path, count in top_endpoints.most_common(20)
        ],
        "hourly_distribution": hourly_distribution
    }

    try:
        with open(export_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
        print(f"[*] [Success] Structured JSON report exported to: {export_path}")
    except Exception as e:
        print(f"[-] Error: Failed to export JSON report: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="LogSphere: A high-performance CLI tool for analyzing access log files."
    )
    parser.add_argument(
        "logfile",
        type=str,
        help="Path to the access log file (supports standard text logs, .gz or .tar.gz compressed archives)"
    )
    parser.add_argument(
        "--export",
        type=str,
        metavar="OUTPUT_JSON_PATH",
        help="Optional: Path to export the structured analytics report as a JSON file"
    )

    args = parser.parse_args()
    log_path = args.logfile

    if not os.path.exists(log_path) or not os.path.isfile(log_path):
        print(f"[-] Error: The file '{log_path}' is invalid or does not exist.", file=sys.stderr)
        sys.exit(1)

    # تشخیص نوع فشرده‌سازی و باز کردن استریم فایل (Stream) جهت جلوگیری از بارگذاری کل فایل در رم
    is_tar_gz = log_path.endswith('.tar.gz')
    is_gzip = log_path.endswith('.gz') and not is_tar_gz

    print(f"[*] Starting analysis on: {os.path.basename(log_path)}")
    print("[*] Processing log stream and computing analytics triggers...")

    start_time = time.time()
    total_lines = 0
    malformed_lines = 0

    total_valid = 0
    errors_4xx = 0
    errors_5xx = 0

    ip_counts = Counter()
    top_endpoints = Counter()
    hourly_distribution = {f"{i:02d}": 0 for i in range(24)}


    minute_distribution = Counter()
    minute_5xx_counts = Counter()
    login_failures = Counter()

    tar_handle = None
    try:
        if is_tar_gz:
            tar_handle = tarfile.open(log_path, 'r:gz')
            members = [m for m in tar_handle.getmembers() if m.isfile()]
            if not members:
                print("[-] Error: No files found inside tar.gz archive.", file=sys.stderr)
                sys.exit(1)
            file_obj = tar_handle.extractfile(members[0])
            file = io.TextIOWrapper(file_obj, encoding='utf-8', errors='replace')
        else:
            open_func = gzip.open if is_gzip else open
            file_mode = 'rt' if is_gzip else 'r'
            file = open_func(log_path, file_mode, encoding='utf-8', errors='replace')

        with file:
            for line in file:

                line = line.strip()
                if not line:
                    continue

                total_lines += 1

                parsed_data = parse_log_line(line)
                if parsed_data is None:
                    malformed_lines += 1
                    continue

                total_valid += 1

                client_ip = parsed_data["ip"]
                path = parsed_data["path"]
                status = parsed_data["status"]
                hour = parsed_data["hour"]
                minute_window = parsed_data["minute_window"]

                ip_counts[client_ip] += 1
                top_endpoints[path] += 1
                hourly_distribution[hour] += 1
                minute_distribution[minute_window] += 1

                # شمارش خطاها و بررسی الگوهای مشکوک بر اساس کدهای وضعیت HTTP
                if 400 <= status < 500:
                    errors_4xx += 1
                    if path == "/login" and status in (401, 403):
                        login_failures[client_ip] += 1
                elif 500 <= status < 600:
                    errors_5xx += 1
                    minute_5xx_counts[minute_window] += 1

    except KeyboardInterrupt:
        print("\n[-] Operation cancelled by user.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        if tar_handle:
            tar_handle.close()

    # محاسبه نهایی آمار کل
    error_rate = ((errors_4xx + errors_5xx) / total_valid * 100) if total_valid > 0 else 0.0

    top_login_failures = detect_brute_force(login_failures, top_n=5)
    detected_spikes = detect_5xx_spike(minute_distribution, minute_5xx_counts, min_delta=10.0, min_traffic_gate=10)

    execution_time = time.time() - start_time

    print_dashboard(
        total_lines, total_valid, malformed_lines, len(ip_counts),
        errors_4xx, errors_5xx, error_rate, top_endpoints,
        hourly_distribution, top_login_failures, detected_spikes, execution_time
    )

    if args.export:
        export_to_json(
            args.export, total_lines, total_valid, malformed_lines, ip_counts,
            errors_4xx, errors_5xx, error_rate, top_endpoints,
            hourly_distribution, top_login_failures, detected_spikes
        )


if __name__ == "__main__":
    main()