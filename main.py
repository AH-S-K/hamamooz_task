# main.py
import argparse
import gzip
import os
import sys
import time
from parser import parse_log_line


def main():
    # ۱. تنظیم آرگومان‌های خط فرمان با argparse
    parser = argparse.ArgumentParser(
        description="LogSphere: A CLI tool for analyzing access log files."
    )
    parser.add_argument(
        "logfile",
        type=str,
        help="Path to the access log file (supports standard text logs or .gz compressed files)"
    )

    args = parser.parse_args()
    log_path = args.logfile

    # ۲. اعتبارسنجی وجود و صحت مسیر فایل روی دیسک
    if not os.path.exists(log_path):
        print(f"❌ Error: The file '{log_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(log_path):
        print(f"❌ Error: '{log_path}' is a directory or invalid file type.", file=sys.stderr)
        sys.exit(1)

    # ۳. تشخیص نوع فایل (متنی معمولی یا فشرده شده .gz)
    is_gzip = log_path.endswith('.gz')
    open_func = gzip.open if is_gzip else open
    file_mode = 'rt' if is_gzip else 'r'  # استفاده از text mode برای خواندن خط‌به‌خط استرینگ

    print(f"[*] Starting analysis on: {os.path.basename(log_path)} "
          f"({'Gzip Compressed' if is_gzip else 'Plain Text'})")
    print("-" * 50)

    start_time = time.time()
    total_lines = 0
    malformed_lines = 0

    try:
        # ۴. باز کردن ایمن فایل با مدیریت خطای انکودینگ
        # استفاده از errors='replace' یا 'ignore' تضمین می‌کند که بایت‌های شکسته یا کاراکترهای یونیکد کثیف
        # باعث کرش کردن کل برنامه و پرتاب UnicodeDecodeError نمی‌شوند.
        with open_func(log_path, file_mode, encoding='utf-8', errors='replace') as file:

            # ۵. لوپ استریم خط‌به‌خط (بدون بارگذاری کل فایل در RAM)
            for line in file:
                total_lines += 1

                # فراخوانی پارسر روی خط جاری
                parsed_data = parse_log_line(line)

                if parsed_data is None:
                    malformed_lines += 1
                    continue

                # ----------------------------------------------------
                # [محل قرارگیری منطق تجمیع داده‌ها در قدم‌های ۳ و ۵]
                # ----------------------------------------------------

                # برای اینکه در فایل‌های میلیونی ترمینال قفل نشود، می‌توانید هر ۱۰۰ هزار خط وضعیت را چاپ کنید
                if total_lines % 500000 == 0:
                    print(f"⏳ Processed {total_lines:,} lines...")

    except KeyboardInterrupt:
        print("\n🛑 Operation cancelled by user.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ An unexpected error occurred during execution: {e}", file=sys.stderr)
        sys.exit(1)

    execution_time = time.time() - start_time

    # ۶. گزارش اولیه ساختار برای تایید صحت عملکرد قدم اول
    print("-" * 50)
    print("✅ Step 1 Execution Completed Successfully!")
    print(f"🔹 Total Lines Read: {total_lines:,}")
    print(f"🔹 Malformed/Empty Lines Skipped: {malformed_lines:,}")
    print(f"🔹 Execution Time: {execution_time:.2f} seconds")
    print("-" * 50)


if __name__ == "__main__":
    main()