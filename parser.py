# parser.py

def parse_log_line(line: str) -> dict | None:
    """
    تجزیه خطوط لاگ.
    برای افزایش کارایی، به‌جای استفاده از Regex، از متدهای پایه رشته (مانند find و split)
    استفاده شده است تا سرعت پردازش فایل‌های حجیم به حداکثر برسد.
    """

    # ۱. استخراج IP و تاریخ با پیدا کردن براکت‌ها
    start_bracket = line.find('[')
    if start_bracket == -1:
        return None

    end_bracket = line.find(']', start_bracket)
    if end_bracket == -1:
        return None

    first_space = line.find(' ')
    if first_space == -1 or first_space > start_bracket:
        return None
    ip = line[:first_space]

    date_str = line[start_bracket + 1:end_bracket]
    colon_idx = date_str.find(':')
    if colon_idx == -1 or len(date_str) < colon_idx + 6:
        return None

    hour = date_str[colon_idx + 1: colon_idx + 3]
    minute_window = date_str[:colon_idx + 6]

    # ۲. پیدا کردن شروع بخش درخواست
    start_request = line.find('"', end_bracket)
    if start_request == -1:
        return None

    # ۳ و ۴. پیدا کردن کوتیشن پایانی + استخراج همزمان Status و Bytes (ادغام دو مرحله برای سرعت)
    idx = start_request + 1
    end_request = -1

    # متغیرهای آماده برای ذخیره در صورت موفقیت
    status_val = 0
    bytes_val = 0

    while True:
        next_quote = line.find('"', idx)
        if next_quote == -1:
            break

        # بریدن بخش بعد از کوتیشن
        tail = line[next_quote + 1:]

        # شرط امنیتی: بخش بعد از کوتیشن حتماً باید با حداقل یک فاصله شروع شود
        if tail.startswith(' '):
            # متد split(None) به‌طور خودکار فاصله‌های متوالی (Multi-space) را نادیده می‌گیرد
            parts = tail.split(None, 2)

            # بررسی وجود status و bytes
            if len(parts) >= 2:
                st_str, b_str = parts[0], parts[1]

                # بررسی سریع صحت Status (۳ رقم) و Bytes (فقط عدد یا خط تیره)
                if len(st_str) == 3 and st_str.isdigit() and (b_str.isdigit() or b_str == '-'):
                    end_request = next_quote
                    status_val = int(st_str)
                    bytes_val = int(b_str) if b_str != '-' else 0
                    break

        idx = next_quote + 1

    if end_request == -1:
        return None

    request_str = line[start_request + 1:end_request]

    # ۵. تفکیک متد و مسیر
    request_parts = request_str.split(' ', 2)
    method = request_parts[0] if request_parts else "-"
    raw_path = request_parts[1] if len(request_parts) > 1 else "-"

    # حذف Query String از مسیر درخواست (بدون ایجاد لیست اضافی در مموری)
    q_mark = raw_path.find('?')
    path = raw_path[:q_mark] if q_mark != -1 else raw_path

    return {
        "ip": ip,
        "date": date_str,
        "hour": hour,
        "minute_window": minute_window,
        "method": method,
        "path": path,
        "status": status_val,
        "bytes": bytes_val
    }