# parser.py

def _is_valid_following_pattern(line: str, start_idx: int) -> bool:
    """
    بررسی بهینه الگوی بعد از کوتیشن بدون کپی کردن رشته در حافظه (حذف اسلایسینگ).
    الگوی مورد انتظار: [فاصله] + [۳ رقم کد وضعیت] + [فاصله] + [حداقل یک رقم یا خط تیره]
    """
    # بررسی حداقل طول باقی‌مانده خط برای جلوگیری از IndexError
    if len(line) - start_idx < 6:
        return False

    if line[start_idx] != ' ':
        return False

    # بررسی سریع ۳ رقم مربوط به کد وضعیت (HTTP Status Code)
    if not (line[start_idx + 1].isdigit() and
            line[start_idx + 2].isdigit() and
            line[start_idx + 3].isdigit()):
        return False

    if line[start_idx + 4] != ' ':
        return False

    # بررسی شروع کاراکتر حجم پاسخ (عدد یا خط تیره)
    char_5 = line[start_idx + 5]
    if not (char_5.isdigit() or char_5 == '-'):
        return False

    return True


def parse_log_line(line: str) -> dict | None:
    """
    پارس کردن خطوط لاگ فرمت Combined به صورت فوق‌سریع، بدون ریجکس و مقاوم در برابر " اضافه.
    در صورت معتبر بودن خط، یک دیکشنری و در صورت خراب بودن مقدار None برمی‌گرداند.
    """
    # حذف کاراکترهای فضای خالی سمت راست (مثل n\) به صورت سریع
    line = line.rstrip()
    if not line:
        return None

    # ۱. پیدا کردن براکت‌ها برای استخراج IP و تاریخ (استفاده از find به جای index جهت سرعت)
    start_bracket = line.find('[')
    if start_bracket == -1:
        return None

    end_bracket = line.find(']', start_bracket)
    if end_bracket == -1:
        return None

    # استخراج IP (بخش قبل از اولین فاصله پیش از براکت)
    first_space = line.find(' ')
    if first_space == -1 or first_space > start_bracket:
        return None
    ip = line[:first_space]

    # استخراج تاریخ و ساعت
    date_str = line[start_bracket + 1:end_bracket]
    if len(date_str) < 14:  # بررسی حداقل طول برای اطمینان از وجود بخش ساعت
        return None
    hour = date_str[12:14]  # استخراج سریع ۲ رقم ساعت (مثلاً 09)

    # ۲. پیدا کردن شروع بخش درخواست (اولین کوتیشن بعد از تاریخ)
    start_request = line.find('"', end_bracket)
    if start_request == -1:
        return None

    # ۳. پیدا کردن کوتیشن پایانیِ واقعی بخش Request با ایندکس مپینگ (بدون تکه‌تکه کردن رشته)
    idx = start_request + 1
    end_request = -1
    while True:
        next_quote = line.find('"', idx)
        if next_quote == -1:
            break

        # چک کردن ساختار بعد از کوتیشن با ارجاع به ایندکس اصلی
        if _is_valid_following_pattern(line, next_quote + 1):
            end_request = next_quote
            break

        idx = next_quote + 1

    if end_request == -1:
        return None

    request_str = line[start_request + 1:end_request]

    # ۴. جداسازی کد وضعیت و حجم فایل بدون اسپلیت کردن کل خط (رفع گلوگاه پردازش مروگرها)
    after_request = line[end_request + 2:]

    space_after_status = after_request.find(' ')
    if space_after_status == -1:
        return None
    status = after_request[:space_after_status]

    space_after_bytes = after_request.find(' ', space_after_status + 1)
    if space_after_bytes == -1:
        bytes_sent = after_request[space_after_status + 1:]
    else:
        bytes_sent = after_request[space_after_status + 1:space_after_bytes]

    # ۵. تفکیک متد و مسیر از داخل بخش Request
    request_parts = request_str.split(' ', 2)
    method = request_parts[0] if len(request_parts) > 0 else "-"
    path = request_parts[1] if len(request_parts) > 1 else "-"

    try:
        return {
            "ip": ip,
            "date": date_str,
            "hour": hour,
            "method": method,
            "path": path,
            "status": int(status),
            "bytes": int(bytes_sent) if bytes_sent != '-' else 0
        }
    except ValueError:
        # در صورت بروز خطای غیرمنتظره در تبدیل انواع داده (مثلاً خراب بودن فیلد حجم)
        return None