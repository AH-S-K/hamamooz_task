def _is_valid_following_pattern(segment: str) -> bool:
    """
    بررسی می‌کند که آیا فرمت رشته بلافاصله بعد از کوتیشن پایانیِ Request معتبر است یا خیر.
    الگوی مورد انتظار: [فاصله] + [۳ رقم کد وضعیت] + [فاصله] + [حداقل یک رقم یا خط تیره]
    نمونه‌های معتبر: ' 200 5324' یا ' 404 -'
    """
    if len(segment) < 6:
        return False

    if segment[0] != ' ':
        return False

    # بررسی ۳ رقم مربوط به کد وضعیت (HTTP Status Code)
    if not (segment[1].isdigit() and segment[2].isdigit() and segment[3].isdigit()):
        return False

    if segment[4] != ' ':
        return False

    # بررسی شروع کاراکتر حجم پاسخ (حداقل یک عدد یا خط تیره برای مقادیر خالی)
    if not (segment[5].isdigit() or segment[5] == '-'):
        return False

    return True


def parse_log_line_ultimate(line: str) -> dict | None:
    """
    پارس کردن خطوط لاگ فرمت Combined به صورت سریع و بدون ریجکس.
    این تابع در برابر وجود کاراکترهای " اضافه در بخش Request کاملاً مقاوم است.

    در صورت معتبر بودن خط، یک دیکشنری و در صورت خراب بودن خط (Malformed)، مقدار None برمی‌گرداند.
    """
    line = line.strip()
    if not line:
        return None

    try:
        # ۱. استخراج IP و رشته تاریخ (از سمت چپ خط)
        first_space = line.index(' ')
        ip = line[:first_space]

        start_bracket = line.index('[', first_space)
        end_bracket = line.index(']', start_bracket)
        date_str = line[start_bracket + 1:end_bracket]
        hour = date_str[12:14]

        # ۲. پیدا کردن شروع بخش درخواست (اولین کوتیشن بعد از تاریخ)
        start_request = line.index('"', end_bracket)

        # ۳. پیدا کردن کوتیشن پایانیِ واقعی بخش Request با اعتبارسنجی الگوی بعد از آن
        idx = start_request + 1
        while True:
            next_quote = line.index('"', idx)

            # چک کردن ساختار بعد از کوتیشن (وجود درستِ Status و Bytes)
            if _is_valid_following_pattern(line[next_quote + 1:]):
                end_request = next_quote
                break

            idx = next_quote + 1

        request_str = line[start_request + 1:end_request]

        # ۴. جداسازی کد وضعیت و حجم فایل از بخش باقیمانده خط
        after_request = line[end_request + 2:].strip()
        status_bytes_and_more = after_request.split(' ', 2)

        status = status_bytes_and_more[0]
        bytes_sent = status_bytes_and_more[1]

        # ۵. تفکیک متد و مسیر از داخل بخش Request
        request_parts = request_str.split(' ')
        method = request_parts[0] if len(request_parts) > 0 else "-"
        path = request_parts[1] if len(request_parts) > 1 else "-"

        return {
            "ip": ip,
            "date": date_str,
            "hour": hour,
            "method": method,
            "path": path,
            "status": int(status),
            "bytes": int(bytes_sent) if bytes_sent != '-' else 0
        }

    except (ValueError, IndexError):
        # بازگرداندن None در صورت عدم تطابق با ساختار یا خطای تبدیل دیتا انواع داده
        return None



test = '''16.93.138.131 - - [01/Jun/2026:00:00:08 +0000] "POST /cart HTTP/1.1" 200 6672 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'''

print(parse_log_line_ultimate(test))