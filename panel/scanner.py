"""Локальный статический сканер APK (без интернета, без внешних программ).

Читает APK как ZIP, ищет в манифесте и dex-файлах признаки вредоносного поведения.
Это эвристика: она находит подозрительное, но не заменяет антивирус.
"""
import hashlib
import os
import re
import zipfile

MAX_DEX = 120 * 1024 * 1024

PERMS = {
    "SEND_SMS": ("HIGH", "Разрешение отправлять SMS"),
    "READ_SMS": ("HIGH", "Разрешение читать SMS"),
    "RECEIVE_SMS": ("HIGH", "Разрешение перехватывать входящие SMS"),
    "BIND_DEVICE_ADMIN": ("HIGH", "Права администратора устройства"),
    "BIND_ACCESSIBILITY_SERVICE": ("HIGH", "Служба специальных возможностей (часто используется для слежки)"),
    "REQUEST_INSTALL_PACKAGES": ("MEDIUM", "Может устанавливать другие приложения"),
    "SYSTEM_ALERT_WINDOW": ("MEDIUM", "Рисует окна поверх других приложений"),
    "READ_CALL_LOG": ("MEDIUM", "Читает журнал звонков"),
    "RECORD_AUDIO": ("LOW", "Запись звука с микрофона"),
    "READ_CONTACTS": ("LOW", "Чтение контактов"),
}

# (описание, серьёзность, [группы строк: в каждой группе нужна хотя бы одна])
DEX_RULES = [
    ("Отправка SMS из кода", "HIGH",
     [["Landroid/telephony/SmsManager;"], ["sendTextMessage", "sendMultipartTextMessage", "sendDataMessage"]]),
    ("Управление устройством (блокировка/стирание)", "HIGH",
     [["Landroid/app/admin/DevicePolicyManager;"], ["lockNow", "wipeData", "resetPassword"]]),
    ("Динамическая загрузка постороннего кода", "MEDIUM",
     [["Ldalvik/system/DexClassLoader;", "Ldalvik/system/InMemoryDexClassLoader;"]]),
    ("Выполнение shell-команд", "MEDIUM",
     [["Ljava/lang/Runtime;"], ["exec"]]),
    ("Обращение к root (su)", "MEDIUM",
     [["/system/bin/su", "/system/xbin/su", "/sbin/su"]]),
    ("Установка других APK из кода", "MEDIUM",
     [["application/vnd.android.package-archive"], ["Landroid/content/Intent;"]]),
    ("Отправка данных через Telegram/Discord/Pastebin", "MEDIUM",
     [["api.telegram.org", "discord.com/api/webhooks", "discordapp.com/api/webhooks", "pastebin.com"]]),
    ("Рефлексия (часто маскирует код)", "LOW",
     [["Ljava/lang/reflect/Method;"], ["invoke"]]),
    ("Base64-декодирование (часто прячет строки)", "LOW",
     [["Landroid/util/Base64;"], ["decode"]]),
]

SAFE_HOSTS = ("google", "android.com", "apache.org", "w3.org", "gstatic", "googleapis",
              "facebook", "firebase", "xmlpull.org", "schemas.", "example.com", "github.com",
              "mozilla.org", "unicode.org", "sun.com", "oracle.com")

URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]{4,120}")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def has_dex_string(data, s):
    """Точное совпадение строки в таблице строк dex (длина + текст + NUL)."""
    b = s.encode()
    return len(b) < 128 and data.find(bytes([len(b)]) + b + b"\x00") != -1


def manifest_has(manifest, text):
    return (text.encode("utf-16-le") in manifest) or (text.encode() in manifest)


def scan_apk(path, hash_list=None):
    findings = []
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    digest = h.hexdigest()
    size_mb = os.path.getsize(path) / 1048576

    if hash_list and digest in hash_list:
        findings.append(("HIGH", "SHA256 файла найден в списке известных вредоносов"))

    try:
        z = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        raise ValueError("Это не APK (повреждённый архив)")

    names = z.namelist()
    if "AndroidManifest.xml" not in names:
        findings.append(("HIGH", "В архиве нет AndroidManifest.xml: это не обычный APK"))

    # --- структура ---
    for info in z.infolist():
        low = info.filename.lower()
        if (low.startswith(("assets/", "res/raw/"))) and low.endswith((".dex", ".jar", ".apk")):
            findings.append(("MEDIUM", f"Исполняемый файл спрятан в ресурсах: {info.filename}"))
        if info.compress_size and info.file_size / max(info.compress_size, 1) > 200 and info.file_size > 50 * 1048576:
            findings.append(("MEDIUM", f"Подозрительно сильное сжатие: {info.filename}"))

    # --- манифест ---
    manifest = z.read("AndroidManifest.xml") if "AndroidManifest.xml" in names else b""
    for perm, (sev, desc) in PERMS.items():
        if manifest_has(manifest, "android.permission." + perm):
            findings.append((sev, f"{desc} ({perm})"))

    # --- dex ---
    found_rules, urls = set(), set()
    for name in names:
        if not re.fullmatch(r"classes\d*\.dex", name):
            continue
        if z.getinfo(name).file_size > MAX_DEX:
            findings.append(("INFO", f"{name} слишком большой, пропущен"))
            continue
        data = z.read(name)
        for i, (desc, sev, groups) in enumerate(DEX_RULES):
            if i in found_rules:
                continue
            if all(any(has_dex_string(data, s) or (len(s) > 20 and s.encode() in data) for s in g)
                   for g in groups):
                found_rules.add(i)
        for m in URL_RE.findall(data):
            urls.add(m.decode(errors="ignore"))
    for i in sorted(found_rules):
        desc, sev, _ = DEX_RULES[i]
        findings.append((sev, desc))

    # --- адреса ---
    shown = 0
    for u in sorted(urls):
        host = u.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
        if any(s in host for s in SAFE_HOSTS):
            continue
        if IP_RE.match(host) and not host.startswith(("127.", "0.")):
            findings.append(("MEDIUM", f"Прямой IP-адрес в коде: {host}"))
        elif shown < 6:
            findings.append(("INFO", f"Адрес в коде: {u[:80]}"))
            shown += 1

    # --- комбинации: сильнее каждого признака по отдельности ---
    msgs = " | ".join(m for _, m in findings)
    if "SEND_SMS" in msgs and "Отправка SMS из кода" in msgs:
        findings.append(("HIGH", "Комбинация: разрешение на SMS + код отправки SMS (типично для SMS-троянов)"))
    if "REQUEST_INSTALL_PACKAGES" in msgs and "Динамическая загрузка" in msgs:
        findings.append(("HIGH", "Комбинация: загрузка кода + установка приложений (типично для дропперов)"))

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda x: order[x[0]])
    score = sum({"HIGH": 5, "MEDIUM": 2, "LOW": 1}.get(s, 0) for s, _ in findings)
    level = "ВЫСОКИЙ" if score >= 10 else "СРЕДНИЙ" if score >= 4 else "НИЗКИЙ"

    lines = [f"SHA256: {digest}", f"Размер: {size_mb:.1f} МБ"]
    lines += [f"[{s}] {m}" for s, m in findings]
    lines.append(f"Итоговая оценка риска: {score} ({level})")
    return {"sha256": digest, "findings": findings, "score": score, "level": level,
            "report": "\n".join(lines), "patched": None}
