#!/usr/bin/env python3
"""
apk_scan.py - статический анализ APK и (опционально) обезвреживание.

Требуется: Python 3.8+, apktool, zipalign, apksigner, keytool (JDK / Android build-tools) в PATH.

Использование:
  python apk_scan.py app.apk                  # анализ + патч + пересборка (fix включён всегда)
  python apk_scan.py app.apk --report-only    # только анализ
  python apk_scan.py app.apk --hashes bad.txt # доп. проверка SHA256 по списку (по одному хэшу в строке)
"""
import argparse, hashlib, re, shutil, subprocess, sys, zipfile
from pathlib import Path

# (описание, regex по smali, серьёзность, можно ли автоматически вырезать вызов)
SMALI_RULES = {
    "sms_send":    ("Отправка SMS из кода",            r"Landroid/telephony/SmsManager;->(sendTextMessage|sendMultipartTextMessage|sendDataMessage)", "HIGH", True),
    "runtime_exec": ("Выполнение shell-команд",         r"Ljava/lang/Runtime;->exec|Ljava/lang/ProcessBuilder;->start", "HIGH", True),
    "dex_loader":  ("Динамическая загрузка кода",       r"Ldalvik/system/(DexClassLoader|InMemoryDexClassLoader|PathClassLoader);-><init>", "HIGH", False),
    "su_binary":   ("Обращение к root/su",              r'"(/system/(x?bin)/su|/sbin/su|su)"', "MEDIUM", False),
    "reflection":  ("Рефлексия (часто обфускация)",     r"Ljava/lang/reflect/Method;->invoke", "LOW", False),
    "b64_decode":  ("Base64-декодирование",             r"Landroid/util/Base64;->decode", "LOW", False),
    "admin":       ("Device Admin",                     r"Landroid/app/admin/DevicePolicyManager;->(lockNow|wipeData|resetPassword)", "HIGH", False),
    "install_pkg": ("Установка других APK",             r"application/vnd\.android\.package-archive", "MEDIUM", False),
    "overlay":     ("Оверлей поверх приложений",        r"TYPE_APPLICATION_OVERLAY|TYPE_SYSTEM_ALERT", "MEDIUM", False),
}

DANGEROUS_PERMS = {
    "SEND_SMS": "HIGH", "READ_SMS": "HIGH", "RECEIVE_SMS": "HIGH",
    "BIND_DEVICE_ADMIN": "HIGH", "BIND_ACCESSIBILITY_SERVICE": "HIGH",
    "REQUEST_INSTALL_PACKAGES": "MEDIUM", "SYSTEM_ALERT_WINDOW": "MEDIUM",
    "READ_CONTACTS": "LOW", "RECORD_AUDIO": "LOW", "READ_CALL_LOG": "MEDIUM",
}
STRIP_PERMS = {"SEND_SMS", "READ_SMS", "RECEIVE_SMS", "REQUEST_INSTALL_PACKAGES"}

URL_RE = re.compile(r"https?://[^\s\"'<>]+|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"Ошибка: {' '.join(map(str, cmd))}\n{r.stderr or r.stdout}")
    return r.stdout


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_apk_structure(apk):
    findings = []
    with zipfile.ZipFile(apk) as z:
        names = z.namelist()
        dex = [n for n in names if re.fullmatch(r"classes\d*\.dex", n)]
        if len(dex) > 4:
            findings.append(("MEDIUM", f"Много dex-файлов: {len(dex)}"))
        for n in names:
            if n.startswith("assets/") and n.lower().endswith((".dex", ".jar", ".apk", ".so", ".bin")):
                findings.append(("MEDIUM", f"Исполняемый payload в assets: {n}"))
    return findings


def analyze(src_dir):
    findings, hits = [], []
    manifest = (src_dir / "AndroidManifest.xml").read_text(errors="ignore")
    for perm, sev in DANGEROUS_PERMS.items():
        if f"android.permission.{perm}" in manifest:
            findings.append((sev, f"Разрешение {perm}"))

    urls = set()
    for f in src_dir.rglob("*.smali"):
        text = f.read_text(errors="ignore")
        for key, (desc, rx, sev, _) in SMALI_RULES.items():
            if re.search(rx, text):
                hits.append((key, f))
                findings.append((sev, f"{desc}: {f.relative_to(src_dir)}"))
        urls.update(URL_RE.findall(text))
    for u in sorted(urls)[:20]:
        findings.append(("INFO", f"URL/IP в коде: {u}"))
    return findings, hits


def patch_smali(path, rule_rx):
    """Заменяет подозрительный invoke на nop (+ обнуляет результат, если он читается)."""
    lines = path.read_text(errors="ignore").split("\n")
    changed, i = 0, 0
    while i < len(lines):
        if lines[i].lstrip().startswith("invoke-") and re.search(rule_rx, lines[i]):
            lines[i] = "    nop  # [apk_scan] removed: " + lines[i].strip()
            changed += 1
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            m = re.match(r"\s*move-result(-object|-wide)?\s+(v\d+|p\d+)", lines[j]) if j < len(lines) else None
            if m:
                reg = m.group(2)
                lines[j] = (f"    const-wide/16 {reg}, 0x0" if m.group(1) == "-wide"
                            else f"    const/4 {reg}, 0x0")
        i += 1
    if changed:
        path.write_text("\n".join(lines))
    return changed


def fix(src_dir, hits):
    total = 0
    # 1) убираем опасные разрешения
    mf = src_dir / "AndroidManifest.xml"
    text = mf.read_text(errors="ignore")
    for perm in STRIP_PERMS:
        text, n = re.subn(rf'\s*<uses-permission[^>]*android\.permission\.{perm}"[^>]*/>', "", text)
        total += n
    mf.write_text(text)
    # 2) вырезаем вызовы
    for key, f in set(hits):
        desc, rx, sev, patchable = SMALI_RULES[key]
        if patchable:
            total += patch_smali(f, rx)
    return total


def rebuild(src_dir, out_apk):
    tmp = out_apk.with_suffix(".unsigned.apk")
    aligned = out_apk.with_suffix(".aligned.apk")
    run(["apktool", "b", str(src_dir), "-o", str(tmp)])
    run(["zipalign", "-f", "4", str(tmp), str(aligned)])
    ks = Path("apk_scan.keystore")
    if not ks.exists():
        run(["keytool", "-genkey", "-v", "-keystore", str(ks), "-alias", "scan", "-keyalg", "RSA",
             "-keysize", "2048", "-validity", "10000", "-storepass", "android", "-keypass", "android",
             "-dname", "CN=apk_scan"])
    run(["apksigner", "sign", "--ks", str(ks), "--ks-pass", "pass:android",
         "--out", str(out_apk), str(aligned)])
    tmp.unlink(missing_ok=True)
    aligned.unlink(missing_ok=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("apk")
    ap.add_argument("--report-only", action="store_true", help="только анализ, без исправления (по умолчанию исправление ВКЛЮЧЕНО)")
    ap.add_argument("--hashes", help="файл со списком SHA256 известных вредоносов")
    ap.add_argument("--workdir", default="apk_work")
    a = ap.parse_args()

    apk = Path(a.apk)
    if not zipfile.is_zipfile(apk):
        sys.exit("Это не валидный APK/ZIP")

    digest = sha256(apk)
    print(f"SHA256: {digest}")
    if a.hashes and digest in {l.strip().lower() for l in open(a.hashes) if l.strip()}:
        print("!!! Хэш найден в списке известных вредоносов. Не устанавливайте этот файл.")

    findings = check_apk_structure(apk)

    work = Path(a.workdir)
    shutil.rmtree(work, ignore_errors=True)
    run(["apktool", "d", "-f", str(apk), "-o", str(work)])
    f2, hits = analyze(work)
    findings += f2

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    for sev, msg in sorted(findings, key=lambda x: order[x[0]]):
        print(f"[{sev}] {msg}")
    score = sum({"HIGH": 5, "MEDIUM": 2, "LOW": 1}.get(s, 0) for s, _ in findings)
    print(f"\nИтоговая оценка риска: {score} ({'ВЫСОКИЙ' if score >= 10 else 'СРЕДНИЙ' if score >= 4 else 'НИЗКИЙ'})")

    if not a.report_only and any(s == "HIGH" for s, _ in findings):
        n = fix(work, hits)
        print(f"Изменений внесено: {n}")
        out = apk.with_name(apk.stem + "_patched.apk")
        rebuild(work, out)
        print(f"Пересобран и подписан (новым ключом): {out}")
        print("Внимание: подпись изменена, приложение может не работать. Проверяйте только в песочнице.")


if __name__ == "__main__":
    main()
