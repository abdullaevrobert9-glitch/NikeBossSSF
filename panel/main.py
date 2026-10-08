"""APK Scanner v0.4: окно «проверить перед установкой», проверка на телефоне + исправление через GitHub."""
import base64, io, json, os, shutil, threading, time, zipfile
from datetime import datetime, timedelta

import requests
from kivy.app import App
from kivy.clock import Clock
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput

from scanner import scan_apk

try:
    from jnius import autoclass
    from android import activity as android_activity
    ANDROID = True
except Exception:
    ANDROID = False

API = "https://api.github.com"
WORKFLOW = "scan-apk.yml"
REMOTE = "incoming/app.apk"
MAX_MB = 90


# ---------- Android-помощники ----------
def j_activity():
    return autoclass("org.kivy.android.PythonActivity").mActivity


def read_intent(intent):
    """Если Android открыл APK через наше приложение, вернёт (uri, имя файла)."""
    if intent is None or intent.getAction() != "android.intent.action.VIEW":
        return None
    uri = intent.getData()
    if uri is None:
        return None
    name = "app.apk"
    try:
        if uri.getScheme() == "content":
            cur = j_activity().getContentResolver().query(uri, None, None, None, None)
            if cur is not None:
                if cur.moveToFirst():
                    idx = cur.getColumnIndex("_display_name")
                    if idx >= 0:
                        name = cur.getString(idx)
                cur.close()
        else:
            name = os.path.basename(uri.getPath())
    except Exception:
        pass
    return uri, name


def copy_uri(uri, dst):
    if uri.getScheme() == "file":
        shutil.copyfile(uri.getPath(), dst)
        return
    pfd = j_activity().getContentResolver().openFileDescriptor(uri, "r")
    fd = pfd.detachFd()
    with os.fdopen(fd, "rb") as src, open(dst, "wb") as out:
        shutil.copyfileobj(src, out, 1 << 20)


def install_uri(uri):
    """Передаёт файл системному установщику."""
    Intent = autoclass("android.content.Intent")
    i = Intent("android.intent.action.INSTALL_PACKAGE")
    i.setData(uri)
    i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    j_activity().startActivity(i)


# ---------- Интерфейс ----------
class Panel(BoxLayout):
    def __init__(self, cfg_path, **kw):
        super().__init__(orientation="vertical", padding=10, spacing=8, **kw)
        self.cfg_path = cfg_path
        self.cur_uri = None
        cfg = {}
        try:
            cfg = json.load(open(cfg_path))
        except Exception:
            pass
        self.add_widget(Label(text="APK Scanner v0.4", size_hint_y=None, height=40, font_size=22))
        self.path = TextInput(text=cfg.get("path", "/storage/emulated/0/Download/"),
                              hint_text="Путь к APK", multiline=False,
                              size_hint_y=None, height=44)
        self.add_widget(self.path)
        pick = Button(text="Выбрать APK...", size_hint_y=None, height=54)
        pick.bind(on_release=lambda *_: self.pick_file())
        self.add_widget(pick)
        self.btn = Button(text="Проверить на телефоне", size_hint_y=None, height=54)
        self.btn.bind(on_release=lambda *_: self.start_local())
        self.add_widget(self.btn)
        self.add_widget(Label(text="Исправление через GitHub (необязательно, для разработчиков):",
                              size_hint_y=None, height=30, font_size=13))
        self.token = TextInput(text=cfg.get("token", ""), hint_text="GitHub токен", password=True,
                               multiline=False, size_hint_y=None, height=44)
        self.repo = TextInput(text=cfg.get("repo", "abdullaevrobert9-glitch/NikeBossSSF"),
                              hint_text="владелец/репозиторий", multiline=False,
                              size_hint_y=None, height=44)
        self.add_widget(self.token)
        self.add_widget(self.repo)
        self.cloud_btn = Button(text="Исправить через GitHub", size_hint_y=None, height=54)
        self.cloud_btn.bind(on_release=lambda *_: self.start())
        self.add_widget(self.cloud_btn)
        sv = ScrollView()
        self.out = Label(text="Готово к работе.", size_hint_y=None, halign="left", valign="top")
        self.out.bind(width=lambda *_: setattr(self.out, "text_size", (self.out.width, None)))
        self.out.bind(texture_size=lambda *_: setattr(self.out, "height", self.out.texture_size[1]))
        sv.add_widget(self.out)
        self.add_widget(sv)

    # --- окна ---
    def ask(self, text, left, right, on_left, on_right, title="APK Scanner"):
        box = BoxLayout(orientation="vertical", padding=10, spacing=10)
        lbl = Label(text=text, halign="center", valign="middle")
        lbl.bind(size=lambda w, _: setattr(w, "text_size", (w.width, None)))
        row = BoxLayout(size_hint_y=None, height=56, spacing=10)
        bl, br = Button(text=left), Button(text=right)
        row.add_widget(bl)
        row.add_widget(br)
        box.add_widget(lbl)
        box.add_widget(row)
        popup = Popup(title=title, content=box, size_hint=(0.92, 0.5), auto_dismiss=False)

        def go(cb):
            popup.dismiss()
            cb()

        bl.bind(on_release=lambda *_: go(on_left))
        br.bind(on_release=lambda *_: go(on_right))
        popup.open()

    def ui(self, fn):
        Clock.schedule_once(lambda dt: fn())

    # --- сценарий «открыли APK» ---
    def on_apk_opened(self, uri, name):
        if name.lower().endswith("_patched.apk"):  # уже проверенная и исправленная нами копия
            install_uri(uri)
            return
        self.cur_uri = uri
        self.ask("Вы хотите установить это приложение?\n\n"
                 "Давайте проверим этот файл на вредоносный код (вирус)?",
                 "Не нужно", "Проверить", self.warn_skip, self.scan_opened)

    def warn_skip(self):
        self.ask("Мы настоятельно рекомендуем проверить файл. "
                 "Установка без проверки может быть опасна.",
                 "Всё равно установить", "Проверить",
                 lambda: install_uri(self.cur_uri), self.scan_opened)

    def scan_opened(self):
        cfg = self.get_cfg()
        self.out.text = "Копирую файл..."
        self.set_busy(True)
        threading.Thread(target=self.scan_opened_thread, args=(cfg,), daemon=True).start()

    def scan_opened_thread(self, cfg):
        try:
            tmp = os.path.join(os.path.dirname(self.cfg_path), "incoming.apk")
            copy_uri(self.cur_uri, tmp)
            self.log("Проверяю...")
            res = scan_apk(tmp)
            self.log(res["report"])
            self.ui(lambda: self.after_scan(res))
        except Exception as e:
            self.log(f"Ошибка: {e}")
        finally:
            self.set_busy(False)

    def after_scan(self, res):
        lines = res["report"].splitlines()
        main = [l for l in lines if l.startswith(("[HIGH]", "[MEDIUM]"))][:4]
        risk = next((l for l in lines if l.startswith("Итоговая оценка")), "")
        if res["level"] == "НИЗКИЙ":
            self.ask(f"Серьёзных признаков вредоносного кода не найдено.\n{risk}\n\n"
                     "Это не гарантия безопасности: сканер ищет только известные приёмы.",
                     "Отмена", "Установить", lambda: None,
                     lambda: install_uri(self.cur_uri), title="Результат проверки")
        else:
            self.ask(f"Найдено подозрительное:\n" + "\n".join(main) + f"\n\n{risk}\n"
                     "Установка не рекомендуется.",
                     "Не устанавливать", "Всё равно установить", lambda: None,
                     lambda: install_uri(self.cur_uri), title="Результат проверки")

    # --- ручной режим ---
    def pick_file(self):
        start = "/storage/emulated/0/Download"
        if not os.path.isdir(start):
            start = "/storage/emulated/0"
        chooser = FileChooserListView(path=start, filters=["*.apk"])
        box = BoxLayout(orientation="vertical", spacing=6)
        box.add_widget(chooser)
        row = BoxLayout(size_hint_y=None, height=54, spacing=6)
        ok, cancel = Button(text="Выбрать"), Button(text="Отмена")
        row.add_widget(ok)
        row.add_widget(cancel)
        box.add_widget(row)
        popup = Popup(title="Выберите APK", content=box, size_hint=(0.95, 0.9))

        def choose(*_):
            if chooser.selection:
                self.path.text = chooser.selection[0]
            popup.dismiss()

        ok.bind(on_release=choose)
        cancel.bind(on_release=popup.dismiss)
        popup.open()

    def log(self, msg):
        Clock.schedule_once(lambda dt: setattr(self.out, "text", self.out.text + "\n" + msg))

    def set_busy(self, busy):
        def f(dt):
            self.btn.disabled = busy
            self.cloud_btn.disabled = busy
        Clock.schedule_once(f)

    def get_cfg(self):
        cfg = {"token": self.token.text.strip(), "repo": self.repo.text.strip(),
               "path": self.path.text.strip()}
        try:
            json.dump(cfg, open(self.cfg_path, "w"))
        except Exception:
            pass
        return cfg

    def start_local(self):
        cfg = self.get_cfg()
        self.out.text = "Проверяю на телефоне..."
        self.set_busy(True)
        threading.Thread(target=self.local_thread, args=(cfg["path"],), daemon=True).start()

    def local_thread(self, path):
        try:
            if not os.path.isfile(path):
                return self.log("Файл не найден. Проверьте путь и доступ к файлам.")
            self.log("\n" + scan_apk(path)["report"])
        except Exception as e:
            self.log(f"Ошибка: {e}")
        finally:
            self.set_busy(False)

    def start(self):
        cfg = self.get_cfg()
        self.out.text = "Запуск..."
        self.set_busy(True)
        threading.Thread(target=self.run, args=(cfg,), daemon=True).start()

    def run(self, cfg):
        try:
            self.pipeline(cfg)
        except Exception as e:
            self.log(f"Ошибка: {e}")
        finally:
            self.set_busy(False)

    # --- проверка через GitHub ---
    def pipeline(self, cfg):
        repo, apk = cfg["repo"], cfg["path"]
        h = {"Authorization": f"Bearer {cfg['token']}", "Accept": "application/vnd.github+json"}
        if not cfg["token"]:
            return self.log("Введите GitHub токен.")
        if not os.path.isfile(apk):
            return self.log("Файл не найден. Проверьте путь и доступ к файлам.")
        size = os.path.getsize(apk) / 1048576
        if size > MAX_MB:
            return self.log(f"APK слишком большой ({size:.0f} МБ), лимит {MAX_MB} МБ.")

        self.log(f"1/4 Загрузка APK ({size:.1f} МБ)...")
        url = f"{API}/repos/{repo}/contents/{REMOTE}"
        body = {"message": "upload apk", "branch": "main",
                "content": base64.b64encode(open(apk, "rb").read()).decode()}
        r = requests.get(url, headers=h, params={"ref": "main"}, timeout=60)
        if r.status_code == 200:
            body["sha"] = r.json()["sha"]
        r = requests.put(url, headers=h, json=body, timeout=900)
        if r.status_code not in (200, 201):
            return self.log(f"Не удалось загрузить: {r.status_code} {r.text[:200]}")

        self.log("2/4 Запуск проверки...")
        t0 = datetime.utcnow() - timedelta(seconds=30)
        r = requests.post(f"{API}/repos/{repo}/actions/workflows/{WORKFLOW}/dispatches",
                          headers=h, timeout=60,
                          json={"ref": "main", "inputs": {"apk_path": REMOTE}})
        if r.status_code != 204:
            return self.log(f"Не удалось запустить: {r.status_code} {r.text[:200]}")

        self.log("3/4 Ожидание результата (1-3 мин)...")
        run = None
        for _ in range(120):
            time.sleep(8)
            runs = requests.get(f"{API}/repos/{repo}/actions/runs", headers=h, timeout=60,
                                params={"event": "workflow_dispatch", "per_page": 5}).json()
            for x in runs.get("workflow_runs", []):
                created = datetime.strptime(x["created_at"], "%Y-%m-%dT%H:%M:%SZ")
                if created >= t0:
                    run = x
                    break
            if run and run["status"] == "completed":
                break
        if not run or run["status"] != "completed":
            return self.log("Время ожидания вышло. Смотрите вкладку Actions на GitHub.")

        self.log(f"Итог запуска: {run['conclusion']}")
        arts = requests.get(f"{API}/repos/{repo}/actions/runs/{run['id']}/artifacts",
                            headers=h, timeout=60).json().get("artifacts", [])
        art = next((a for a in arts if a["name"] == "scan-result"), None)
        if not art:
            return self.log("Результата нет (проверка завершилась ошибкой). Смотрите Actions на GitHub.")

        self.log("4/4 Скачивание результата...")
        z = zipfile.ZipFile(io.BytesIO(requests.get(art["archive_download_url"], headers=h,
                                                    timeout=300).content))
        out_dir = "/storage/emulated/0/Download"
        if not os.access(out_dir, os.W_OK):
            out_dir = os.path.dirname(self.cfg_path)
        res = {"report": "", "patched": None}
        for name in z.namelist():
            data = z.read(name)
            if name.endswith("report.txt"):
                res["report"] = data.decode(errors="ignore")
                self.log("\n" + res["report"])
            elif name.endswith(".apk"):
                dst = os.path.join(out_dir, os.path.basename(name))
                open(dst, "wb").write(data)
                res["patched"] = dst
                self.log(f"\nИсправленный APK сохранён: {dst}")
        self.log("\nГотово.")
        return res


class ScanApp(App):
    def build(self):
        self.panel = Panel(os.path.join(self.user_data_dir, "config.json"))
        return self.panel

    def on_start(self):
        if not ANDROID:
            return
        try:
            android_activity.bind(on_new_intent=self.on_new_intent)
            self.on_new_intent(j_activity().getIntent())
        except Exception:
            pass

    def on_new_intent(self, intent):
        r = read_intent(intent)
        if r:
            Clock.schedule_once(lambda dt: self.panel.on_apk_opened(*r))

    def on_pause(self):
        return True

    def on_resume(self):
        pass


if __name__ == "__main__":
    ScanApp().run()
