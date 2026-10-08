"""Панель управления: отправляет APK в GitHub, запускает проверку и забирает результат."""
import base64, io, json, os, threading, time, zipfile
from datetime import datetime, timedelta

import requests
from kivy.app import App
from kivy.clock import Clock
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput

API = "https://api.github.com"
WORKFLOW = "scan-apk.yml"
REMOTE = "incoming/app.apk"
MAX_MB = 90


class Panel(BoxLayout):
    def __init__(self, cfg_path, **kw):
        super().__init__(orientation="vertical", padding=10, spacing=8, **kw)
        self.cfg_path = cfg_path
        cfg = {}
        try:
            cfg = json.load(open(cfg_path))
        except Exception:
            pass
        self.add_widget(Label(text="APK Scanner v0.2", size_hint_y=None, height=40, font_size=22))
        self.token = TextInput(text=cfg.get("token", ""), hint_text="GitHub токен", password=True,
                               multiline=False, size_hint_y=None, height=44)
        self.repo = TextInput(text=cfg.get("repo", "abdullaevrobert9-glitch/NikeBossSSF"),
                              hint_text="владелец/репозиторий", multiline=False,
                              size_hint_y=None, height=44)
        self.path = TextInput(text=cfg.get("path", "/storage/emulated/0/Download/"),
                              hint_text="Путь к APK", multiline=False,
                              size_hint_y=None, height=44)
        for w in (self.token, self.repo, self.path):
            self.add_widget(w)
        pick = Button(text="Выбрать APK...", size_hint_y=None, height=54)
        pick.bind(on_release=lambda *_: self.pick_file())
        self.add_widget(pick)
        self.btn = Button(text="Проверить и исправить", size_hint_y=None, height=54)
        self.btn.bind(on_release=lambda *_: self.start())
        self.add_widget(self.btn)
        sv = ScrollView()
        self.out = Label(text="Готово к работе.", size_hint_y=None, halign="left", valign="top")
        self.out.bind(width=lambda *_: setattr(self.out, "text_size", (self.out.width, None)))
        self.out.bind(texture_size=lambda *_: setattr(self.out, "height", self.out.texture_size[1]))
        sv.add_widget(self.out)
        self.add_widget(sv)

    def pick_file(self):
        start = "/storage/emulated/0/Download"
        if not os.path.isdir(start):
            start = "/storage/emulated/0"
        chooser = FileChooserListView(path=start, filters=["*.apk"])
        box = BoxLayout(orientation="vertical", spacing=6)
        box.add_widget(chooser)
        row = BoxLayout(size_hint_y=None, height=54, spacing=6)
        ok = Button(text="Выбрать")
        cancel = Button(text="Отмена")
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
        Clock.schedule_once(lambda dt: setattr(self.btn, "disabled", busy))

    def start(self):
        cfg = {"token": self.token.text.strip(), "repo": self.repo.text.strip(),
               "path": self.path.text.strip()}
        try:
            json.dump(cfg, open(self.cfg_path, "w"))
        except Exception:
            pass
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

    def pipeline(self, cfg):
        repo, apk = cfg["repo"], cfg["path"]
        h = {"Authorization": f"Bearer {cfg['token']}", "Accept": "application/vnd.github+json"}
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
        for name in z.namelist():
            data = z.read(name)
            if name.endswith("report.txt"):
                self.log("\n" + data.decode(errors="ignore"))
            elif name.endswith(".apk"):
                dst = os.path.join(out_dir, os.path.basename(name))
                open(dst, "wb").write(data)
                self.log(f"\nИсправленный APK сохранён: {dst}")
        self.log("\nГотово.")


class ScanApp(App):
    def build(self):
        return Panel(os.path.join(self.user_data_dir, "config.json"))


if __name__ == "__main__":
    ScanApp().run()
