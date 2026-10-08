[app]
title = APK Scanner
package.name = apkscanner
package.domain = org.nikeboss
source.dir = .
source.include_exts = py
version = 0.4
requirements = python3==3.11.5,hostpython3==3.11.5,kivy==2.3.0,pyjnius,android,requests,urllib3,charset-normalizer,idna,certifi
orientation = portrait
fullscreen = 0
android.permissions = INTERNET,READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE,MANAGE_EXTERNAL_STORAGE,REQUEST_INSTALL_PACKAGES
android.api = 33
android.minapi = 24
android.archs = arm64-v8a
android.ndk = 25b
p4a.branch = v2024.01.21
android.manifest.intent_filters = intent_filters.xml
android.accept_sdk_license = True

[buildozer]
log_level = 2
warn_on_root = 1
