# Odoo 19 API Tester (Windows)

Ein leichtgewichtiges GUI-Tool (Python + Tkinter) zum Testen und Debuggen der **Odoo v19 JSON‑2 API**. Es ermöglicht schnelle Abfragen und Tests, ohne komplexe Postman-Collections einrichten zu müssen.

> **Author:** Cenk Özdemir ([co@prime-it.de](mailto:co@prime-it.de))

---

## 🚀 Features

* **Einfache Verbindung:** Konfiguration von Base-URL, Datenbank und API-Key (Bearer).
* **Flexible Abfragen:** Freie Wahl von Model und Methode (z. B. `search_read`).
* **Schnellaktionen (Presets):**
    * 📦 **Alle Produkte abrufen** (`product.product`, batchweise)
    * 👥 **Alle Kontakte abrufen** (`res.partner`, nur aktive)
    * 🕒 **Letzte 10 Änderungen** (basierend auf `write_date` des gewählten Modells)
* **🆕 System-Protokoll:**
    * Zeigt die **letzten 10 Änderungen systemweit** an (quer über alle Modelle via `mail.message` + `mail.tracking.value`).

## 🛠 Schnellstart (Windows)

1.  **Herunterladen & Entpacken:**
    Lade das Repository als ZIP herunter und entpacke es in einen beliebigen Ordner.
2.  **Starten:**
    Doppelklicke auf die `run.bat`.
    *Das Skript installiert automatisch fehlende Requirements und startet die GUI.*
3.  **Verwenden:**
    * **Base-URL/IP** eintragen (z. B. `http://192.168.1.50:8069` oder `https://dein.odoo.com`).
    * Optional **Datenbank** setzen (setzt den `X-Odoo-Database` Header).
    * **API-Key** einfügen.
    * **Model** und **Methode** wählen.
    * JSON-Payload anpassen und auf **Senden** klicken.

## 📦 EXE erstellen (Optional)

Falls du das Tool als eigenständige `.exe` Datei ohne Python-Installation weitergeben möchtest, kannst du PyInstaller verwenden:

```bat
py -m pip install pyinstaller
py -m PyInstaller --noconsole --onefile --name OdooAPITester main.py