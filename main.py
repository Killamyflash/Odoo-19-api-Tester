#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Odoo 19 API Test Tool (Windows-friendly)
----------------------------------------
Ein kleines GUI-Tool zum Testen der Odoo v19 JSON-2 API.

Funktionen:
- Eingabefelder für Base-URL, DB-Name (optional), API-Key (Bearer)
- Auswahl von Model und Methode (z. B. res.partner / search_read)
- Freies JSON-Payload-Feld mit Vorlagen-Buttons (search_read, create, write, unlink)
- Response-Panel mit Pretty-JSON-Ausgabe
- Fehler- und Statusanzeige
- Speichert Einstellungen in odoo_api_tester.ini im selben Ordner

Voraussetzungen:
    pip install requests

Optional: Exe bauen (unter Windows):
    pip install pyinstaller
    pyinstaller --noconsole --onefile --name OdooAPITester main.py

Autor: ChatGPT
Lizenz: MIT
"""

import json
import os
import traceback
import configparser
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText

try:
    import requests
except ImportError:
    raise SystemExit("Das Paket 'requests' fehlt. Bitte mit 'pip install requests' installieren.")

APP_TITLE = "Odoo 19 API Tester - Prime IT"
INI_FILE = "odoo_api_tester.ini"
DEFAULT_PAYLOADS = {
    "search_read": {
        "context": {"lang": "de_DE"},
        "domain": [["is_company", "=", True]],
        "fields": ["id", "name", "email"],
        "limit": 5
    },
    "create": {
        "vals": {
            "name": "API Test GmbH",
            "email": "apitest@example.com"
        }
    },
    "write": {
        "ids": [1],
        "vals": {
            "phone": "+49 30 123456"
        }
    },
    "unlink": {
        "ids": [1]
    }
}

class OdooApiTester(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        # Größere Standardgröße; Tk wählt passende DPI-Scaling unter Windows
        self.geometry("1000x700")
        self.minsize(900, 600)

        self._build_ui()
        self._load_settings()

    # ---------------- UI -----------------
    def _build_ui(self):
        root = ttk.Frame(self)
        root.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Status var früh initialisieren, bevor _set_status irgendwo genutzt wird
        self.status_var = tk.StringVar(value="Bereit.")

        # Connection frame
        conn = ttk.LabelFrame(root, text="Verbindung")
        conn.pack(fill=tk.X, pady=(0, 10))

        self.base_url_var = tk.StringVar(value="https://mein.odoo.com")
        self.db_var = tk.StringVar()
        self.api_key_var = tk.StringVar()
        self.verify_ssl_var = tk.BooleanVar(value=True)

        ttk.Label(conn, text="Base URL:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(conn, textvariable=self.base_url_var, width=40).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(conn, text="Datenbank (optional):").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(conn, textvariable=self.db_var, width=25).grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)

        ttk.Label(conn, text="API Key (Bearer):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(conn, textvariable=self.api_key_var, width=40, show="•").grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Checkbutton(conn, text="SSL-Zertifikat prüfen", variable=self.verify_ssl_var).grid(row=1, column=2, sticky=tk.W, padx=5, pady=5)

        ttk.Button(conn, text="Einstellungen speichern", command=self._save_settings).grid(row=1, column=3, sticky=tk.E, padx=5, pady=5)

        for i in range(4):
            conn.columnconfigure(i, weight=1)

        # Request frame
        req = ttk.LabelFrame(root, text="Request")
        req.pack(fill=tk.BOTH, expand=True)

        self.model_var = tk.StringVar(value="res.partner")
        self.method_var = tk.StringVar(value="search_read")

        ttk.Label(req, text="Model:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(req, textvariable=self.model_var, width=30).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(req, text="Methode:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        method_box = ttk.Combobox(req, textvariable=self.method_var, width=27,
                                  values=["search", "read", "search_read", "create", "write", "unlink", "name_search", "fields_get"])
        method_box.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)

        ttk.Button(req, text="Vorlage search_read", command=lambda: self._load_template("search_read")).grid(row=0, column=4, padx=5, pady=5)
        ttk.Button(req, text="Vorlage create", command=lambda: self._load_template("create")).grid(row=0, column=5, padx=5, pady=5)
        ttk.Button(req, text="Vorlage write", command=lambda: self._load_template("write")).grid(row=0, column=6, padx=5, pady=5)
        ttk.Button(req, text="Vorlage unlink", command=lambda: self._load_template("unlink")).grid(row=0, column=7, padx=5, pady=5)

        # Payload editor
        ttk.Label(req, text="Payload (JSON):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=(10, 5))
        self.payload_txt = ScrolledText(req, wrap=tk.NONE, height=12)
        self.payload_txt.grid(row=2, column=0, columnspan=8, sticky="nsew", padx=5, pady=(0, 10))
        self._load_template("search_read")

        # Send row
        ttk.Button(req, text="Senden", command=self._send_request).grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Button(req, text="Test-Verbindung", command=self._test_connection).grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Button(req, text="Payload laden…", command=self._open_payload_file).grid(row=3, column=2, padx=5, pady=5, sticky=tk.W)
        ttk.Button(req, text="Payload speichern…", command=self._save_payload_file).grid(row=3, column=3, padx=5, pady=5, sticky=tk.W)

        # Quick Actions
        quick = ttk.LabelFrame(root, text="Schnellaktionen")
        quick.pack(fill=tk.X, pady=(10, 0))

        ttk.Button(quick, text="Alle Produkte abrufen", command=self._qa_fetch_all_products).grid(row=0, column=0, padx=5, pady=8, sticky=tk.W)
        ttk.Button(quick, text="Alle Kontakte abrufen", command=self._qa_fetch_all_contacts).grid(row=0, column=1, padx=5, pady=8, sticky=tk.W)
        ttk.Button(quick, text="Letzte 10 Änderungen (aktuelles Modell)", command=self._qa_last_changes_current_model).grid(row=0, column=2, padx=5, pady=8, sticky=tk.W)

        ttk.Button(quick, text="System-Protokoll: letzte 10 Änderungen", command=self._qa_system_last_changes).grid(row=0, column=3, padx=5, pady=8, sticky=tk.W)

        for i in range(4):
            quick.columnconfigure(i, weight=1)

        for i in range(8):
            req.columnconfigure(i, weight=1)
        req.rowconfigure(2, weight=1)

        # Response frame
        resp = ttk.LabelFrame(root, text="Response")
        resp.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        self.response_txt = ScrolledText(resp, wrap=tk.NONE)
        self.response_txt.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Status bar
        status = ttk.Label(self, textvariable=self.status_var, anchor=tk.W, relief=tk.SUNKEN)
        status.pack(side=tk.BOTTOM, fill=tk.X)

    # ------------- Settings -------------
    def _load_settings(self):
        if not os.path.exists(INI_FILE):
            return
        cfg = configparser.ConfigParser()
        cfg.read(INI_FILE, encoding="utf-8")
        if "connection" in cfg:
            c = cfg["connection"]
            self.base_url_var.set(c.get("base_url", self.base_url_var.get()))
            self.db_var.set(c.get("db", ""))
            self.api_key_var.set(c.get("api_key", ""))
            self.verify_ssl_var.set(c.getboolean("verify_ssl", True))

    def _save_settings(self):
        cfg = configparser.ConfigParser()
        cfg["connection"] = {
            "base_url": self.base_url_var.get().strip(),
            "db": self.db_var.get().strip(),
            "api_key": self.api_key_var.get().strip(),
            "verify_ssl": str(self.verify_ssl_var.get()),
        }
        with open(INI_FILE, "w", encoding="utf-8") as f:
            cfg.write(f)
        self._set_status("Einstellungen gespeichert.")

    # ------------- Helpers --------------
    def _set_status(self, text):
        ts = datetime.now().strftime("%H:%M:%S")
        try:
            self.status_var.set(f"[{ts}] {text}")
        except Exception:
            pass

    def _load_template(self, key):
        payload = DEFAULT_PAYLOADS.get(key, {})
        self.payload_txt.delete("1.0", tk.END)
        self.payload_txt.insert(tk.END, json.dumps(payload, indent=2, ensure_ascii=False))
        self._set_status(f"Vorlage '{key}' geladen.")

    def _open_payload_file(self):
        path = filedialog.askopenfilename(title="Payload laden", filetypes=[("JSON", "*.json"), ("Alle Dateien", "*.*")])
        if not path:
            return
        with open(path, "r", encoding="utf-8") as f:
            data = f.read()
        self.payload_txt.delete("1.0", tk.END)
        self.payload_txt.insert(tk.END, data)
        self._set_status(f"Payload aus Datei geladen: {os.path.basename(path)}")

    def _save_payload_file(self):
        path = filedialog.asksaveasfilename(title="Payload speichern", defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.payload_txt.get("1.0", tk.END).strip())
        self._set_status(f"Payload gespeichert: {os.path.basename(path)}")

    def _headers(self):
        api_key = self.api_key_var.get().strip()
        headers = {
            "Content-Type": "application/json; charset=utf-8",
        }
        if api_key:
            headers["Authorization"] = f"bearer {api_key}"
        db = self.db_var.get().strip()
        if db:
            headers["X-Odoo-Database"] = db
        return headers

    def _build_url(self):
        base = self.base_url_var.get().strip().rstrip("/")
        model = self.model_var.get().strip()
        method = self.method_var.get().strip()
        if not base or not model or not method:
            raise ValueError("Base URL, Model und Methode dürfen nicht leer sein.")
        return f"{base}/json/2/{model}/{method}"


    def _api_post(self, model: str, method: str, payload: dict):
        """Low-level POST wrapper to Odoo JSON-2 API."""
        import requests
        base = self.base_url_var.get().strip().rstrip("/")
        url = f"{base}/json/2/{model}/{method}"
        headers = self._headers()
        verify_ssl = self.verify_ssl_var.get()
        r = requests.post(url, headers=headers, json=payload, timeout=60, verify=verify_ssl)
        return r

    def _fetch_all(self, model: str, fields: list, domain=None, order=None, batch_size: int = 200, max_records: int = 5000):
        """Fetch many records in batches via search_read. Returns list of dicts."""
        domain = domain or []
        offset = 0
        results = []
        while True:
            payload = {
                "domain": domain,
                "fields": fields,
                "limit": min(batch_size, max_records - len(results)),
                "offset": offset,
            }
            if order:
                payload["order"] = order
            r = self._api_post(model, "search_read", payload)
            try:
                data = r.json()
            except Exception:
                raise RuntimeError(f"Serverantwort ist kein JSON: {r.text[:2000]}")
            # Accept both {"jsonrpc":"2.0","result":[...]} and {"result":{"records":[...]}} or plain list
            if isinstance(data, list):
                chunk = data
            else:
                result = data.get("result", data)
                if isinstance(result, dict) and "records" in result:
                    chunk = result["records"]
                elif isinstance(result, list):
                    chunk = result
                else:
                    raise RuntimeError(f"Unerwartete Antwortstruktur: {str(data)[:2000]}")

            if not chunk:
                break

            results.extend(chunk)
            if len(results) >= max_records:
                break
            offset += len(chunk)

        return results

    def _show_json(self, payload_dict, header_text=""):
        self.response_txt.delete("1.0", "end")
        if header_text:
            self.response_txt.insert("end", header_text + "\n\n")
        import json as _json
        self.response_txt.insert("end", _json.dumps(payload_dict, indent=2, ensure_ascii=False))
        self.response_txt.see("end")

    def _pretty_response(self, r):
        try:
            data = r.json()
            pretty = json.dumps(data, indent=2, ensure_ascii=False)
        except Exception:
            pretty = r.text
        meta = f"Status: {r.status_code}\nURL: {r.request.method} {r.url}\n"
        return meta + "\n" + pretty

    def _send_request(self):
        import requests
        url = None
        try:
            url = self._build_url()
            payload_text = self.payload_txt.get("1.0", tk.END).strip() or "{}"
            try:
                payload = json.loads(payload_text)
            except json.JSONDecodeError as e:
                messagebox.showerror("JSON-Fehler", f"Payload ist kein gültiges JSON:\n{e}")
                return

            headers = self._headers()
            verify_ssl = self.verify_ssl_var.get()

            self._set_status("Sende Request…")
            r = requests.post(url, headers=headers, json=payload, timeout=60, verify=verify_ssl)

            self.response_txt.delete("1.0", tk.END)
            self.response_txt.insert(tk.END, self._pretty_response(r))
            self._set_status("Antwort erhalten.")
        except Exception as e:
            self.response_txt.delete("1.0", tk.END)
            self.response_txt.insert(tk.END, f"Fehler beim Senden an {url or '-'}:\n{e}\n\nTraceback:\n{traceback.format_exc()}")
            self._set_status("Fehler – Details siehe Response.")

    def _test_connection(self):
        old_model = self.model_var.get()
        old_method = self.method_var.get()
        old_payload = self.payload_txt.get("1.0", tk.END)
        try:
            self.model_var.set("res.partner")
            self.method_var.set("search_read")
            self.payload_txt.delete("1.0", tk.END)
            self.payload_txt.insert(tk.END, json.dumps({"fields": ["id", "name"], "limit": 1}, indent=2))
            self._send_request()
            self._set_status("Verbindungstest ausgeführt.")
        finally:
            self.model_var.set(old_model)
            self.method_var.set(old_method)
            self.payload_txt.delete("1.0", tk.END)
            self.payload_txt.insert(tk.END, old_payload)

    # ------------- Quick Actions -------------
    def _qa_fetch_all_products(self):
        """Fetch all products in batches (product.product)."""
        try:
            self._set_status("Produkte werden geladen ...")
            fields = ["id", "name", "default_code", "type", "list_price", "write_date"]
            data = self._fetch_all("product.product", fields=fields, domain=[], order=None, batch_size=200, max_records=10000)
            out = {
                "summary": {"count": len(data), "model": "product.product"},
                "records": data,
            }
            self._show_json(out, header_text=f"{len(data)} Produkte geladen.")
            self._set_status(f"{len(data)} Produkte geladen.")
        except Exception as e:
            self._show_json({"error": str(e)} , header_text="Fehler beim Laden der Produkte")
            self._set_status("Fehler – Details im Response-Bereich.")

    def _qa_fetch_all_contacts(self):
        """Fetch all contacts in batches (res.partner)."""
        try:
            self._set_status("Kontakte werden geladen ...")
            fields = ["id", "name", "email", "phone", "is_company", "customer_rank", "supplier_rank", "write_date"]
            domain = [["active", "=", True]]
            data = self._fetch_all("res.partner", fields=fields, domain=domain, order=None, batch_size=200, max_records=10000)
            out = {
                "summary": {"count": len(data), "model": "res.partner"},
                "records": data,
            }
            self._show_json(out, header_text=f"{len(data)} Kontakte geladen.")
            self._set_status(f"{len(data)} Kontakte geladen.")
        except Exception as e:
            self._show_json({"error": str(e)} , header_text="Fehler beim Laden der Kontakte")
            self._set_status("Fehler – Details im Response-Bereich.")

    def _qa_system_last_changes(self):
        """System-Protokoll: letzte 10 Änderungen quer über alle Modelle via mail.message + mail.tracking.value."""
        try:
            self._set_status("Lade letzte 10 Änderungen (System-Protokoll) ...")
            # 1) Hole die letzten 10 Nachrichten mit Tracking-Werten
            msg_payload = {
                "domain": [["tracking_value_ids", "!=", False]],
                "fields": ["id", "date", "model", "res_id", "record_name", "author_id", "tracking_value_ids"],
                "limit": 10,
                "order": "date desc",
            }
            r = self._api_post("mail.message", "search_read", msg_payload)
            data = r.json()
            # normalize
            if isinstance(data, list):
                messages = data
            else:
                messages = data.get("result", data)
                if isinstance(messages, dict) and "records" in messages:
                    messages = messages["records"]
            if not isinstance(messages, list):
                raise RuntimeError(f"Unerwartete Antwortstruktur für mail.message: {str(data)[:2000]}")

            msg_ids = [m["id"] for m in messages if isinstance(m, dict) and "id" in m]
            if not msg_ids:
                self._show_json({"summary": {"count": 0}, "records": []}, header_text="Keine Änderungen gefunden.")
                self._set_status("Keine Änderungen gefunden.")
                return

            # 2) Hole Tracking-Details zu diesen Nachrichten
            tv_payload = {
                "domain": [["mail_message_id", "in", msg_ids]],
                "fields": ["mail_message_id", "field", "field_desc", "old_value_char", "new_value_char"],
                "limit": 1000,
            }
            r2 = self._api_post("mail.tracking.value", "search_read", tv_payload)
            data2 = r2.json()
            if isinstance(data2, list):
                tracking_vals = data2
            else:
                tracking_vals = data2.get("result", data2)
                if isinstance(tracking_vals, dict) and "records" in tracking_vals:
                    tracking_vals = tracking_vals["records"]
            if not isinstance(tracking_vals, list):
                tracking_vals = []

            # 3) index per message id
            by_msg = {}
            for tv in tracking_vals:
                mid = tv.get("mail_message_id")
                if isinstance(mid, list):
                    # many2one might come as [id, display_name] – Odoo json often returns this for x2many? we'll normalize
                    mid = mid[0]
                by_msg.setdefault(mid, []).append(tv)

            # 4) assemble output
            records = []
            for m in messages:
                mid = m.get("id")
                rec = {
                    "date": m.get("date"),
                    "model": m.get("model"),
                    "res_id": m.get("res_id"),
                    "record_name": m.get("record_name"),
                    "author": m.get("author_id"),
                    "changes": by_msg.get(mid, []),
                }
                records.append(rec)

            out = {
                "summary": {"count": len(records)},
                "records": records,
            }
            self._show_json(out, header_text="System-Protokoll: letzte 10 Änderungen")
            self._set_status("Fertig.")
        except Exception as e:
            self._show_json({"error": str(e)}, header_text="Fehler beim Laden des System-Protokolls")
            self._set_status("Fehler – Details im Response-Bereich.")

    def _qa_last_changes_current_model(self):
        """Fetch last 10 changes (by write_date desc) for the currently selected model."""
        try:
            model = self.model_var.get().strip() or "res.partner"
            self._set_status(f"Letzte 10 Änderungen für {model} ...")
            fields = ["id", "display_name", "write_date"]
            payload = {
                "domain": [],
                "fields": fields,
                "limit": 10,
                "order": "write_date desc",
            }
            r = self._api_post(model, "search_read", payload)
            data = r.json()
            # Accept list, dict with result, dict with result.records
            if isinstance(data, list):
                result = data
            else:
                result = data.get("result", data)
                if isinstance(result, dict) and "records" in result:
                    result = result["records"]
            out = {
                "summary": {"count": len(result) if isinstance(result, list) else 0, "model": model},
                "records": result if isinstance(result, list) else result,
            }
            self._show_json(out, header_text=f"Letzte 10 Änderungen für {model}")
            self._set_status("Fertig.")
        except Exception as e:
            self._show_json({"error": str(e)} , header_text="Fehler beim Laden der letzten Änderungen")
            self._set_status("Fehler – Details im Response-Bereich.")


def main():
    app = OdooApiTester()
    app.mainloop()


if __name__ == "__main__":
    main()
