#!/usr/bin/env python3
"""
otxc-server: a minimal OTXC (odd tar.xz containers) registry server.

Pure stdlib. One manifest.json tree, HTTP Basic Auth, PUT/DELETE/PATCH backend.

Data layout (under --data-dir, default ./otxc_data):
  manifest.json   - the registry tree (namespaces -> image -> tag -> entry)
  users.json      - ordered list of users; users[0] is the admin
  storage/        - uploaded file blobs (internally hosted images)

manifest.json shape:
{
  "main": { "<image>": "redirect:<namespace>/<image>/<tag>", ... },
  "<namespace>": {
    "<image>": {
      "<tag>": {
        "url": "/path/to/file.tar.xz" | "http(s)://..." | "ftp://..." | "redirect:ns/image/tag",
        "source": "https://...",          (optional)
        "private": false,                  (optional, default false)
        "allowed": ["user1", "user2"]       (optional, only matters if private)
      }
    }
  }
}

Ownership rule: a user may PUT/PATCH/DELETE under namespace == their own username.
The admin (users[0]) may additionally edit the reserved "main" namespace.

Run:
  ./otxc_server.py --port 8080 --data-dir ./otxc_data
First run creates an empty manifest and prompts you to register the admin user
via the normal PUT-a-user flow (see /_users).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, unquote

LOCK = threading.Lock()


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return digest.hex(), salt


class Store:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.storage_dir = os.path.join(data_dir, "storage")
        self.manifest_path = os.path.join(data_dir, "manifest.json")
        self.users_path = os.path.join(data_dir, "users.json")
        os.makedirs(self.storage_dir, exist_ok=True)
        if not os.path.exists(self.manifest_path):
            self._write_json(self.manifest_path, {"main": {}})
        if not os.path.exists(self.users_path):
            self._write_json(self.users_path, [])

    @staticmethod
    def _write_json(path: str, obj):
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(obj, f, indent=2)
        os.replace(tmp, path)

    def manifest(self) -> dict:
        with open(self.manifest_path) as f:
            return json.load(f)

    def save_manifest(self, m: dict):
        self._write_json(self.manifest_path, m)

    def users(self) -> list[dict]:
        with open(self.users_path) as f:
            return json.load(f)

    def save_users(self, u: list[dict]):
        self._write_json(self.users_path, u)

    def find_user(self, username: str) -> dict | None:
        for u in self.users():
            if u["username"] == username:
                return u
        return None

    def is_admin(self, username: str) -> bool:
        users = self.users()
        return bool(users) and users[0]["username"] == username

    def check_auth(self, username: str, password: str) -> bool:
        u = self.find_user(username)
        if not u:
            return False
        digest, _ = hash_password(password, u["salt"])
        return hmac.compare_digest(digest, u["hash"])


def resolve_redirect(manifest: dict, ns: str, image: str, tag: str, depth: int = 0) -> tuple[str, str, str] | None:
    """Follow redirect: chains, return the final (ns, image, tag) or None."""
    if depth > 10:
        return None
    node = manifest.get(ns, {}).get(image)
    if node is None:
        return None
    if isinstance(node, str):
        # main-style shortcut: "redirect:ns/image/tag" with no tag level
        if node.startswith("redirect:"):
            target = node[len("redirect:"):]
            parts = target.split("/")
            if len(parts) == 3:
                return resolve_redirect(manifest, parts[0], parts[1], parts[2], depth + 1)
        return None
    entry = node.get(tag)
    if entry is None:
        return None
    url = entry.get("url", "")
    if url.startswith("redirect:"):
        target = url[len("redirect:"):]
        parts = target.split("/")
        if len(parts) == 3:
            return resolve_redirect(manifest, parts[0], parts[1], parts[2], depth + 1)
        return None
    return ns, image, tag


def find_entry_by_url(manifest: dict, url_path: str) -> dict | None:
    """Find a tag entry whose stored url matches this exact literal path."""
    for ns, images in manifest.items():
        for image, node in images.items():
            if isinstance(node, str):
                continue
            for tag, entry in node.items():
                if entry.get("url") == url_path:
                    return entry
    return None


def filter_manifest_for_user(manifest: dict, username: str | None, is_admin: bool) -> dict:
    if is_admin:
        return manifest
    out = {}
    for ns, images in manifest.items():
        ns_out = {}
        for image, node in images.items():
            if isinstance(node, str):
                ns_out[image] = node
                continue
            tags_out = {}
            for tag, entry in node.items():
                if entry.get("private"):
                    allowed = entry.get("allowed", [])
                    if username is None or username not in allowed:
                        continue
                tags_out[tag] = entry
            if tags_out:
                ns_out[image] = tags_out
        if ns_out:
            out[ns] = ns_out
    return out


class Handler(BaseHTTPRequestHandler):
    store: Store = None  # set by main()

    server_version = "otxc/1.0"

    def log_message(self, fmt, *args):
        pass

    # -- auth helpers --------------------------------------------------
    def get_auth(self) -> tuple[str, str] | None:
        header = self.headers.get("Authorization")
        if not header or not header.startswith("Basic "):
            return None
        try:
            raw = base64.b64decode(header[len("Basic "):]).decode()
            username, _, password = raw.partition(":")
            return username, password
        except Exception:
            return None

    def require_auth(self) -> str | None:
        """Returns authenticated username, or None (and writes a 401) if auth fails."""
        creds = self.get_auth()
        if not creds or not self.store.check_auth(*creds):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="otxc"')
            self.end_headers()
            return None
        return creds[0]

    def can_edit_namespace(self, username: str, ns: str) -> bool:
        if ns == "main":
            return self.store.is_admin(username)
        return username == ns

    # -- json helpers ----------------------------------------------------
    def send_json(self, code: int, obj):
        body = json.dumps(obj, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    # -- routing -----------------------------------------------------
    def do_GET(self):
        path = unquote(urlparse(self.path).path)
        if path == "/manifest.json":
            return self.handle_get_manifest()
        if path == "/_users" and self.path.endswith("?list"):
            return self.handle_list_users()
        # serve a literal storage path as published in manifest "url" fields
        # (e.g. GET /odd/archlinux/latest.tar.xz), independent of tag lookup
        literal = os.path.normpath(path.lstrip("/"))
        if not literal.startswith("..") and os.path.isfile(os.path.join(self.store.storage_dir, literal)):
            return self.serve_static_file(literal, path)
        parts = [p for p in path.split("/") if p]
        if len(parts) == 3:
            return self.handle_get_file(*parts)
        self.send_json(404, {"error": "not found"})

    def serve_static_file(self, rel_path: str, url_path: str):
        with LOCK:
            m = self.store.manifest()
        entry = find_entry_by_url(m, url_path)
        if entry and entry.get("private"):
            creds = self.get_auth()
            username = creds[0] if creds and self.store.check_auth(*creds) else None
            allowed = entry.get("allowed", [])
            if username is None or (username not in allowed and not self.store.is_admin(username)):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="otxc"')
                self.end_headers()
                return
        fpath = os.path.join(self.store.storage_dir, rel_path)
        self.send_response(200)
        self.send_header("Content-Type", "application/x-xz")
        self.send_header("Content-Length", str(os.path.getsize(fpath)))
        self.end_headers()
        with open(fpath, "rb") as f:
            shutil.copyfileobj(f, self.wfile)

    def do_PUT(self):
        path = unquote(urlparse(self.path).path)
        parts = [p for p in path.split("/") if p]
        if path == "/_users":
            return self.handle_create_user()
        if len(parts) == 3:
            return self.handle_put_entry(*parts)
        self.send_json(404, {"error": "not found"})

    def do_PATCH(self):
        path = unquote(urlparse(self.path).path)
        parts = [p for p in path.split("/") if p]
        if len(parts) == 3:
            return self.handle_patch_entry(*parts)
        self.send_json(404, {"error": "not found"})

    def do_DELETE(self):
        path = unquote(urlparse(self.path).path)
        parts = [p for p in path.split("/") if p]
        if len(parts) == 3:
            return self.handle_delete_entry(*parts)
        self.send_json(404, {"error": "not found"})

    # -- manifest read -------------------------------------------------
    def handle_get_manifest(self):
        creds = self.get_auth()
        username = None
        if creds:
            if not self.store.check_auth(*creds):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="otxc"')
                self.end_headers()
                return
            username = creds[0]
        is_admin = username is not None and self.store.is_admin(username)
        with LOCK:
            m = self.store.manifest()
        self.send_json(200, filter_manifest_for_user(m, username, is_admin))

    def handle_get_file(self, ns, image, tag):
        creds = self.get_auth()
        username = creds[0] if creds and self.store.check_auth(*creds) else None
        with LOCK:
            m = self.store.manifest()
        resolved = resolve_redirect(m, ns, image, tag)
        if resolved is None:
            return self.send_json(404, {"error": "no such image/tag"})
        rns, rimage, rtag = resolved
        entry = m[rns][rimage][rtag]
        if entry.get("private"):
            allowed = entry.get("allowed", [])
            if username is None or (username not in allowed and not self.store.is_admin(username)):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="otxc"')
                self.end_headers()
                return
        url = entry["url"]
        if url.startswith("/"):
            fpath = os.path.join(self.store.storage_dir, url.lstrip("/"))
            if not os.path.isfile(fpath):
                return self.send_json(404, {"error": "stored file missing"})
            self.send_response(200)
            self.send_header("Content-Type", "application/x-xz")
            self.send_header("Content-Length", str(os.path.getsize(fpath)))
            self.end_headers()
            with open(fpath, "rb") as f:
                shutil.copyfileobj(f, self.wfile)
        else:
            self.send_response(302)
            self.send_header("Location", url)
            self.end_headers()

    # -- backend writes --------------------------------------------------
    def handle_put_entry(self, ns, image, tag):
        username = self.require_auth()
        if username is None:
            return
        if not self.can_edit_namespace(username, ns):
            return self.send_json(403, {"error": f"not allowed to edit namespace '{ns}'"})
        body = self.read_body()
        if not body:
            return self.send_json(400, {"error": "empty body, expected file bytes"})
        rel_path = f"{ns}/{image}/{tag}.tar.xz"
        fpath = os.path.join(self.store.storage_dir, rel_path)
        os.makedirs(os.path.dirname(fpath), exist_ok=True)
        with open(fpath, "wb") as f:
            f.write(body)
        with LOCK:
            m = self.store.manifest()
            m.setdefault(ns, {}).setdefault(image, {})
            if isinstance(m[ns][image], str):
                return self.send_json(409, {"error": f"{ns}/{image} is a redirect shortcut, not a tag map"})
            existing = m[ns][image].get(tag, {})
            m[ns][image][tag] = {**existing, "url": f"/{rel_path}"}
            self.store.save_manifest(m)
        self.send_json(201, {"ok": True, "ns": ns, "image": image, "tag": tag})

    def handle_patch_entry(self, ns, image, tag):
        username = self.require_auth()
        if username is None:
            return
        if not self.can_edit_namespace(username, ns):
            return self.send_json(403, {"error": f"not allowed to edit namespace '{ns}'"})
        try:
            patch = json.loads(self.read_body() or b"{}")
        except json.JSONDecodeError:
            return self.send_json(400, {"error": "invalid json"})
        with LOCK:
            m = self.store.manifest()
            if ns == "main" and tag == "_":
                # shortcut form: PATCH /main/<image>/_  {"redirect": "ns/image/tag"}
                m.setdefault("main", {})
                if "redirect" in patch:
                    m["main"][image] = f"redirect:{patch['redirect']}"
                self.store.save_manifest(m)
                return self.send_json(200, {"ok": True})
            m.setdefault(ns, {}).setdefault(image, {})
            if isinstance(m[ns][image], str):
                return self.send_json(409, {"error": f"{ns}/{image} is a redirect shortcut"})
            entry = m[ns][image].get(tag, {})
            for key in ("url", "source", "private", "allowed"):
                if key in patch:
                    entry[key] = patch[key]
            m[ns][image][tag] = entry
            self.store.save_manifest(m)
        self.send_json(200, {"ok": True, "entry": entry})

    def handle_delete_entry(self, ns, image, tag):
        username = self.require_auth()
        if username is None:
            return
        if not self.can_edit_namespace(username, ns):
            return self.send_json(403, {"error": f"not allowed to edit namespace '{ns}'"})
        with LOCK:
            m = self.store.manifest()
            if ns == "main":
                if image in m.get("main", {}):
                    del m["main"][image]
                    self.store.save_manifest(m)
                    return self.send_json(200, {"ok": True})
                return self.send_json(404, {"error": "no such entry"})
            entry = m.get(ns, {}).get(image, {}).pop(tag, None) if isinstance(m.get(ns, {}).get(image), dict) else None
            if entry is None:
                return self.send_json(404, {"error": "no such entry"})
            if not m[ns][image]:
                del m[ns][image]
            self.store.save_manifest(m)
        url = entry.get("url", "")
        if url.startswith("/"):
            fpath = os.path.join(self.store.storage_dir, url.lstrip("/"))
            if os.path.isfile(fpath):
                os.remove(fpath)
        self.send_json(200, {"ok": True})

    # -- user management ---------------------------------------------
    def handle_create_user(self):
        """
        First-ever user becomes admin automatically. After that, only the
        admin can create further users.
        """
        try:
            data = json.loads(self.read_body() or b"{}")
            new_username = data["username"]
            new_password = data["password"]
        except (json.JSONDecodeError, KeyError):
            return self.send_json(400, {"error": "expected {\"username\":..., \"password\":...}"})
        with LOCK:
            users = self.store.users()
            if users:
                username = self.require_auth()
                if username is None:
                    return
                if not self.store.is_admin(username):
                    return self.send_json(403, {"error": "only the admin can create users"})
            if self.store.find_user(new_username):
                return self.send_json(409, {"error": "user already exists"})
            digest, salt = hash_password(new_password)
            users.append({"username": new_username, "hash": digest, "salt": salt})
            self.store.save_users(users)
        self.send_json(201, {"ok": True, "username": new_username, "admin": len(users) == 1})

    def handle_list_users(self):
        with LOCK:
            users = self.store.users()
        self.send_json(200, {"users": [u["username"] for u in users], "admin": users[0]["username"] if users else None})


def main():
    ap = argparse.ArgumentParser(description="otxc registry server")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--data-dir", default="./otxc_data")
    args = ap.parse_args()

    Handler.store = Store(args.data_dir)
    httpd = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"otxc server listening on :{args.port}, data dir {args.data_dir}")
    if not Handler.store.users():
        print("no users yet: register the first one (becomes admin) with:")
        print(f'  curl -X PUT localhost:{args.port}/_users -d \'{{"username":"odd","password":"..."}}\'')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
