"""Реліз інструментів супроводжувача: перевірка готовності, відтворювана збірка, SBOM (ЛР15–16).

Призначення цільового файлу в репозиторії: tools/release/release_tools.py

Що випускається: «DRS maintainer tools» — tools/drs_release (ЛР4–ЛР8) і tools/drs_hub (ЛР10–ЛР16)
однією версією, тег tools-v<версія>, GitHub Releases. Мод DynamicReloadSpeed сюди НЕ входить: його
єдине джерело — NexusMods (SR-02).

    python tools/release/release_tools.py check [--osv]               готовність до релізу (код 1 — є блокери)
    python tools/release/release_tools.py build --version 1.0.0 [--out DIR]
    python tools/release/release_tools.py verify-repro --version 1.0.0

Запуск — з кореня репозиторію інтерпретатором середовища, де встановлено cryptography
(напр. tools\\drs_hub\\.venv\\Scripts\\python.exe). Збірка бере вміст файлів із коміту HEAD
(git show), а не з робочої теки: незакомічені правки в реліз не потрапляють. ZIP детермінований
(відсортовані записи, час = час коміту, фіксовані атрибути й рівень стиснення) — дві збірки одного
коміту дають однаковий SHA-256.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import zipfile

PRODUCT = "drs-maintainer-tools"
INCLUDE_PREFIXES = ("tools/drs_release/", "tools/drs_hub/")
INCLUDE_FILES = ("LICENSE", "SECURITY.md")
PUBLIC_KEYS = {"release_passport.pub", "release_signing.pub", "report_recipient.pub"}
FORBIDDEN_SUFFIXES = (".key", ".pem", ".secret", ".db", ".sqlite", ".dhbk", ".p12", ".pfx", ".jsonl",
                      "accounts.json", "audit.log")      # два останні — робочі файли drs_release (.gitignore)
SECRET_PATTERNS = (
    (re.compile(rb"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"), "закритий ключ PEM"),
    (re.compile(rb"dhs_[A-Za-z0-9_-]{30,}"), "секрет клієнта drs_hub"),
    (re.compile(rb"dha_[A-Za-z0-9_-]{30,}"), "токен доступу drs_hub"),
    (re.compile(rb"(?i)client_secret\s*[=:]\s*[\"'][A-Za-z0-9]{8,}[\"']"), "client_secret у коді"),
    (re.compile(rb"gh[pousr]_[A-Za-z0-9]{36}"), "токен GitHub"),
)
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.]{1,20})?$")
REPO_URL = "https://github.com/PerepeliakDanylo/program-security--lab-2026-Danylo"
MIN_ZIP_TIME = 315532800          # 1980-01-01: нижня межа часу у форматі ZIP


def git(*args: str, binary: bool = False):
    done = subprocess.run(["git", *args], capture_output=True, check=True, timeout=60)
    return done.stdout if binary else done.stdout.decode("utf-8").strip()


def tracked_files() -> list[str]:
    # -z і quotePath=false: імена з кирилицею приходять як є, а не "\320\267…" у лапках
    return [p for p in git("-c", "core.quotePath=false", "ls-files", "-z").split("\0") if p]


def release_files() -> list[str]:
    tracked = tracked_files()
    files = [p for p in tracked if p.startswith(INCLUDE_PREFIXES)]
    files += [p for p in INCLUDE_FILES if p in tracked]
    return sorted(p for p in files if "/.venv/" not in p and not p.endswith(FORBIDDEN_SUFFIXES))


def pinned_requirements() -> dict[str, str]:
    """{пакет: версія} з requirements.txt обох інструментів; непінований рядок → ''."""
    pins: dict[str, str] = {}
    for path in ("tools/drs_release/requirements.txt", "tools/drs_hub/requirements.txt"):
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8-sig") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                name, sep, version = line.partition("==")
                pins[name.strip().lower()] = version.strip() if sep else ""
    return pins


def _installed(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


# --- SBOM ----------------------------------------------------------------------------
def make_sbom(version: str, commit: str, commit_time: int) -> dict:
    pins = pinned_requirements()
    crypto = pins.get("cryptography") or _installed("cryptography") or "unknown"
    components = [{"type": "library", "bom-ref": f"pkg:pypi/cryptography@{crypto}", "name": "cryptography",
                   "version": crypto, "purl": f"pkg:pypi/cryptography@{crypto}", "scope": "required",
                   "licenses": [{"expression": "Apache-2.0 OR BSD-3-Clause"}]}]
    depends = [f"pkg:pypi/cryptography@{crypto}"]
    crypto_deps = []
    for name in ("cffi", "pycparser"):
        found = _installed(name)
        if found:
            ref = f"pkg:pypi/{name}@{found}"
            components.append({"type": "library", "bom-ref": ref, "name": name, "version": found,
                               "purl": ref, "scope": "required"})
            crypto_deps.append(ref)
    components.append({"type": "platform", "bom-ref": "cpython", "name": "CPython", "version": ">=3.10",
                       "description": "Інтерпретатор; решта — стандартна бібліотека (http.server, ssl, sqlite3, …)"})
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(commit_time))
    dependencies = [{"ref": PRODUCT, "dependsOn": depends + ["cpython"]}]
    if crypto_deps:
        dependencies.append({"ref": f"pkg:pypi/cryptography@{crypto}", "dependsOn": crypto_deps})
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"{REPO_URL}/{PRODUCT}/{version}/{commit}")),
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "component": {"type": "application", "bom-ref": PRODUCT, "name": PRODUCT, "version": version,
                          "licenses": [{"license": {"id": "MIT"}}],
                          "externalReferences": [{"type": "vcs", "url": REPO_URL}],
                          "properties": [{"name": "git:commit", "value": commit}]},
            "tools": {"components": [{"type": "application", "name": "release_tools.py", "version": "1.0.0"}]},
        },
        "components": components,
        "dependencies": dependencies,
    }


# --- збірка ---------------------------------------------------------------------------
def build(version: str, out_dir: str) -> dict:
    if not VERSION_RE.fullmatch(version):
        raise ValueError("версія: MAJOR.MINOR.PATCH[-суфікс]")
    commit = git("rev-parse", "HEAD")
    commit_time = int(git("log", "-1", "--format=%ct"))
    date_time = time.gmtime(max(commit_time, MIN_ZIP_TIME))[:6]
    root = f"{PRODUCT}-{version}"
    entries: dict[str, bytes] = {}
    manifest = []
    for path in release_files():
        blob = git("show", f"HEAD:{path}", binary=True)
        entries[f"{root}/{path}"] = blob
        manifest.append(f"{hashlib.sha256(blob).hexdigest()}  {path}")
    sbom = make_sbom(version, commit, commit_time)
    sbom_bytes = (json.dumps(sbom, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    notes = (f"# {PRODUCT} {version}\n\nКоміт `{commit}`, дата коміту "
             f"{time.strftime('%Y-%m-%d', time.gmtime(commit_time))} (UTC).\n\n"
             "Склад: `tools/drs_release` (автентифікація супроводжувача, доступ, підпис і паспорт релізу) і "
             "`tools/drs_hub` (службовий HTTPS-сервер: OAuth 2.0 Client Credentials, журнал JSON Lines з ланцюгом "
             "SHA-256, наскрізне шифрування звітів тестерів, хеш-ланцюг записів, резервні копії).\n\n"
             "Мод DynamicReloadSpeed сюди не входить — його єдине джерело NexusMods.\n\n"
             "Перевірка: `Get-FileHash <архів> -Algorithm SHA256` має збігтися з `SHA256SUMS.txt`; "
             "вміст — з `MANIFEST.sha256` усередині архіву; склад залежностей — `sbom.cdx.json` (CycloneDX 1.5).\n"
             "Підтримка й повідомлення про вразливості — `SECURITY.md`.\n").encode("utf-8")
    entries[f"{root}/MANIFEST.sha256"] = ("\n".join(manifest) + "\n").encode("utf-8")
    entries[f"{root}/sbom.cdx.json"] = sbom_bytes
    entries[f"{root}/RELEASE_NOTES.md"] = notes
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=date_time)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, entries[name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    os.makedirs(out_dir, exist_ok=True)
    zip_path = os.path.join(out_dir, f"{root}.zip")
    sbom_path = os.path.join(out_dir, f"{root}.cdx.json")
    notes_path = os.path.join(out_dir, f"{root}-RELEASE_NOTES.md")
    for path, data in ((zip_path, buffer.getvalue()), (sbom_path, sbom_bytes), (notes_path, notes)):
        with open(path, "wb") as fh:
            fh.write(data)
    sums = {os.path.basename(p): hashlib.sha256(open(p, "rb").read()).hexdigest() for p in (zip_path, sbom_path)}
    with open(os.path.join(out_dir, "SHA256SUMS.txt"), "w", encoding="ascii", newline="\n") as fh:
        for name in sorted(sums):
            fh.write(f"{sums[name]}  {name}\n")
    return {"zip": zip_path, "sbom": sbom_path, "notes": notes_path, "sha256": sums, "files": len(manifest),
            "commit": commit}


# --- перевірка готовності ---------------------------------------------------------------
def _osv(name: str, version: str) -> tuple[str, str]:
    body = json.dumps({"package": {"name": name, "ecosystem": "PyPI"}, "version": version}).encode("utf-8")
    request = urllib.request.Request("https://api.osv.dev/v1/query", data=body,
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            vulns = json.loads(response.read().decode("utf-8")).get("vulns", [])
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return "WARN", f"OSV недоступний ({exc}) — перевірити вручну https://osv.dev"
    if vulns:
        return "FAIL", f"{name}=={version}: відомі вразливості " + ", ".join(v.get("id", "?") for v in vulns[:8])
    return "OK", f"{name}=={version}: відомих вразливостей в OSV немає"


def check(osv: bool) -> int:
    results: list[tuple[str, str, str]] = []
    branch = git("rev-parse", "--abbrev-ref", "HEAD")
    dirty = [line for line in git("status", "--porcelain").splitlines() if line.strip()]
    results.append(("Гілка й стан дерева", "OK" if branch == "master" and not dirty else "WARN",
                    f"гілка {branch}; незакомічених змін {len(dirty)} (у збірку не потрапляють — вона бере HEAD)"))
    files = tracked_files()
    forbidden = [p for p in files if p.endswith(FORBIDDEN_SUFFIXES) or "/.venv/" in p]
    results.append(("Секретні й робочі файли в репозиторії (*.key, *.pem, *.secret, *.db, копії, журнали, .venv)",
                    "FAIL" if forbidden else "OK", ", ".join(forbidden[:5]) or "немає"))
    hits = []
    for path in files:
        if not os.path.isfile(path) or os.path.getsize(path) > 5 * 1024 * 1024:
            continue
        with open(path, "rb") as fh:
            data = fh.read()
        for pattern, label in SECRET_PATTERNS:
            if pattern.search(data):
                hits.append(f"{path}: {label}")
    results.append(("Секрети у вмісті відстежуваних файлів", "FAIL" if hits else "OK",
                    "; ".join(hits[:5]) or f"перевірено {len(files)} файлів"))
    sys.path.insert(0, os.path.join("tools", "drs_hub"))
    try:
        import hub_config
        cfg = hub_config.HubConfig(data_dir=tempfile.gettempdir())
        cfg.validate()
        safe = not cfg.insecure_http and cfg.host == "127.0.0.1" and cfg.log_level == "info" and cfg.token_ttl_s <= 600
        results.append(("Налаштування сервера за замовчуванням (TLS, loopback, info, токен ≤ 10 хв)",
                        "OK" if safe else "FAIL",
                        f"insecure_http={cfg.insecure_http}, host={cfg.host}, log_level={cfg.log_level}, "
                        f"token_ttl_s={cfg.token_ttl_s}, версія {hub_config.HUB_VERSION}"))
    except Exception as exc:  # noqa: BLE001
        results.append(("Налаштування сервера за замовчуванням", "FAIL", f"{type(exc).__name__}: {exc}"))
    ini_path = os.path.join("dist", "DynamicReloadSpeed.ini")
    if os.path.exists(ini_path):
        with open(ini_path, "r", encoding="utf-8", errors="replace") as fh:
            ini = fh.read()
        forced = re.search(r"(?mi)^\s*ForceAnimReloadRateOffset\s*=\s*0x0*[1-9a-f]", ini)
        debug = re.search(r"(?mi)^\s*LogLevel\s*=\s*debug", ini)
        results.append(("Постачальний INI мода: без примусового офсета й рівня debug",
                        "FAIL" if forced or debug else "OK",
                        "примусовий офсет" if forced else "LogLevel=debug" if debug else "чисто"))
    pins = pinned_requirements()
    unpinned = [name for name, ver in pins.items() if not ver]
    detail = ", ".join(f"{n}=={v}" if v else f"{n} (не зафіксовано)" for n, v in pins.items())
    installed = _installed("cryptography")
    if pins.get("cryptography") and installed and pins["cryptography"] != installed:
        detail += f"; встановлено {installed}"
    results.append(("Версії залежностей зафіксовано (==)", "FAIL" if unpinned or not pins else "OK", detail or "немає"))
    if osv:
        for name, ver in pins.items():
            if ver:
                status, text = _osv(name, ver)
                results.append(("Відомі вразливості (OSV)", status, text))
    child_env = {**os.environ, "PYTHONIOENCODING": "utf-8"}

    def run_selftest(label: str, script: str, cwd: str, timeout: int) -> None:
        try:
            run = subprocess.run([sys.executable, script], cwd=cwd, capture_output=True, timeout=timeout, env=child_env)
        except subprocess.TimeoutExpired:
            results.append((label, "FAIL", f"не завершилася за {timeout} с"))
            return
        tail = run.stdout.decode("utf-8", errors="replace").strip().splitlines()[-1:] or ["(без виводу)"]
        results.append((label, "OK" if run.returncode == 0 else "FAIL", tail[0][:110]))

    run_selftest("Самоперевірка drs_hub", "hub_selftest.py", os.path.join("tools", "drs_hub"), 600)
    for script in ("crypto.py", "integrity.py", "passport.py"):
        if os.path.exists(os.path.join("tools", "drs_release", script)):
            run_selftest(f"Самоперевірка drs_release/{script}", script, os.path.join("tools", "drs_release"), 300)
    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        first, second = build("0.0.0-check", a), build("0.0.0-check", b)
    same = first["sha256"] == second["sha256"]
    results.append(("Відтворюваність збірки (дві збірки HEAD)", "OK" if same else "FAIL",
                    f"zip {list(first['sha256'].values())[0][:16]}… = {list(second['sha256'].values())[0][:16]}…"
                    if same else "SHA-256 різні"))
    width = max(len(name) for name, _, _ in results)
    for name, status, text in results:
        print(f"{status:<4} {name:<{width}}  {text}")
    failures = sum(1 for _, status, _ in results if status == "FAIL")
    print(f"Підсумок: {len(results) - failures}/{len(results)} без блокерів" + (" — РЕЛІЗ ЗАБЛОКОВАНО" if failures else ""))
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):      # кирилиця в каналі cp1251/cp1252 не валить вивід
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = argparse.ArgumentParser(prog="release_tools", description="Реліз інструментів супроводжувача DRS.")
    sub = parser.add_subparsers(dest="command", required=True)
    chk = sub.add_parser("check", help="готовність до релізу")
    chk.add_argument("--osv", action="store_true", help="запитати OSV про відомі вразливості залежностей (мережа)")
    bld = sub.add_parser("build", help="детермінований архів + SHA256SUMS + SBOM")
    bld.add_argument("--version", required=True)
    bld.add_argument("--out", default=os.path.join("build", "tools-release"))
    rep = sub.add_parser("verify-repro", help="зібрати двічі й порівняти SHA-256")
    rep.add_argument("--version", required=True)
    args = parser.parse_args(argv)
    if not os.path.isdir(".git"):
        print("Запускати з кореня репозиторію.")
        return 2
    if args.command == "check":
        return check(args.osv)
    if args.command == "build":
        result = build(args.version, args.out)
        print(f"Архів: {result['zip']} ({result['files']} файлів з коміту {result['commit'][:12]})")
        for name, digest in result["sha256"].items():
            print(f"  SHA-256 {digest}  {name}")
        print(f"SBOM: {result['sbom']}; примітки: {result['notes']}")
        return 0
    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        first, second = build(args.version, a), build(args.version, b)
    for name in first["sha256"]:
        print(f"{name}: {first['sha256'][name]} | {second['sha256'][name]} → "
              f"{'збігається' if first['sha256'][name] == second['sha256'][name] else 'РІЗНИЙ'}")
    return 0 if first["sha256"] == second["sha256"] else 1


if __name__ == "__main__":
    sys.exit(main())
