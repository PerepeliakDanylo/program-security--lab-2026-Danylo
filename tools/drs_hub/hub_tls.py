"""drs_hub — сертифікати TLS для локального сервера (версія ЛР10–11).

Призначення цільового файлу в репозиторії: tools/drs_hub/hub_tls.py

Схема довіри: власний маленький CA (ECDSA P-256) підписує сертифікат сервера з SAN `localhost` і
`127.0.0.1`. Клієнт довіряє ЛИШЕ цьому CA (`--ca ca_cert.pem`) і перевіряє ім'я хоста — перехоплення
з'єднання іншим сертифікатом дає помилку перевірки (захист від «людини посередині»).

Закритий ключ CA НЕ зберігається: він потрібен один раз — підписати сертифікат сервера — і одразу
знищується (лишається в пам'яті процесу до виходу). Красти нема чого; перевипуск сертифіката = новий CA,
і клієнти отримують новий ca_cert.pem. Закритий ключ сервера лежить у теці даних поза репозиторієм.

Розширення підібрано під суворий режим перевірки Python 3.13 (VERIFY_X509_STRICT): у CA — критичні
BasicConstraints(CA) і KeyUsage(keyCertSign, cRLSign), SKI та AKI; у сервера — BasicConstraints(не CA),
KeyUsage(digitalSignature), EKU serverAuth, SAN, SKI та AKI.
"""

from __future__ import annotations

import datetime
import hashlib
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DEFAULT_DAYS = 397          # строк дії сертифіката сервера (≈13 міс., як у публічних CA)


def _key_usage(*, digital_signature=False, key_cert_sign=False, crl_sign=False) -> x509.KeyUsage:
    return x509.KeyUsage(digital_signature=digital_signature, content_commitment=False,
                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                         key_cert_sign=key_cert_sign, crl_sign=crl_sign, encipher_only=False,
                         decipher_only=False)


def _write_private(path: str, data: bytes) -> None:
    """Закритий ключ: створити заново з правами 0600 (на Windows діє ACL профілю)."""
    if os.path.exists(path):
        os.remove(path)
    # O_BINARY: без нього Windows відкриває дескриптор у текстовому режимі (\n → \r\n)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def fingerprint(cert_path: str) -> str:
    """SHA-256 відбиток сертифіката (DER) у вигляді AA:BB:… — для звірки поза каналом."""
    with open(cert_path, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    digest = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def create_ca_and_server_cert(tls_dir: str, dns_names: tuple[str, ...] = ("localhost",),
                              ip_addresses: tuple[str, ...] = ("127.0.0.1",),
                              days: int = DEFAULT_DAYS) -> dict:
    """Створити CA і сертифікат сервера; записати ca_cert.pem, server_cert.pem, server_key.pem."""
    os.makedirs(tls_dir, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now - datetime.timedelta(days=1)       # запас на розбіжність годинників
    not_after = now + datetime.timedelta(days=days)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DRS Hub"),
        x509.NameAttribute(NameOID.COMMON_NAME, "DRS Hub local CA " + now.strftime("%Y-%m-%d")),
    ])
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before).not_valid_after(not_after + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_key_usage(key_cert_sign=True, crl_sign=True), critical=True)
        .add_extension(ca_ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = ec.generate_private_key(ec.SECP256R1())
    san = [x509.DNSName(name) for name in dns_names] + \
          [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ip_addresses]
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_names[0] if dns_names
                                                    else ip_addresses[0])]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before).not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(digital_signature=True), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    del ca_key   # ключ CA свідомо не зберігається (див. докстрінг модуля)

    ca_path = os.path.join(tls_dir, "ca_cert.pem")
    cert_path = os.path.join(tls_dir, "server_cert.pem")
    key_path = os.path.join(tls_dir, "server_key.pem")
    with open(ca_path, "wb") as fh:
        fh.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    with open(cert_path, "wb") as fh:
        fh.write(server_cert.public_bytes(serialization.Encoding.PEM))
    _write_private(key_path, server_key.private_bytes(serialization.Encoding.PEM,
                                                      serialization.PrivateFormat.PKCS8,
                                                      serialization.NoEncryption()))
    return {"ca": ca_path, "cert": cert_path, "key": key_path,
            "ca_fingerprint": fingerprint(ca_path), "not_after": not_after.strftime("%Y-%m-%d")}
