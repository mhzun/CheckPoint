#!/bin/bash
# TLS 证书轮换（v1.3.0）
# 生成新自签名证书 -> 备份旧证书 -> 原子替换 -> 重启容器 -> 打印新指纹与客户端更新指引
# 用法: ./rotate-cert.sh [部署IP，默认 checkpoint.example.com]
set -e
cd /opt/checkpoint
IP="${1:-checkpoint.example.com}"
STAMP=$(date +%Y%m%dT%H%M%S)
mkdir -p certs/old

python3 - "$IP" "$STAMP" <<'PYEOF'
import datetime, ipaddress, sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ip, stamp = sys.argv[1], sys.argv[2]
key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CheckPoint"),
    x509.NameAttribute(NameOID.COMMON_NAME, "checkpoint.local"),
])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("checkpoint.local"), x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address(ip))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
open("certs/cert.pem.new", "wb").write(cert.public_bytes(serialization.Encoding.PEM))
open("certs/key.pem.new", "wb").write(key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption()))
import hashlib
print("NEW_CERT_SHA256=" + hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest())
PYEOF

mv certs/cert.pem "certs/old/cert-$STAMP.pem" 2>/dev/null || true
mv certs/key.pem "certs/old/key-$STAMP.pem" 2>/dev/null || true
mv certs/cert.pem.new certs/cert.pem
mv certs/key.pem.new certs/key.pem
chmod 644 certs/cert.pem
chmod 600 certs/key.pem
sudo chown 10001:10001 certs/cert.pem certs/key.pem

docker compose restart > /dev/null 2>&1
sleep 8
curl -sk -m 5 https://127.0.0.1:8080/health && echo ""

cat <<'EOF'

轮换完成。客户端对接（二选一）：
  A) 重新发布客户端：把新指纹写入 client/Program.cs 的 DefaultCertPin 后 dotnet publish；
  B) 临时过渡：在客户端 checkpoint_config.json 增加 "cert_sha256": "<新指纹>"。
新指纹见上面输出 NEW_CERT_SHA256=... （旧证书已备份到 certs/old/）。
EOF