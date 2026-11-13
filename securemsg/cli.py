"""Interfaz de línea de comandos."""

import argparse
import json
from pathlib import Path
import sys

from cryptography.exceptions import InvalidSignature, InvalidTag

from .certificates import init_ca, issue_user
from .hashing import avalanche_demo
from .messaging import receive_message, send_message


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="securemsg", description="Mensajería segura didáctica (AES-GCM + RSA + X.509).")
    p.add_argument("--pki", type=Path, default=Path("pki"), help="Directorio de CA y usuarios (por defecto: ./pki)")
    sub = p.add_subparsers(dest="command", required=True)
    ca = sub.add_parser("init-ca", help="Crear la autoridad certificadora local")
    ca.add_argument("--name", default="Taller Criptografia CA")
    user = sub.add_parser("register", help="Generar clave RSA y certificado para un usuario")
    user.add_argument("identity")
    user.add_argument("--days", type=int, default=365)
    send = sub.add_parser("send", help="Firmar y cifrar un mensaje para otro usuario")
    send.add_argument("--from", dest="sender", required=True)
    send.add_argument("--to", dest="recipient", required=True)
    send.add_argument("--message", required=True)
    send.add_argument("--out", type=Path, required=True)
    receive = sub.add_parser("receive", help="Descifrar y verificar un mensaje recibido")
    receive.add_argument("--as", dest="recipient", required=True)
    receive.add_argument("--in", dest="input", type=Path, required=True)
    receive.add_argument("--expect-sender")
    hash_cmd = sub.add_parser("hash-demo", help="Mostrar SHA-256 y efecto avalancha de un bit")
    hash_cmd.add_argument("--message", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "init-ca":
            init_ca(args.pki, args.name)
            print(f"CA creada en {args.pki / 'ca'}")
        elif args.command == "register":
            issue_user(args.pki, args.identity, args.days)
            print(f"Usuario {args.identity} registrado en {args.pki / 'users' / args.identity}")
        elif args.command == "send":
            send_message(args.pki, args.sender, args.recipient, args.message, args.out)
            print(f"Mensaje firmado y cifrado: {args.out}")
        elif args.command == "receive":
            result = receive_message(args.pki, args.recipient, args.input, args.expect_sender)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif args.command == "hash-demo":
            print(json.dumps(avalanche_demo(args.message), ensure_ascii=False, indent=2))
        return 0
    except (ValueError, FileNotFoundError, FileExistsError, InvalidSignature, InvalidTag) as exc:
        print(f"RECHAZADO: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
