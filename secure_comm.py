import argparse
import base64
import json
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


KEYS_DIR = Path("keys")
TRANSMITTED_FILE = Path("Transmitted_Data.json")
RECEIVED_FILE = Path("Received_Message.txt")


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(text):
    return base64.b64decode(text.encode("ascii"))


def public_key_file(party):
    return KEYS_DIR / f"{party}_public.pem"


def private_key_file(party):
    return KEYS_DIR / f"{party}_private.pem"


def mac_data(package):
    data = {
        "sender": package["sender"],
        "receiver": package["receiver"],
        "encrypted_key": package["encrypted_key"],
        "iv": package["iv"],
        "ciphertext": package["ciphertext"],
    }
    return json.dumps(data, sort_keys=True).encode("utf-8")


def make_mac(mac_key, package):
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(mac_data(package))
    return b64(h.digest())


def genkeys(party):
    KEYS_DIR.mkdir(exist_ok=True)
    key = RSA.generate(2048)
    private_key_file(party).write_bytes(key.export_key())
    public_key_file(party).write_bytes(key.publickey().export_key())
    print(f"Created keys for {party}")


def send(sender, receiver, message_file):
    plaintext = Path(message_file).read_bytes()

    aes_key = get_random_bytes(32)
    mac_key = get_random_bytes(32)
    iv = get_random_bytes(16)

    aes = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = aes.encrypt(pad(plaintext, AES.block_size))

    receiver_public_key = RSA.import_key(public_key_file(receiver).read_bytes())
    rsa = PKCS1_OAEP.new(receiver_public_key)
    encrypted_key = rsa.encrypt(aes_key + mac_key)

    package = {
        "sender": sender,
        "receiver": receiver,
        "encrypted_key": b64(encrypted_key),
        "iv": b64(iv),
        "ciphertext": b64(ciphertext),
    }
    package["mac"] = make_mac(mac_key, package)

    TRANSMITTED_FILE.write_text(json.dumps(package, indent=2), encoding="utf-8")
    print(f"Sent encrypted data in {TRANSMITTED_FILE}")


def receive(receiver):
    package = json.loads(TRANSMITTED_FILE.read_text(encoding="utf-8"))
    if package["receiver"] != receiver:
        raise ValueError("This message is not for this receiver.")

    receiver_private_key = RSA.import_key(private_key_file(receiver).read_bytes())
    rsa = PKCS1_OAEP.new(receiver_private_key)
    keys = rsa.decrypt(unb64(package["encrypted_key"]))
    aes_key = keys[:32]
    mac_key = keys[32:]

    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(mac_data(package))
    h.verify(unb64(package["mac"]))

    aes = AES.new(aes_key, AES.MODE_CBC, unb64(package["iv"]))
    plaintext = unpad(aes.decrypt(unb64(package["ciphertext"])), AES.block_size)

    RECEIVED_FILE.write_bytes(plaintext)
    print(f"MAC verified. Decrypted message written to {RECEIVED_FILE}")


def main():
    parser = argparse.ArgumentParser(description="Simple RSA + AES + HMAC demo")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("genkeys", help="Generate RSA keys for a party")
    gen.add_argument("party")

    snd = sub.add_parser("send", help="Sender role: encrypt and authenticate a file")
    snd.add_argument("sender")
    snd.add_argument("receiver")
    snd.add_argument("message_file")

    rcv = sub.add_parser("receive", help="Receiver role: verify and decrypt")
    rcv.add_argument("receiver")

    args = parser.parse_args()

    if args.command == "genkeys":
        genkeys(args.party)
    elif args.command == "send":
        send(args.sender, args.receiver, args.message_file)
    elif args.command == "receive":
        receive(args.receiver)


if __name__ == "__main__":
    main()
