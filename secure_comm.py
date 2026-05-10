"""
secure_comm.py — RSA + AES-CBC + HMAC-SHA256 secure messaging demo
CS4600 Final Project

Simulates encrypted, authenticated communication between two parties
using local files in place of a real network socket.

Usage:
    python3 secure_comm.py genkeys <party>
    python3 secure_comm.py send <sender> <receiver> <message_file>
    python3 secure_comm.py receive <receiver>
"""

import argparse
import base64
import json
import sys
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


# ---------------------------------------------------------------------------
# File path constants
# All keys live under keys/, the channel file simulates network transmission.
# ---------------------------------------------------------------------------
KEYS_DIR = Path("keys")
TRANSMITTED_FILE = Path("Transmitted_Data.json")
RECEIVED_FILE = Path("Received_Message.txt")


# ---------------------------------------------------------------------------
# Base64 helpers
# JSON can only hold text, so all binary crypto output is base64-encoded
# before being written to the transmission file, and decoded on the way back.
# ---------------------------------------------------------------------------

def b64(data: bytes) -> str:
    """Encode raw bytes to a base64 ASCII string for JSON serialisation."""
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    """Decode a base64 ASCII string back to raw bytes."""
    return base64.b64decode(text.encode("ascii"))


# ---------------------------------------------------------------------------
# Key file path helpers
# ---------------------------------------------------------------------------

def public_key_file(party: str) -> Path:
    """Return the path to <party>'s RSA public key PEM file."""
    return KEYS_DIR / f"{party}_public.pem"


def private_key_file(party: str) -> Path:
    """Return the path to <party>'s RSA private key PEM file."""
    return KEYS_DIR / f"{party}_private.pem"


# ---------------------------------------------------------------------------
# MAC helpers
# The HMAC is computed over a canonical JSON representation of the fields
# that matter for integrity: sender, receiver, encrypted_key, iv, ciphertext.
# sort_keys=True guarantees a consistent byte string regardless of insertion
# order, closing an ordering-ambiguity attack.
# ---------------------------------------------------------------------------

def mac_data(package: dict) -> bytes:
    """
    Serialise the fields that the MAC must protect into a stable byte string.
    The 'mac' field itself is intentionally excluded to avoid circular hashing.
    """
    covered = {
        "sender":        package["sender"],
        "receiver":      package["receiver"],
        "encrypted_key": package["encrypted_key"],
        "iv":            package["iv"],
        "ciphertext":    package["ciphertext"],
    }
    return json.dumps(covered, sort_keys=True).encode("utf-8")


def make_mac(mac_key: bytes, package: dict) -> str:
    """
    Compute HMAC-SHA256 over the MAC-covered fields and return it as a
    base64 string ready to embed in the JSON package.
    """
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(mac_data(package))
    return b64(h.digest())


# ---------------------------------------------------------------------------
# genkeys — RSA key-pair generation
# Generates a 2048-bit RSA key pair and saves both halves as PEM files.
# The public key is "published" (accessible to any party); the private key
# must stay secret on the owner's machine.
# ---------------------------------------------------------------------------

def genkeys(party: str) -> None:
    """Generate and persist a 2048-bit RSA key pair for <party>."""
    try:
        KEYS_DIR.mkdir(exist_ok=True)
    except OSError as e:
        sys.exit(f"Error: could not create keys directory — {e}")

    # RSA 2048-bit is the minimum recommended size; 4096-bit would be stronger
    # but significantly slower for key generation and decryption.
    key = RSA.generate(2048)

    try:
        private_key_file(party).write_bytes(key.export_key())
        public_key_file(party).write_bytes(key.publickey().export_key())
    except OSError as e:
        sys.exit(f"Error: could not write key files for '{party}' — {e}")

    print(f"[genkeys] RSA-2048 key pair created for '{party}'")
    print(f"  Private key → {private_key_file(party)}")
    print(f"  Public key  → {public_key_file(party)}")


# ---------------------------------------------------------------------------
# send — encryption and authentication (sender role)
#
# Flow:
#   1. Read plaintext from file.
#   2. Generate a fresh AES-256 session key and a separate HMAC key.
#   3. Encrypt plaintext with AES-256-CBC (random IV each call).
#   4. Concatenate [aes_key | mac_key] and RSA-OAEP encrypt with
#      the receiver's public key → encrypted_key field.
#   5. Build the JSON package, compute HMAC over it, append mac field.
#   6. Write the package to the shared channel file.
# ---------------------------------------------------------------------------

def send(sender: str, receiver: str, message_file: str) -> None:
    """Encrypt and authenticate a message file from <sender> to <receiver>."""

    # --- Load plaintext ---
    msg_path = Path(message_file)
    if not msg_path.is_file():
        sys.exit(f"Error: message file '{message_file}' not found.")
    plaintext = msg_path.read_bytes()

    # --- Load receiver's RSA public key ---
    pub_path = public_key_file(receiver)
    if not pub_path.is_file():
        sys.exit(
            f"Error: public key for '{receiver}' not found at {pub_path}.\n"
            f"       Run:  python3 secure_comm.py genkeys {receiver}"
        )
    try:
        receiver_public_key = RSA.import_key(pub_path.read_bytes())
    except (ValueError, IndexError) as e:
        sys.exit(f"Error: could not parse public key for '{receiver}' — {e}")

    # --- Generate fresh session keys and IV ---
    # A new AES key and HMAC key are generated for every message so that
    # compromise of one session does not expose past sessions (forward secrecy
    # at the symmetric layer).
    aes_key = get_random_bytes(32)   # 256-bit AES key
    mac_key = get_random_bytes(32)   # 256-bit HMAC key
    iv      = get_random_bytes(16)   # 128-bit IV for AES-CBC

    # --- AES-256-CBC encryption ---
    # CBC requires the plaintext length to be a multiple of the block size (16
    # bytes), so PKCS#7 padding is applied before encryption and stripped after
    # decryption.
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext  = aes_cipher.encrypt(pad(plaintext, AES.block_size))

    # --- RSA-OAEP key encapsulation ---
    # Both symmetric keys are bundled and encrypted together under the
    # receiver's RSA public key. PKCS1-OAEP is used (not the older PKCS1-v1_5)
    # because OAEP is IND-CCA2 secure and resistant to padding-oracle attacks.
    rsa_cipher    = PKCS1_OAEP.new(receiver_public_key)
    encrypted_key = rsa_cipher.encrypt(aes_key + mac_key)  # 64 bytes total

    # --- Assemble the transmission package (without MAC yet) ---
    package = {
        "sender":        sender,
        "receiver":      receiver,
        "encrypted_key": b64(encrypted_key),
        "iv":            b64(iv),
        "ciphertext":    b64(ciphertext),
    }

    # --- Compute and append HMAC-SHA256 ---
    # The MAC is computed last so it covers all of the above fields.
    # It protects against tampering with the ciphertext, IV, key, or routing
    # metadata (sender/receiver) in transit.
    package["mac"] = make_mac(mac_key, package)

    # --- Write to the simulated channel file ---
    try:
        TRANSMITTED_FILE.write_text(json.dumps(package, indent=2), encoding="utf-8")
    except OSError as e:
        sys.exit(f"Error: could not write transmission file — {e}")

    print(f"[send] Message encrypted and authenticated.")
    print(f"  AES-256-CBC  ciphertext → {len(ciphertext)} bytes")
    print(f"  RSA-OAEP     key bundle → {len(encrypted_key)} bytes")
    print(f"  HMAC-SHA256  tag        → {package['mac'][:24]}…")
    print(f"  Transmission file       → {TRANSMITTED_FILE}")


# ---------------------------------------------------------------------------
# receive — authentication and decryption (receiver role)
#
# Flow:
#   1. Load the JSON package from the channel file.
#   2. Verify the receiver field matches identity.
#   3. RSA-OAEP decrypt the key bundle → recover aes_key and mac_key.
#   4. Recompute HMAC and compare (constant-time) with the transmitted tag.
#      If verification fails, abort — never decrypt unauthenticated data.
#   5. AES-CBC decrypt the ciphertext and strip PKCS#7 padding.
#   6. Write the recovered plaintext to the output file.
# ---------------------------------------------------------------------------

def receive(receiver: str) -> None:
    """Verify and decrypt a message intended for <receiver>."""

    # --- Load the channel file ---
    if not TRANSMITTED_FILE.is_file():
        sys.exit(
            f"Error: transmission file '{TRANSMITTED_FILE}' not found.\n"
            f"       The sender must run 'send' before you can receive."
        )
    try:
        package = json.loads(TRANSMITTED_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        sys.exit(f"Error: could not read/parse transmission file — {e}")

    # --- Routing check ---
    if package.get("receiver") != receiver:
        sys.exit(
            f"Error: this message is addressed to '{package.get('receiver')}', "
            f"not '{receiver}'."
        )

    # --- Load receiver's RSA private key ---
    priv_path = private_key_file(receiver)
    if not priv_path.is_file():
        sys.exit(
            f"Error: private key for '{receiver}' not found at {priv_path}.\n"
            f"       Run:  python3 secure_comm.py genkeys {receiver}"
        )
    try:
        receiver_private_key = RSA.import_key(priv_path.read_bytes())
    except (ValueError, IndexError) as e:
        sys.exit(f"Error: could not parse private key for '{receiver}' — {e}")

    # --- RSA-OAEP key decapsulation ---
    # Recover the concatenated [aes_key | mac_key] bundle.
    rsa_cipher = PKCS1_OAEP.new(receiver_private_key)
    try:
        keys    = rsa_cipher.decrypt(unb64(package["encrypted_key"]))
    except ValueError as e:
        sys.exit(f"Error: RSA decryption failed — key may be wrong or data corrupted ({e})")

    aes_key = keys[:32]   # first 32 bytes
    mac_key = keys[32:]   # second 32 bytes

    # --- HMAC-SHA256 verification ---
    # Verify BEFORE decrypting. Decrypting unauthenticated ciphertext
    # can leak information via padding oracles; the MAC check prevents that.
    # HMAC.verify() uses a constant-time comparison to prevent timing attacks.
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(mac_data(package))
    try:
        h.verify(unb64(package["mac"]))
    except ValueError:
        sys.exit(
            "Error: MAC verification FAILED. The message may have been tampered "
            "with in transit. Decryption aborted."
        )

    print("[receive] MAC verified — message is authentic and unmodified.")

    # --- AES-256-CBC decryption ---
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, unb64(package["iv"]))
    try:
        plaintext = unpad(aes_cipher.decrypt(unb64(package["ciphertext"])), AES.block_size)
    except ValueError as e:
        sys.exit(f"Error: AES decryption/unpadding failed — {e}")

    # --- Write recovered plaintext ---
    try:
        RECEIVED_FILE.write_bytes(plaintext)
    except OSError as e:
        sys.exit(f"Error: could not write output file — {e}")

    print(f"[receive] Decrypted message written to {RECEIVED_FILE}")
    print(f"\n--- Message contents ---\n{plaintext.decode('utf-8', errors='replace')}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="RSA + AES-256-CBC + HMAC-SHA256 secure messaging demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 secure_comm.py genkeys alice\n"
            "  python3 secure_comm.py genkeys bob\n"
            "  python3 secure_comm.py send alice bob messages/alice_message.txt\n"
            "  python3 secure_comm.py receive bob\n"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # genkeys sub-command
    gen = sub.add_parser("genkeys", help="Generate an RSA-2048 key pair for a party")
    gen.add_argument("party", help="Name of the party (e.g. alice, bob)")

    # send sub-command
    snd = sub.add_parser("send", help="Encrypt and authenticate a message file")
    snd.add_argument("sender",       help="Name of the sending party")
    snd.add_argument("receiver",     help="Name of the receiving party")
    snd.add_argument("message_file", help="Path to the plaintext .txt file")

    # receive sub-command
    rcv = sub.add_parser("receive", help="Verify and decrypt a received message")
    rcv.add_argument("receiver", help="Name of the receiving party")

    args = parser.parse_args()

    if args.command == "genkeys":
        genkeys(args.party)
    elif args.command == "send":
        send(args.sender, args.receiver, args.message_file)
    elif args.command == "receive":
        receive(args.receiver)


if __name__ == "__main__":
    main()
