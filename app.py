"""
app.py — Flask bridge between the browser frontend and secure_comm.py

Exposes the following REST endpoints:

    POST /api/genkeys          Generate RSA key pairs for alice and bob
    POST /api/send             Alice encrypts + authenticates a message
    POST /api/intercept        Eve corrupts the ciphertext in the channel file
    POST /api/receive          Bob decrypts and authenticates (or fails)
    GET  /api/status           Returns current state of the channel file
    GET  /                     Serves index.html

All crypto is handled by secure_comm.py — this file is only routing.

Run with:
    python3 app.py

Then open http://localhost:5000 in your browser.
"""

import base64
import hashlib
import json
import os
import threading
import webbrowser
from pathlib import Path

from flask import Flask, jsonify, render_template_string, request, send_from_directory
from flask_cors import CORS

# Import the actual crypto functions from secure_comm.py —
# Flask is just calling these, not reimplementing them.
from secure_comm import (
    KEYS_DIR,
    TRANSMITTED_FILE,
    b64,
    genkeys,
    mac_data,
    make_mac,
    private_key_file,
    public_key_file,
    unb64,
)

# These imports are used directly in the intercept route so we can
# corrupt bytes without going through the CLI argument parser.
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__, static_folder=".", template_folder=".")
CORS(app)  # allow the browser to call the API from the same origin


# ── Serve the frontend ────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main HTML frontend."""
    return send_from_directory(".", "index.html")


# ── /api/genkeys ─────────────────────────────────────────────────────────────

@app.route("/api/genkeys", methods=["POST"])
def api_genkeys():
    """
    Generate RSA-2048 key pairs for alice and bob.
    This calls genkeys() from secure_comm.py for each party.
    Returns the public key fingerprints so the frontend can display them.
    """
    try:
        genkeys("alice")
        genkeys("bob")

        # Compute a real SHA-256 fingerprint of each public key.
        # Import the key, export raw DER bytes, hash them — same
        # approach used by ssh-keygen -l. Because DER encodes the
        # actual key modulus, two different RSA keys will always
        # produce different fingerprints.
        def key_fingerprint(path):
            key    = RSA.import_key(path.read_bytes())
            der    = key.export_key("DER")
            digest = hashlib.sha256(der).digest()
            return ":".join(f"{b:02x}" for b in digest)

        alice_fp = key_fingerprint(public_key_file("alice"))
        bob_fp   = key_fingerprint(public_key_file("bob"))

        return jsonify({
            "ok": True,
            "alice_fingerprint": alice_fp,
            "bob_fingerprint":   bob_fp,
            "message": "RSA-2048 key pairs generated for alice and bob.",
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── /api/send ─────────────────────────────────────────────────────────────────

@app.route("/api/send", methods=["POST"])
def api_send():
    """
    Alice encrypts and authenticates a message.

    Accepts JSON: { "message": "plaintext string" }

    This runs the full send() logic from secure_comm.py inline so we can
    return each intermediate value to the frontend for display.
    The Transmitted_Data.json file is written to disk as normal.
    """
    body    = request.get_json(force=True)
    message = body.get("message", "").strip()
    if not message:
        return jsonify({"ok": False, "error": "Message cannot be empty."}), 400

    # Check keys exist
    if not public_key_file("bob").is_file():
        return jsonify({"ok": False, "error": "Keys not found. Run genkeys first."}), 400

    try:
        plaintext = message.encode("utf-8")

        # ── Step 2: Generate session keys ──────────────────────────────────
        aes_key = get_random_bytes(32)   # 256-bit AES session key
        mac_key = get_random_bytes(32)   # 256-bit HMAC key
        iv      = get_random_bytes(16)   # 128-bit AES-CBC IV

        # ── Step 3: AES-256-CBC encrypt ────────────────────────────────────
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = aes_cipher.encrypt(pad(plaintext, AES.block_size))

        # ── Step 4: RSA-OAEP encrypt key bundle ───────────────────────────
        bob_pub    = RSA.import_key(public_key_file("bob").read_bytes())
        rsa_cipher = PKCS1_OAEP.new(bob_pub)
        enc_key    = rsa_cipher.encrypt(aes_key + mac_key)

        # ── Step 5: Build package and compute HMAC ────────────────────────
        package = {
            "sender":        "alice",
            "receiver":      "bob",
            "encrypted_key": b64(enc_key),
            "iv":            b64(iv),
            "ciphertext":    b64(ciphertext),
        }
        package["mac"] = make_mac(mac_key, package)

        # ── Step 6: Write channel file ────────────────────────────────────
        TRANSMITTED_FILE.write_text(json.dumps(package, indent=2), encoding="utf-8")

        # Return each intermediate value so the UI can display them
        return jsonify({
            "ok": True,
            "steps": {
                "plaintext":     message,
                "aes_key_hex":   aes_key.hex(),
                "mac_key_hex":   mac_key.hex(),
                "iv_hex":        iv.hex(),
                "ciphertext_b64": b64(ciphertext),
                "enc_key_b64":   b64(enc_key),
                "mac_b64":       package["mac"],
                "package":       package,
            }
        })

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── /api/intercept ────────────────────────────────────────────────────────────

@app.route("/api/intercept", methods=["POST"])
def api_intercept():
    """
    Eve intercepts the channel file and corrupts the ciphertext.

    Reads Transmitted_Data.json, flips bytes in the middle of the
    ciphertext binary (not the Base64 string), then re-saves the file.

    Eve cannot forge a valid MAC because she doesn't have mac_key —
    so Bob's HMAC check will fail purely on math, not on a flag.
    """
    if not TRANSMITTED_FILE.is_file():
        return jsonify({"ok": False, "error": "No channel file to intercept. Run send first."}), 400

    try:
        package = json.loads(TRANSMITTED_FILE.read_text(encoding="utf-8"))

        # Decode the ciphertext bytes
        ct_bytes      = unb64(package["ciphertext"])
        ct_bytearray  = bytearray(ct_bytes)

        # Flip 8 bytes in the middle — visible corruption, not the MAC-covered
        # structure itself, so the MAC check is what catches it.
        mid = len(ct_bytearray) // 2
        original_bytes = bytes(ct_bytearray[mid:mid+8])
        for i in range(8):
            ct_bytearray[mid + i] ^= 0xFF   # XOR with 0xFF flips all bits

        corrupted_bytes = bytes(ct_bytearray[mid:mid+8])

        # Re-encode and overwrite the channel file
        # NOTE: the MAC field is NOT updated — Eve can't recompute it
        # because she doesn't have mac_key. This is what Bob will catch.
        package["ciphertext"] = b64(bytes(ct_bytearray))
        TRANSMITTED_FILE.write_text(json.dumps(package, indent=2), encoding="utf-8")

        return jsonify({
            "ok": True,
            "original_bytes_hex":  original_bytes.hex(),
            "corrupted_bytes_hex": corrupted_bytes.hex(),
            "byte_offset":         mid,
            "ciphertext_b64":      package["ciphertext"],
            "mac_b64":             package["mac"],   # unchanged — Eve can't fix this
            "message": f"Eve flipped 8 bytes at offset {mid}. MAC is now invalid.",
        })

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── /api/receive ──────────────────────────────────────────────────────────────

@app.route("/api/receive", methods=["POST"])
def api_receive():
    """
    Bob attempts to authenticate and decrypt the channel file.

    Runs the full receive logic inline (same as secure_comm.py's receive())
    so we can return intermediate values at each step.

    If the MAC fails, we return mac_ok: false and stop — no decryption
    is attempted. The failure is purely algorithmic (HMAC math), not a flag.
    """
    if not TRANSMITTED_FILE.is_file():
        return jsonify({"ok": False, "error": "No channel file found. Run send first."}), 400

    if not private_key_file("bob").is_file():
        return jsonify({"ok": False, "error": "Bob's private key not found. Run genkeys first."}), 400

    try:
        package = json.loads(TRANSMITTED_FILE.read_text(encoding="utf-8"))

        # ── Step 1: RSA-OAEP decrypt key bundle ───────────────────────────
        bob_priv   = RSA.import_key(private_key_file("bob").read_bytes())
        rsa_cipher = PKCS1_OAEP.new(bob_priv)
        key_bundle = rsa_cipher.decrypt(unb64(package["encrypted_key"]))
        aes_key    = key_bundle[:32]
        mac_key    = key_bundle[32:]

        # ── Step 2: Recompute HMAC over received fields ───────────────────
        h = HMAC.new(mac_key, digestmod=SHA256)
        h.update(mac_data(package))
        recomputed_mac = b64(h.digest())

        transmitted_mac = package["mac"]
        mac_ok = (recomputed_mac == transmitted_mac)

        if not mac_ok:
            # Return the mismatch — decryption is NOT attempted.
            # This is the real algorithmic detection: the HMAC math failed.
            return jsonify({
                "ok":              True,   # request succeeded; crypto failed
                "mac_ok":          False,
                "recomputed_mac":  recomputed_mac,
                "transmitted_mac": transmitted_mac,
                "error": "MAC verification FAILED. Message rejected — possible tampering detected.",
            })

        # ── Step 3: AES-256-CBC decrypt ───────────────────────────────────
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, unb64(package["iv"]))
        plaintext  = unpad(aes_cipher.decrypt(unb64(package["ciphertext"])), AES.block_size)

        return jsonify({
            "ok":              True,
            "mac_ok":          True,
            "recomputed_mac":  recomputed_mac,
            "transmitted_mac": transmitted_mac,
            "plaintext":       plaintext.decode("utf-8", errors="replace"),
            "aes_key_hex":     aes_key.hex(),
            "mac_key_hex":     mac_key.hex(),
        })

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── /api/status ───────────────────────────────────────────────────────────────

@app.route("/api/status", methods=["GET"])
def api_status():
    """Return current state: which keys exist, whether a channel file is present."""
    return jsonify({
        "keys_exist":     public_key_file("alice").is_file() and public_key_file("bob").is_file(),
        "channel_exists": TRANSMITTED_FILE.is_file(),
        "channel_file":   TRANSMITTED_FILE.read_text(encoding="utf-8")
                          if TRANSMITTED_FILE.is_file() else None,
    })


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Starting Secure Comm visualizer at http://localhost:5000")
    print("Make sure you are in the cs4600-final-project directory.")

    # Open the default system browser after a 1-second delay so Flask
    # has time to start before the browser tries to connect.
    threading.Timer(
        1.0,
        lambda: webbrowser.open("http://127.0.0.1:5000")
    ).start()

    # To use Firefox specifically instead, comment out the two lines
    # above and uncomment these:
    # firefox = webbrowser.get("firefox")
    # threading.Timer(1.0, lambda: firefox.open("http://127.0.0.1:5000")).start()

    app.run(debug=False, port=5000)