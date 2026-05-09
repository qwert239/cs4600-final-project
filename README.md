# Simple Secure Communication Demo

Everything is in `secure_comm.py`.

Install the dependency:

```powershell
py -m pip install -r requirements.txt
```

Generate RSA keys:

```powershell
py secure_comm.py genkeys alice
py secure_comm.py genkeys bob
```

Send Alice's text file to Bob:

```powershell
py secure_comm.py send alice bob messages/alice_message.txt
```

Receive and decrypt as Bob:

```powershell
py secure_comm.py receive bob
```

The sender writes `Transmitted_Data.json`. The receiver verifies the MAC, decrypts the message, and writes `Received_Message.txt`.
