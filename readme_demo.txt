for linux:
1 make a venv virtual environment
python3 -m venv .venv

2 activate virtual enviornment
source .venv/bin/activate

3 install dependencies
python3 -m pip install -r requirements.txt

4 run demo
python3 app.py



for windows
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py app.py

for mac
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 app.py
