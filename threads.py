import subprocess

VENV_PATH = r"IDS\Scripts\activate"

process1 = subprocess.Popen(f'cmd /k "{VENV_PATH} && uvicorn app:app --host 0.0.0.0 --port 8000 --reload"', shell=True)
process2 = subprocess.Popen(f'cmd /k "{VENV_PATH} && python ml_ids.py"', shell=True)
process3 = subprocess.Popen(f'cmd /k "{VENV_PATH} && python tranditionalapi.py"', shell=True)
process4 = subprocess.Popen(f'cmd /k "{VENV_PATH} && python live_traffic.py"', shell=True)

process1.wait()
process2.wait()
process3.wait()
process4.wait()
