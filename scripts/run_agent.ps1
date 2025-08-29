$ErrorActionPreference = "Stop"
Set-Location "$PSScriptRoot\..\agent"
python -m pip install --upgrade pip
python -m pip install -r .\requirements.txt
python .\agent.py