Set-Location "$PSScriptRoot\backend"
if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
  py -3.13 -m venv .venv
  if ($LASTEXITCODE -ne 0) { py -3 -m venv .venv }
  if ($LASTEXITCODE -ne 0) { throw "Could not create Python virtual environment. Install Python 3.12+ and retry." }
  .\.venv\Scripts\python.exe -m pip install --upgrade pip
  .\.venv\Scripts\python.exe -m pip install -r requirements.txt
}
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8001
