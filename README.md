# NetSnap

**Scan. Inventory. Backup.**

NetSnap is a local, session-based network utility for one-time switch inventory collection and configuration backups. It does not require a database and does not persist credentials.

## V1 support

- Aruba Instant On 1930 — tested Web UI/HTTP workflow
- Cisco Small Business SG300/SG350/SG355 family — Netmiko Telnet/SSH adapter
- Inventory, backup, or combined mode
- Concurrent device processing
- Failed targets remain visible in results
- ZIP output with `inventory.csv`, `report.csv`, and/or `configs/`
- No database

## Run on Windows

### Backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python run.py
```

Backend: `http://127.0.0.1:8000`  
API docs: `http://127.0.0.1:8000/docs`

### Frontend

Open another terminal:

```powershell
cd frontend
npm install
npm run dev
```

Frontend: `http://127.0.0.1:5173`

## Session behavior

Credentials are accepted for the active job and held only in backend memory. When the job completes, the job's credential fields are cleared. Result files are created in the OS temporary directory.

The current V1 job registry is also in memory. Restarting the backend clears the registry. Temporary OS files may remain until OS cleanup; automatic TTL cleanup is scaffolded for further refinement.

## Outputs

Inventory mode:

```text
inventory.csv
report.csv
```

Backup mode:

```text
configs/
report.csv
```

Combined mode:

```text
inventory.csv
configs/
report.csv
```

All outputs are delivered as one ZIP.

## Notes

- Aruba 1930 currently uses HTTP because that is how the tested local Web UI workflow operates.
- Cisco Telnet is included for legacy SG devices. Prefer SSH where the device/configuration supports it.
- NetSnap intentionally has no permanent device database or backup history in V1.
