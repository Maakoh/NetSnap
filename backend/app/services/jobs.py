import csv
import re
import logging
import io
import ipaddress
import shutil
import tempfile
import threading
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from app.adapters import ADAPTERS

JOBS = {}
LOCK = threading.Lock()
JOB_TTL_SECONDS = 30 * 60
MAX_TARGETS = 4096
logger = logging.getLogger("netsnap.jobs")


def _sort_key(ip):
    try: return (0, ipaddress.ip_address(ip))
    except ValueError: return (1, ip)


def parse_targets(raw: str):
    """Accept IPs, hostnames, ranges and CSV data with optional headers."""
    values = []
    lines = raw.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cells = next(csv.reader([line]))
        if len(cells) > 1 and any(c.strip().lower() in {"ip", "ip address", "host", "hostname", "address"} for c in cells):
            continue
        # Use first column for exported inventory CSVs, otherwise accept comma-separated IPs.
        if len(cells) > 1 and any("." in c or ":" in c for c in cells[1:]):
            tokens = cells
        elif len(cells) > 1 and ("." in cells[0] or ":" in cells[0]):
            tokens = [cells[0]] if any(not ("." in c or ":" in c) for c in cells[1:]) else cells
        else:
            tokens = cells
        for token in tokens:
            token = token.strip()
            if not token or token.lower() in {"ip", "ip address", "host", "hostname", "address"}:
                continue
            if "-" in token and token.count("-") == 1:
                left, right = [x.strip() for x in token.split("-", 1)]
                try:
                    start, end = ipaddress.ip_address(left), ipaddress.ip_address(right)
                    if start.version == end.version and 0 <= int(end)-int(start) <= MAX_TARGETS:
                        values.extend(str(ipaddress.ip_address(i)) for i in range(int(start), int(end)+1))
                        continue
                except ValueError:
                    pass
            try:
                token = str(ipaddress.ip_address(token))
            except ValueError:
                if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", token) or ".." in token:
                    raise ValueError(f"Invalid target: {token[:80]}")
            values.append(token)
            if len(values) > MAX_TARGETS * 2:
                raise ValueError("Too many targets")
    result = sorted(set(values), key=_sort_key)
    if len(result) > MAX_TARGETS:
        raise ValueError(f"Maximum {MAX_TARGETS} targets per job")
    return result


def _public_job(job):
    return {k:v for k,v in job.items() if k not in {"username","password","path"}}


def create_job(vendor, operation, targets, username, password, connection_method="telnet", concurrency=12, timeout=8):
    cleanup_jobs()
    job_id = uuid.uuid4().hex[:12]
    path = Path(tempfile.mkdtemp(prefix=f"netsnap_{job_id}_"))
    job = {
        "id":job_id, "vendor":vendor, "operation":operation, "targets":targets,
        "username":username, "password":password, "connection_method":connection_method,
        "concurrency":max(1,min(concurrency,50)), "timeout":max(2,min(timeout,60)),
        "status":"queued", "total":len(targets), "completed":0, "successful":0, "failed":0,
        "results":[], "created_at":time.time(), "path":str(path), "download_ready":False, "parent_job_id":None,
    }
    with LOCK: JOBS[job_id] = job
    threading.Thread(target=_run_job, args=(job_id,), daemon=True).start()
    return _public_job(job)


def get_job(job_id):
    with LOCK:
        job = JOBS.get(job_id)
        return _public_job(job.copy()) if job else None


def _scan_one(job, host):
    adapter_cls = ADAPTERS[job["vendor"]]
    kwargs = dict(host=host, username=job["username"], password=job["password"], timeout=job["timeout"])
    if job["vendor"] == "cisco": kwargs["connection_method"] = job["connection_method"]
    adapter = adapter_cls(**kwargs)
    result = {"ip":host, "system_name":"Unknown", "serial_number":"Unknown", "model":"Unknown", "status":"failed", "error":None, "config_file":None}
    try:
        adapter.connect()
        if job["operation"] in {"inventory","both"}:
            result.update(adapter.get_inventory().to_dict())
        if job["operation"] in {"backup","both"}:
            filename, content = adapter.get_config()
            configs = Path(job["path"]) / "configs"
            configs.mkdir(exist_ok=True)
            # Prefix the target to prevent collisions between devices with the same hostname.
            safe_host = re.sub(r"[^a-zA-Z0-9_.-]", "_", host)
            safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", Path(filename).name)
            filename = f"{safe_host}_{safe_name}"
            (configs / filename).write_text(content, encoding="utf-8", errors="replace")
            result["config_file"] = filename
        result["status"] = "success"
    except Exception as exc:
        msg = str(exc) or exc.__class__.__name__
        msg = msg.replace(job["password"], "[REDACTED]") if job.get("password") else msg
        msg = msg.replace(job["username"], "[REDACTED]") if job.get("username") else msg
        result["error"] = msg[:500]
        low = msg.lower()
        result["error_type"] = ("timeout" if "timed out" in low or "timeout" in low else
                                "authentication" if any(x in low for x in ("authentication", "login failed", "password", "auth failed")) else
                                "connection" if any(x in low for x in ("refused", "unreachable", "connection", "document root")) else
                                "device_error")
    finally:
        try: adapter.disconnect()
        except Exception: pass
    return result


def _write_csvs(job):
    rows = sorted(job["results"], key=lambda x:_sort_key(x["ip"]))
    root = Path(job["path"])
    if job["operation"] in {"inventory","both"}:
        with (root/"inventory.csv").open("w", newline="", encoding="utf-8") as f:
            w=csv.writer(f); w.writerow(["IP","System Name","Serial Number","Model","Status"])
            for r in rows: w.writerow([r["ip"],r["system_name"],r["serial_number"],r["model"],r["status"]])
    with (root/"report.csv").open("w", newline="", encoding="utf-8") as f:
        w=csv.writer(f); w.writerow(["IP","Status","Error Type","Error","Config File"])
        for r in rows: w.writerow([r["ip"],r["status"],r.get("error_type") or "",r.get("error") or "",r.get("config_file") or ""])


def _make_zip(job):
    root=Path(job["path"]); out=root/"NetSnap_Result.zip"
    with zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED) as z:
        for p in root.rglob("*"):
            if p.is_file() and p != out: z.write(p,p.relative_to(root))
    job["download_ready"] = True


def _run_job(job_id):
    try:
        _execute_job(job_id)
    except Exception:
        logger.exception("NetSnap job failed")
        with LOCK:
            job = JOBS.get(job_id)
            if job:
                job["status"] = "error"
                job["username"] = ""
                job["password"] = ""


def _execute_job(job_id):
    with LOCK:
        job=JOBS[job_id]; job["status"]="running"
    with ThreadPoolExecutor(max_workers=job["concurrency"]) as pool:
        futures={pool.submit(_scan_one,job,h):h for h in job["targets"]}
        for future in as_completed(futures):
            r=future.result()
            with LOCK:
                job["results"].append(r); job["completed"] += 1
                if r["status"] == "success": job["successful"] += 1
                else: job["failed"] += 1
    _write_csvs(job); _make_zip(job)
    with LOCK:
        job["status"]="complete"; job["username"]=""; job["password"]=""


def cleanup_jobs():
    now=time.time()
    with LOCK:
        expired=[jid for jid,j in JOBS.items() if j["status"] not in {"queued", "running"} and now-j["created_at"] > JOB_TTL_SECONDS]
        for jid in expired:
            path=JOBS[jid].get("path"); JOBS.pop(jid,None)
            if path: shutil.rmtree(path,ignore_errors=True)


def retry_failed(job_id: str, username: str, password: str):
    with LOCK:
        original = JOBS.get(job_id)
        if not original or original["status"] != "complete":
            raise ValueError("Original job not found or incomplete")
        failed = [r["ip"] for r in original["results"] if r["status"] != "success"]
        if not failed:
            raise ValueError("No failed devices to retry")
        settings = {k: original[k] for k in ("vendor", "operation", "connection_method", "concurrency", "timeout")}
    result = create_job(targets=failed, username=username, password=password, **settings)
    with LOCK:
        JOBS[result["id"]]["parent_job_id"] = job_id
    return result
