from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from app.services.jobs import create_job, get_job, parse_targets, retry_failed, cancel_job, preflight_targets

app = FastAPI(title="NetSnap", description="Scan. Inventory. Backup.", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173","http://127.0.0.1:5173"], allow_credentials=False, allow_methods=["*"] , allow_headers=["*"])

class JobRequest(BaseModel):
    vendor: str
    operation: str
    targets: str
    username: str
    password: str
    connection_method: str = "telnet"
    concurrency: int = Field(2, ge=1, le=10)
    timeout: int = Field(8, ge=2, le=60)

@app.get("/api/health")
def health(): return {"status":"ok","name":"NetSnap","version":"0.1.0"}

@app.post("/api/jobs")
def start_job(body: JobRequest):
    if body.vendor not in {"cisco","aruba"}: raise HTTPException(400,"Unsupported vendor")
    if body.operation not in {"inventory","backup","both"}: raise HTTPException(400,"Unsupported operation")
    try: targets=parse_targets(body.targets)
    except ValueError as exc: raise HTTPException(400, str(exc)) from exc
    if not targets: raise HTTPException(400,"Add at least one target")
    if len(targets)>4096: raise HTTPException(400,"Maximum 4096 targets per job")
    return create_job(body.vendor,body.operation,targets,body.username,body.password,body.connection_method,body.concurrency,body.timeout)

@app.get("/api/jobs/{job_id}")
def job_status(job_id: str):
    job=get_job(job_id)
    if not job: raise HTTPException(404,"Job not found or expired")
    return job

@app.get("/api/jobs/{job_id}/download")
def download(job_id: str):
    job=get_job(job_id)
    if not job: raise HTTPException(404,"Job not found or expired")
    if not job["download_ready"]: raise HTTPException(409,"Job is not complete")
    # Internal path is deliberately not exposed by get_job; resolve from service registry here.
    from app.services.jobs import JOBS
    path=Path(JOBS[job_id]["path"])/"NetSnap_Result.zip"
    return FileResponse(path, media_type="application/zip", filename=f"NetSnap_{job_id}.zip")

class PreflightRequest(BaseModel):
    targets: str

@app.post("/api/preflight")
def preflight(body: PreflightRequest):
    try:
        return preflight_targets(body.targets)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

@app.post("/api/jobs/{job_id}/cancel")
def cancel(job_id: str):
    if not cancel_job(job_id):
        raise HTTPException(404, "Running job not found")
    return get_job(job_id)

class RetryRequest(BaseModel):
    username: str
    password: str

@app.post("/api/jobs/{job_id}/retry")
def retry_job(job_id: str, body: RetryRequest):
    try:
        return retry_failed(job_id, body.username, body.password)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
