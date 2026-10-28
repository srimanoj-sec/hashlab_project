from __future__ import annotations

import hashlib
import io
import json
import math
import os
import random
import statistics
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("HASHLAB_DATA_DIR", APP_DIR.parent / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "hashlab.sqlite3"

ALGORITHMS = {
    "MD5": {"name": "md5", "bits": 128, "security": "Broken for collision resistance; legacy comparison only."},
    "SHA-1": {"name": "sha1", "bits": 160, "security": "Broken for collision resistance; do not use for new security-sensitive designs."},
    "SHA-256": {"name": "sha256", "bits": 256, "security": "Modern general-purpose hash; SHA-2 family."},
    "SHA-512": {"name": "sha512", "bits": 512, "security": "Modern general-purpose hash; SHA-2 family."},
    "SHA3-256": {"name": "sha3_256", "bits": 256, "security": "Modern general-purpose hash; SHA-3 family."},
    "SHA3-512": {"name": "sha3_512", "bits": 512, "security": "Modern general-purpose hash; SHA-3 family."},
}

app = FastAPI(title="HashLab API", version="1.0.0",
              description="Experimental cryptographic hash behavior analysis and file integrity verification.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    import sqlite3
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS experiments (
            id TEXT PRIMARY KEY, created_at TEXT NOT NULL, algorithm TEXT NOT NULL,
            experiment_type TEXT NOT NULL, input_bytes INTEGER NOT NULL,
            trial_number INTEGER, elapsed_ns INTEGER, throughput_bytes_s REAL,
            changed_output_bits INTEGER, avalanche_percent REAL,
            input_description TEXT, digest_hex TEXT, metadata_json TEXT
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS baselines (
            id TEXT PRIMARY KEY, created_at TEXT NOT NULL, filename TEXT NOT NULL,
            algorithm TEXT NOT NULL, size_bytes INTEGER NOT NULL, digest_hex TEXT NOT NULL
        )""")
        db.commit()

init_db()

class HashRequest(BaseModel):
    text: str = Field(max_length=2_000_000)
    algorithms: list[str] = Field(default_factory=lambda: list(ALGORITHMS.keys()))

class MutationRequest(BaseModel):
    text: str = Field(max_length=100_000)
    mutation: str = "single_character"
    position: int = 0
    seed: int = 2026

class BenchmarkRequest(BaseModel):
    sizes_kb: list[int] = Field(default_factory=lambda: [1, 64, 1024])
    trials: int = Field(default=7, ge=3, le=100)
    algorithms: list[str] = Field(default_factory=lambda: list(ALGORITHMS.keys()))
    seed: int = 2026

class DatasetRequest(BaseModel):
    trials_per_algorithm: int = Field(default=20, ge=1, le=1000)
    include_benchmark: bool = True
    include_mutations: bool = True
    seed: int = 2026

def algorithm_info(algorithm: str) -> dict[str, Any]:
    if algorithm not in ALGORITHMS:
        raise HTTPException(status_code=400, detail=f"Unsupported algorithm: {algorithm}")
    return ALGORITHMS[algorithm]

def digest_bytes(data: bytes, algorithm: str) -> str:
    info = algorithm_info(algorithm)
    try:
        return hashlib.new(info["name"], data).hexdigest()
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Algorithm unavailable in this Python/OpenSSL build: {algorithm}") from exc

def digest_text(text: str, algorithm: str) -> str:
    return digest_bytes(text.encode("utf-8"), algorithm)

def hamming_distance(hex_a: str, hex_b: str) -> int:
    a, b = bytes.fromhex(hex_a), bytes.fromhex(hex_b)
    if len(a) != len(b):
        raise ValueError("Hamming distance requires equal-length digests")
    return sum((x ^ y).bit_count() for x, y in zip(a, b))

def avalanche_stats(percentages: list[float]) -> dict[str, float | int | None]:
    if not percentages:
        return {"count": 0, "mean_percent": None, "median_percent": None,
                "stdev_percent": None, "min_percent": None, "max_percent": None,
                "ci95_low": None, "ci95_high": None}
    mean = statistics.mean(percentages)
    sd = statistics.stdev(percentages) if len(percentages) > 1 else 0.0
    # Normal approximation; clearly labeled approximate and useful for this exploratory tool.
    margin = 1.96 * sd / math.sqrt(len(percentages)) if len(percentages) > 1 else 0.0
    return {"count": len(percentages), "mean_percent": mean,
            "median_percent": statistics.median(percentages), "stdev_percent": sd,
            "min_percent": min(percentages), "max_percent": max(percentages),
            "ci95_low": max(0.0, mean - margin), "ci95_high": min(100.0, mean + margin)}

def record_experiment(algorithm: str, experiment_type: str, input_bytes: int,
                      trial_number: int | None = None, elapsed_ns: int | None = None,
                      throughput_bytes_s: float | None = None,
                      changed_output_bits: int | None = None,
                      avalanche_percent: float | None = None,
                      input_description: str = "", digest_hex: str = "",
                      metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    row = {
        "id": str(uuid.uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": algorithm, "experiment_type": experiment_type, "input_bytes": input_bytes,
        "trial_number": trial_number, "elapsed_ns": elapsed_ns,
        "throughput_bytes_s": throughput_bytes_s, "changed_output_bits": changed_output_bits,
        "avalanche_percent": avalanche_percent, "input_description": input_description,
        "digest_hex": digest_hex, "metadata": metadata or {}
    }
    with get_db() as db:
        db.execute("""INSERT INTO experiments VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                   (row["id"], row["created_at"], row["algorithm"], row["experiment_type"],
                    row["input_bytes"], row["trial_number"], row["elapsed_ns"],
                    row["throughput_bytes_s"], row["changed_output_bits"], row["avalanche_percent"],
                    row["input_description"], row["digest_hex"], json.dumps(row["metadata"])))
        db.commit()
    return row

def validate_algorithms(algorithms: list[str]) -> list[str]:
    if not algorithms:
        raise HTTPException(status_code=400, detail="Select at least one algorithm.")
    for algorithm in algorithms:
        algorithm_info(algorithm)
    return algorithms

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "HashLab API", "algorithms": list(ALGORITHMS.keys())}

@app.get("/api/algorithms")
def algorithms():
    return [{"algorithm": key, "digest_bits": value["bits"], "hex_characters": value["bits"] // 4,
             "family": "MD5" if key == "MD5" else "SHA-1" if key == "SHA-1" else
                       "SHA-2" if key.startswith("SHA-2") or key in ("SHA-256", "SHA-512") else "SHA-3",
             "security_note": value["security"]} for key, value in ALGORITHMS.items()]

@app.post("/api/hash")
def hash_input(request: HashRequest):
    selected = validate_algorithms(request.algorithms)
    raw = request.text.encode("utf-8")
    results = []
    for algorithm in selected:
        start = time.perf_counter_ns()
        digest = digest_bytes(raw, algorithm)
        elapsed = time.perf_counter_ns() - start
        results.append({"algorithm": algorithm, "digest": digest,
                        "digest_bits": ALGORITHMS[algorithm]["bits"],
                        "hex_characters": len(digest), "execution_time_ns": elapsed,
                        "security_note": ALGORITHMS[algorithm]["security"]})
    return {"input_bytes": len(raw), "encoding": "UTF-8", "results": results}

@app.post("/api/mutate")
def mutate(request: MutationRequest):
    original = request.text.encode("utf-8")
    if not original:
        raise HTTPException(status_code=400, detail="Use a non-empty input for mutation experiments.")
    if request.mutation == "single_character":
        chars = list(request.text)
        pos = min(max(request.position, 0), len(chars) - 1)
        old = chars[pos]
        chars[pos] = "X" if old != "X" else "Y"
        mutated_text = "".join(chars)
        changed = mutated_text.encode("utf-8")
        description = f"Character at Unicode index {pos}: {old!r} -> {chars[pos]!r}"
    elif request.mutation == "append_space":
        changed = original + b" "
        description = "Appended one ASCII space"
    elif request.mutation == "flip_bit":
        changed = bytearray(original)
        byte_pos = min(max(request.position, 0), len(changed) - 1)
        changed[byte_pos] ^= 1
        changed = bytes(changed)
        description = f"Flipped least-significant bit of byte index {byte_pos}"
    elif request.mutation == "append_byte":
        changed = original + b"\x00"
        description = "Appended one zero byte"
    else:
        raise HTTPException(status_code=400, detail="Unknown mutation type.")
    rows = []
    for algorithm in ALGORITHMS:
        a = digest_bytes(original, algorithm)
        b = digest_bytes(changed, algorithm)
        distance = hamming_distance(a, b)
        bits = ALGORITHMS[algorithm]["bits"]
        rows.append({"algorithm": algorithm, "original_digest": a, "mutated_digest": b,
                     "changed_output_bits": distance, "digest_bits": bits,
                     "avalanche_percent": distance / bits * 100})
    return {"description": description, "original_bytes": len(original), "mutated_bytes": len(changed),
            "results": rows}

@app.post("/api/benchmark")
def benchmark(request: BenchmarkRequest):
    selected = validate_algorithms(request.algorithms)
    if not request.sizes_kb or any(size < 1 or size > 10240 for size in request.sizes_kb):
        raise HTTPException(status_code=400, detail="Input sizes must be between 1 KB and 10,240 KB.")
    rng = random.Random(request.seed)
    out = []
    for size_kb in request.sizes_kb:
        payload = bytes(rng.getrandbits(8) for _ in range(size_kb * 1024))
        for algorithm in selected:
            # Warm-up is deliberately excluded from recorded trials.
            digest_bytes(payload, algorithm)
            timings = []
            for trial in range(1, request.trials + 1):
                start = time.perf_counter_ns()
                dig = digest_bytes(payload, algorithm)
                elapsed = max(1, time.perf_counter_ns() - start)
                timings.append(elapsed)
                record_experiment(algorithm, "benchmark", len(payload), trial, elapsed,
                                  len(payload) / (elapsed / 1e9), input_description=f"{size_kb} KB random-seeded payload",
                                  digest_hex=dig, metadata={"seed": request.seed, "size_kb": size_kb})
            out.append({"algorithm": algorithm, "size_kb": size_kb, "input_bytes": len(payload),
                        "trials": request.trials, "times_ns": timings,
                        "mean_ns": statistics.mean(timings), "median_ns": statistics.median(timings),
                        "stdev_ns": statistics.stdev(timings) if len(timings) > 1 else 0,
                        "mean_throughput_bytes_s": len(payload) / (statistics.mean(timings) / 1e9)})
    return {"seed": request.seed, "timing_scope": "hash computation only; payload generation excluded",
            "python_version": __import__("sys").version, "results": out}

@app.post("/api/avalanche")
def avalanche(request: DatasetRequest):
    rng = random.Random(request.seed)
    baseline = ("HashLab cryptographic behavior experiment " * 4).encode()
    rows = []
    for algorithm in ALGORITHMS:
        percentages = []
        distances = []
        for trial in range(1, request.trials_per_algorithm + 1):
            payload = bytearray(baseline)
            pos = rng.randrange(len(payload))
            bit = rng.randrange(8)
            payload[pos] ^= 1 << bit
            changed = bytes(payload)
            a = digest_bytes(baseline, algorithm)
            b = digest_bytes(changed, algorithm)
            dist = hamming_distance(a, b)
            pct = dist / ALGORITHMS[algorithm]["bits"] * 100
            percentages.append(pct)
            distances.append(dist)
            record_experiment(algorithm, "single_bit_avalanche", len(baseline), trial,
                              changed_output_bits=dist, avalanche_percent=pct,
                              input_description=f"Flip bit {bit} at byte index {pos}",
                              digest_hex=b, metadata={"seed": request.seed, "byte_position": pos, "bit_position": bit})
        rows.append({"algorithm": algorithm, "digest_bits": ALGORITHMS[algorithm]["bits"],
                     "changed_bits": distances, "percentages": percentages,
                     "statistics": avalanche_stats(percentages)})
    return {"seed": request.seed, "trials_per_algorithm": request.trials_per_algorithm,
            "baseline_bytes": len(baseline), "results": rows,
            "interpretation": "Idealized random-looking outputs have an expected changed-bit fraction near 50%; individual trials vary."}

@app.post("/api/dataset/generate")
def generate_dataset(request: DatasetRequest):
    rng = random.Random(request.seed)
    rows = []
    samples = [
        ("baseline", b"CyberSecurity123", b"CyberSecurity123"),
        ("single_character", b"Hello HashLab", b"hello HashLab"),
        ("whitespace", b"cryptographic hash", b"cryptographic hash "),
        ("append_byte", b"integrity", b"integrity\x00"),
        ("structured_json", b'{"user":"alice","role":"viewer"}', b'{"user":"alice","role":"admin"}'),
    ]
    if request.include_mutations:
        for kind, original, changed in samples:
            for algorithm in ALGORITHMS:
                a = digest_bytes(original, algorithm)
                b = digest_bytes(changed, algorithm)
                dist = hamming_distance(a, b)
                bits = ALGORITHMS[algorithm]["bits"]
                rows.append(record_experiment(algorithm, kind, len(original),
                    changed_output_bits=dist if kind != "baseline" else None,
                    avalanche_percent=dist / bits * 100 if kind != "baseline" else None,
                    input_description=f"{original!r} -> {changed!r}",
                    digest_hex=b, metadata={"seed": request.seed, "comparison": "changed input" if kind != "baseline" else "baseline"}))
    # Reproducible single-bit input mutations; timings are not recorded here.
    baseline = bytearray(b"HashLab reproducible avalanche baseline")
    for algorithm in ALGORITHMS:
        for trial in range(1, request.trials_per_algorithm + 1):
            payload = bytearray(baseline)
            pos = rng.randrange(len(payload))
            bit = rng.randrange(8)
            payload[pos] ^= 1 << bit
            a = digest_bytes(bytes(baseline), algorithm)
            b = digest_bytes(bytes(payload), algorithm)
            dist = hamming_distance(a, b)
            bits = ALGORITHMS[algorithm]["bits"]
            rows.append(record_experiment(algorithm, "single_bit_avalanche", len(payload), trial,
                changed_output_bits=dist, avalanche_percent=dist / bits * 100,
                input_description=f"Flip bit {bit} at byte {pos}", digest_hex=b,
                metadata={"seed": request.seed, "byte_position": pos, "bit_position": bit}))
    if request.include_benchmark:
        # A small quick benchmark dataset to keep this endpoint responsive.
        for size_kb in (1, 16, 64):
            payload = bytes(rng.getrandbits(8) for _ in range(size_kb * 1024))
            for algorithm in ALGORITHMS:
                for trial in range(1, min(request.trials_per_algorithm, 10) + 1):
                    start = time.perf_counter_ns()
                    dig = digest_bytes(payload, algorithm)
                    elapsed = max(1, time.perf_counter_ns() - start)
                    rows.append(record_experiment(algorithm, "benchmark", len(payload), trial, elapsed,
                        len(payload) / (elapsed / 1e9), input_description=f"{size_kb} KB seeded payload",
                        digest_hex=dig, metadata={"seed": request.seed, "size_kb": size_kb}))
    return {"generated_rows": len(rows), "seed": request.seed,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "note": "All measurements and digests were generated by this running application; timings are machine-specific.",
            "rows": rows}

@app.get("/api/experiments")
def list_experiments(limit: int = 5000, experiment_type: str | None = None):
    limit = min(max(limit, 1), 20000)
    with get_db() as db:
        if experiment_type:
            records = db.execute("SELECT * FROM experiments WHERE experiment_type=? ORDER BY created_at DESC LIMIT ?",
                                 (experiment_type, limit)).fetchall()
        else:
            records = db.execute("SELECT * FROM experiments ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [dict(row) for row in records]

@app.get("/api/dataset.csv")
def dataset_csv():
    import csv
    with get_db() as db:
        rows = db.execute("SELECT * FROM experiments ORDER BY created_at ASC").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "created_at", "algorithm", "experiment_type", "input_bytes", "trial_number",
                     "elapsed_ns", "throughput_bytes_s", "changed_output_bits", "avalanche_percent",
                     "input_description", "digest_hex", "metadata_json"])
    for row in rows:
        writer.writerow([row[k] for k in row.keys()])
    data = output.getvalue().encode("utf-8")
    return StreamingResponse(iter([data]), media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="hashlab_experimental_dataset.csv"'})

@app.post("/api/file/hash")
async def hash_file(file: UploadFile = File(...), algorithm: str = "SHA-256"):
    algorithm_info(algorithm)
    h = hashlib.new(ALGORITHMS[algorithm]["name"])
    size = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        h.update(chunk)
    digest = h.hexdigest()
    return {"filename": Path(file.filename or "uploaded-file").name, "algorithm": algorithm,
            "size_bytes": size, "digest": digest,
            "note": "Digest is computed over exact file bytes. Keep the reference digest in a trusted location."}

@app.post("/api/file/baseline")
async def store_baseline(file: UploadFile = File(...), algorithm: str = "SHA-256"):
    algorithm_info(algorithm)
    h = hashlib.new(ALGORITHMS[algorithm]["name"])
    size = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        h.update(chunk)
    digest = h.hexdigest()
    baseline_id = str(uuid.uuid4())
    created = datetime.now(timezone.utc).isoformat()
    filename = Path(file.filename or "uploaded-file").name
    with get_db() as db:
        db.execute("INSERT INTO baselines VALUES (?, ?, ?, ?, ?, ?)",
                   (baseline_id, created, filename, algorithm, size, digest))
        db.commit()
    return {"baseline_id": baseline_id, "filename": filename, "algorithm": algorithm,
            "size_bytes": size, "digest": digest, "created_at": created,
            "warning": "This local database is a demo baseline store, not tamper-proof evidence storage."}

@app.get("/api/file/baselines")
def baselines():
    with get_db() as db:
        rows = db.execute("SELECT * FROM baselines ORDER BY created_at DESC LIMIT 100").fetchall()
    return [dict(row) for row in rows]

@app.post("/api/file/verify/{baseline_id}")
async def verify_file(baseline_id: str, file: UploadFile = File(...)):
    with get_db() as db:
        baseline = db.execute("SELECT * FROM baselines WHERE id=?", (baseline_id,)).fetchone()
    if baseline is None:
        raise HTTPException(status_code=404, detail="Baseline not found.")
    h = hashlib.new(ALGORITHMS[baseline["algorithm"]]["name"])
    size = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        h.update(chunk)
    digest = h.hexdigest()
    matched = digest == baseline["digest_hex"] and size == baseline["size_bytes"]
    return {"baseline_id": baseline_id, "algorithm": baseline["algorithm"],
            "baseline_filename": baseline["filename"], "uploaded_filename": Path(file.filename or "uploaded-file").name,
            "baseline_size_bytes": baseline["size_bytes"], "uploaded_size_bytes": size,
            "baseline_digest": baseline["digest_hex"], "uploaded_digest": digest,
            "status": "MATCH" if matched else "MISMATCH",
            "meaning": "MATCH means bytes match the saved baseline; MISMATCH means content or size differs."}

@app.get("/api/summary")
def summary():
    with get_db() as db:
        count = db.execute("SELECT COUNT(*) FROM experiments").fetchone()[0]
        types = db.execute("SELECT experiment_type, COUNT(*) n FROM experiments GROUP BY experiment_type").fetchall()
        algos = db.execute("SELECT algorithm, COUNT(*) n FROM experiments GROUP BY algorithm").fetchall()
    return {"total_experiments": count, "by_type": {r["experiment_type"]: r["n"] for r in types},
            "by_algorithm": {r["algorithm"]: r["n"] for r in algos},
            "algorithms": list(ALGORITHMS.keys())}
