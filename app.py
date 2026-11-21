import os
import sys
import threading
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Query

import database
from detector import Detector
from sniffer import start_sniffing
from simulate import run_simulation

detector = Detector()


@asynccontextmanager
async def lifespan(app):
    database.init_db()

    if os.environ.get("IDS_MODE") == "demo":
        target = run_simulation   # fake traffic
    else:
        target = start_sniffing   # real traffic

    worker = threading.Thread(target=target, args=(detector,), daemon=True)
    worker.start()

    yield  # server is running here


app = FastAPI(title="Simple IDS", lifespan=lifespan)


@app.get("/alerts")
def alerts(limit: int = Query(50, le=500), severity: str | None = None):
    return database.get_alerts(limit, severity)


@app.get("/stats")
def stats():
    return {
        "by_rule": database.count_by("rule"),
        "by_severity": database.count_by("severity"),
    }


@app.get("/top-attackers")
def top_attackers():
    return database.top_attackers()


@app.get("/timeline")
def timeline(minutes: int = Query(60, ge=1)):
    return database.timeline(minutes)


@app.get("/graph")
def graph():
    return database.attack_graph()


if __name__ == "__main__":
    # "python app.py demo" uses fake traffic, otherwise sniff for real
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        os.environ["IDS_MODE"] = "demo"

    uvicorn.run(app, host="127.0.0.1", port=8000)