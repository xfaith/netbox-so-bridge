import json
from pathlib import Path

def load_state(path):
    p = Path(path)
    if not p.exists():
        return {"assets": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"assets": {}}
    except Exception:
        return {"assets": {}}

def apply_history(coverage, state):
    previous = state.get("assets", {})
    for ip, row in coverage.items():
        old = previous.get(ip, {})
        old_first = str(old.get("historical_first_seen") or "")
        old_last = str(old.get("historical_last_seen") or "")
        row.historical_first_seen = min(old_first, row.first_seen) if old_first and row.first_seen else (old_first or row.first_seen)
        row.historical_last_seen = max(old_last, row.last_seen) if old_last and row.last_seen else (old_last or row.last_seen)

def save_state(path, coverage):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {"assets": {}}
    for ip, row in coverage.items():
        data["assets"][ip] = {
            "name": row.name,
            "historical_first_seen": row.historical_first_seen or row.first_seen,
            "historical_last_seen": row.historical_last_seen or row.last_seen,
            "last_observed_by": sorted(row.observed_by),
        }
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(p)
