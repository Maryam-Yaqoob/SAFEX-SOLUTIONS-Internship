"""validate_data.py - Stage 2 check: loads the synthetic data and validates it.

Run from the project folder (venv active):  python validate_data.py

Reads data/job.json, data/candidates.json and data/expected_tiers.json.
Exit code 0 = everything valid, 1 = at least one problem (all problems are listed).

ASSUMPTIONS (flagged):
  1. expected_tiers.json holds the AUTHOR's own rough labels (strong/medium/weak)
     for sanity-checking rankings later. They are NOT ground truth and must never
     be sent to the LLM.
  2. Files live in a data/ folder next to this script; files are UTF-8.
  3. Every candidate must have exactly one tier label, and no label may point to
     an unknown candidate. These cross-checks use the ids found in the raw JSON, so
     one invalid record is reported once instead of also showing up as "unknown".
"""
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from schemas import CandidateProfile, JobRequirements

DATA_DIR = Path(__file__).resolve().parent / "data"


class ExpectedTiers(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: str
    note: str
    tiers: dict[str, Literal["strong", "medium", "weak"]]
    notes: dict[str, str] = {}


def load_json(name: str):
    path = DATA_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"{path} not found")
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def describe(err: ValidationError) -> str:
    return "; ".join(f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in err.errors())


def main() -> int:
    problems: list[str] = []
    job = None
    candidates: list[CandidateProfile] = []
    raw_ids: list[str] = []  # ids read from the raw JSON, so one bad record does not cascade
    tiers = None

    try:
        job = JobRequirements.model_validate(load_json("job.json"))
    except (FileNotFoundError, json.JSONDecodeError, ValidationError) as e:
        problems.append(f"job.json: {describe(e) if isinstance(e, ValidationError) else e}")

    try:
        raw = load_json("candidates.json")
        if not isinstance(raw, list):
            raise ValueError("top level must be a JSON list")
        for i, item in enumerate(raw):
            if isinstance(item, dict) and isinstance(item.get("candidate_id"), str):
                raw_ids.append(item["candidate_id"])
            try:
                candidates.append(CandidateProfile.model_validate(item))
            except ValidationError as e:
                label = item.get("candidate_id", f"#{i}") if isinstance(item, dict) else f"#{i}"
                problems.append(f"candidates.json [{label}]: {describe(e)}")
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        problems.append(f"candidates.json: {e}")

    try:
        tiers = ExpectedTiers.model_validate(load_json("expected_tiers.json"))
    except (FileNotFoundError, json.JSONDecodeError, ValidationError) as e:
        problems.append(f"expected_tiers.json: {describe(e) if isinstance(e, ValidationError) else e}")

    ids = raw_ids
    for dup, n in Counter(ids).items():
        if n > 1:
            problems.append(f"duplicate candidate_id: {dup} ({n}x)")
    if job and tiers and tiers.job_id != job.job_id:
        problems.append(f"expected_tiers job_id {tiers.job_id} != job.json job_id {job.job_id}")
    if tiers and ids:
        missing = sorted(set(ids) - set(tiers.tiers))
        unknown = sorted(set(tiers.tiers) - set(ids))
        if missing:
            problems.append(f"candidates without a tier label: {missing}")
        if unknown:
            problems.append(f"tier labels for unknown candidates: {unknown}")

    print(f"Job        : {'OK - ' + job.job_id + ' ' + job.title if job else 'INVALID'}")
    print(f"Candidates : {len(candidates)} valid")
    if tiers:
        print(f"Tier counts: {dict(Counter(tiers.tiers.values()))}")
    sparse = [c.candidate_id for c in candidates if not (c.summary and c.location and c.education)]
    print(f"Missing summary/location/education (edge-case data): {sparse}")

    if problems:
        print(f"\n{len(problems)} problem(s):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("\nOK - all data files are valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
