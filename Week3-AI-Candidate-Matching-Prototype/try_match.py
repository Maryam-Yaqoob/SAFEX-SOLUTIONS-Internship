"""try_match.py - Stage 3 manual check: match one or more candidates against the job.

Usage (project folder, venv active):
    python try_match.py C001
    python try_match.py C001 C011 C012

Makes ONE Gemini call per candidate id. Prints the score, reasoning, matched and
missing skills and the skill-gap explanation. The author's rough tier label from
data/expected_tiers.json is printed ONLY for comparison; it is never sent to the model.

ASSUMPTIONS (flagged):
  1. data/job.json holds the single job; candidates come from data/candidates.json.
  2. Exit code: 0 all matched, 1 at least one candidate failed, 2 usage/data problem.
  3. Candidates are processed one after another with no delay; for a few ids this
     stays inside typical free-tier limits (batch/rate-limit handling is Stage 6).
"""
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from matcher import MatchError, match_candidate
from schemas import CandidateProfile, JobRequirements

DATA_DIR = Path(__file__).resolve().parent / "data"


def load_data():
    job = JobRequirements.model_validate(json.loads((DATA_DIR / "job.json").read_text(encoding="utf-8")))
    raw = json.loads((DATA_DIR / "candidates.json").read_text(encoding="utf-8"))
    candidates = {c.candidate_id: c for c in (CandidateProfile.model_validate(x) for x in raw)}
    tiers_path = DATA_DIR / "expected_tiers.json"
    tiers = json.loads(tiers_path.read_text(encoding="utf-8")).get("tiers", {}) if tiers_path.exists() else {}
    return job, candidates, tiers


def main(argv: list[str]) -> int:
    try:
        job, candidates, tiers = load_data()
    except (OSError, json.JSONDecodeError, ValidationError) as e:
        print(f"[DATA] could not load data files: {e}. Run python validate_data.py first.")
        return 2

    ids = [a.upper() for a in argv]
    if not ids:
        print("Usage: python try_match.py C001 [C002 ...]")
        print("Valid ids:", ", ".join(sorted(candidates)))
        return 2
    unknown = [i for i in ids if i not in candidates]
    if unknown:
        print(f"[USAGE] unknown candidate id(s): {unknown}. Valid ids: {', '.join(sorted(candidates))}")
        return 2

    failed = 0
    for cid in ids:
        cand = candidates[cid]
        print("=" * 72)
        print(f"{cid} | {cand.name} | {cand.current_title} | author tier: {tiers.get(cid, '?')} (not sent to the model)")
        try:
            result = match_candidate(job, cand)
        except MatchError as e:
            failed += 1
            print(f"FAILED {e}")
            continue
        print(f"Score     : {result.score}/100")
        print(f"Reasoning : {result.reasoning}")
        print(f"Matched   : {', '.join(result.matched_skills) or '(none)'}")
        print(f"Missing   : {', '.join(result.missing_skills) or '(none)'}")
        print(f"Skill gap : {result.skill_gap_explanation}")
    print("=" * 72)
    print(f"Done: {len(ids) - failed} ok, {failed} failed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
