"""schemas.py - data models for the AI Candidate Matching Prototype.

Input models (Stage 2): JobRequirements, ExperienceEntry, CandidateProfile.
LLM output model (Stage 3): MatchResult, plus match_result_json_schema() which
builds the schema that is sent to Gemini.

ASSUMPTIONS (flagged):
  1. pydantic v2 (pinned 2.13.5 in requirements.txt).
  2. extra="forbid": unknown or misspelled fields are rejected, never ignored.
  3. Text is stripped of surrounding whitespace; required text must be non-empty.
  4. Deliberately NO age, gender, religion, nationality or photo fields: this is
     an HR screening tool and those fields would invite biased matching.
  5. years_experience and the per-job "years" values are NOT cross-checked against
     each other (self-reported, like a real CV).
  6. Optional candidate fields (location, summary, education, certifications,
     experience) may be missing or empty; the matcher must cope with that.
  7. All data is synthetic English text; companies and people are fictional.
  8. MatchResult has exactly the five fields decided for the project: score,
     reasoning, matched_skills, missing_skills, skill_gap_explanation. Stage 5 may
     refine skill_gap_explanation (and therefore this schema).
  9. The schema sent to Gemini is derived from the pydantic model but with a few
     JSON-Schema keywords removed (see _LLM_UNSUPPORTED_KEYS) because it is not
     verified that Gemini accepts them. pydantic still enforces everything on the
     reply, so nothing is lost; an empty text or a score outside 0-100 is caught
     after the call and triggers the retry in matcher.py.
  10. matched_skills / missing_skills should use the job's own skill wording, but
      this is requested in the prompt and NOT enforced by code in Stage 3.
"""
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
OptionalStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)] | None


def _dedupe(items: list[str]) -> list[str]:
    """Remove case-insensitive duplicates, keeping the first spelling and the order."""
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.casefold()
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


class JobRequirements(BaseModel):
    """One open role, as an HR manager would write it."""

    model_config = ConfigDict(extra="forbid")

    job_id: NonEmptyStr
    title: NonEmptyStr
    company: NonEmptyStr
    seniority: NonEmptyStr
    summary: NonEmptyStr
    responsibilities: list[NonEmptyStr] = Field(default_factory=list)
    must_have_skills: list[NonEmptyStr] = Field(min_length=1)
    nice_to_have_skills: list[NonEmptyStr] = Field(default_factory=list)
    min_years_experience: float = Field(ge=0, le=30)
    education_preference: OptionalStr = None
    location: OptionalStr = None
    remote_policy: OptionalStr = None

    @field_validator("must_have_skills", "nice_to_have_skills")
    @classmethod
    def _dedupe_skills(cls, value: list[str]) -> list[str]:
        return _dedupe(value)

    @field_validator("nice_to_have_skills")
    @classmethod
    def _no_overlap_with_must_have(cls, value: list[str], info) -> list[str]:
        must = {s.casefold() for s in info.data.get("must_have_skills", [])}
        clash = [s for s in value if s.casefold() in must]
        if clash:
            raise ValueError(f"skills listed as both must-have and nice-to-have: {clash}")
        return value


class ExperienceEntry(BaseModel):
    """One past role on a candidate's CV."""

    model_config = ConfigDict(extra="forbid")

    title: NonEmptyStr
    company: NonEmptyStr
    years: float = Field(ge=0, le=50)
    highlights: list[NonEmptyStr] = Field(default_factory=list)


class CandidateProfile(BaseModel):
    """One candidate. Only identity, title, years and skills are required."""

    model_config = ConfigDict(extra="forbid")

    candidate_id: NonEmptyStr
    name: NonEmptyStr
    current_title: NonEmptyStr
    years_experience: float = Field(ge=0, le=50)
    skills: list[NonEmptyStr] = Field(default_factory=list)
    location: OptionalStr = None
    summary: OptionalStr = None
    education: OptionalStr = None
    certifications: list[NonEmptyStr] = Field(default_factory=list)
    experience: list[ExperienceEntry] = Field(default_factory=list)

    @field_validator("skills", "certifications")
    @classmethod
    def _dedupe_lists(cls, value: list[str]) -> list[str]:
        return _dedupe(value)


class MatchResult(BaseModel):
    """The LLM's assessment of ONE candidate against ONE job."""

    model_config = ConfigDict(extra="forbid")

    score: int = Field(
        ge=0,
        le=100,
        description="Overall match score, an integer from 0 (no fit) to 100 (ideal fit).",
    )
    reasoning: NonEmptyStr = Field(
        description="2-4 sentences explaining the score, citing specific evidence from the candidate profile."
    )
    matched_skills: list[NonEmptyStr] = Field(
        default_factory=list,
        description="Job requirements (must-have or nice-to-have, in the job's own wording) that the candidate satisfies.",
    )
    missing_skills: list[NonEmptyStr] = Field(
        default_factory=list,
        description="Job requirements (in the job's own wording) that the candidate does not satisfy or satisfies only weakly.",
    )
    skill_gap_explanation: NonEmptyStr = Field(
        description="1-3 sentences on what is missing and how serious it is for this role; say so if there is no real gap."
    )

    @field_validator("matched_skills", "missing_skills")
    @classmethod
    def _dedupe_skill_lists(cls, value: list[str]) -> list[str]:
        return _dedupe(value)


# JSON-Schema keywords removed from the schema sent to Gemini (assumption 9).
_LLM_UNSUPPORTED_KEYS = {"title", "default", "additionalProperties", "minLength"}


def _clean_schema(node: Any, in_properties: bool = False) -> Any:
    """Recursively drop unsupported keywords. Property NAMES are never dropped."""
    if isinstance(node, dict):
        return {
            key: _clean_schema(value, in_properties=(key == "properties"))
            for key, value in node.items()
            if in_properties or key not in _LLM_UNSUPPORTED_KEYS
        }
    if isinstance(node, list):
        return [_clean_schema(item) for item in node]
    return node


def match_result_json_schema() -> dict[str, Any]:
    """JSON schema for MatchResult, as sent to Gemini (response_json_schema).

    All five fields are marked required for the model (pydantic would otherwise
    treat the two skill lists as optional because they default to empty).
    """
    schema = _clean_schema(MatchResult.model_json_schema())
    schema["required"] = list(schema["properties"])
    return schema
