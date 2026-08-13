"""
Resume/CV Screening Assistant
SafeX Solutions - AI/ML Internship - Week 2 Task
Author: Maryam Yaqoob (FA23-BAI-025)

Core engine: parses resumes (PDF + plain text), scores them against a job
description using TF-IDF + cosine similarity, and produces a ranked
shortlist with matched/missing keywords and basic bias-check notes.
"""

import os
import re
import glob
import pandas as pd
import pdfplumber
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# ---------------------------------------------------------------------------
# A curated skills vocabulary used for keyword matching / matched-missing
# skill reporting. In a production tool this could be pulled from a larger
# skills taxonomy (e.g. ESCO, LinkedIn Skills API) - kept small here since
# this is a mock/demo task.
# ---------------------------------------------------------------------------
SKILL_VOCAB = [
    "python", "pandas", "numpy", "sql", "excel", "statistics",
    "data visualization", "matplotlib", "seaborn", "machine learning",
    "scikit-learn", "power bi", "tableau", "git", "data cleaning",
    "api integration", "communication skills", "communication",
]

# Words that shouldn't be treated as differentiating "missing skills" even
# though they appear in a JD (too generic to be meaningful signals).
GENERIC_SOFT_SKILLS = {"communication", "communication skills", "teamwork"}


# ---------------------------------------------------------------------------
# STEP 1: Extract text from resumes (PDF and plain text)
# ---------------------------------------------------------------------------
def extract_text_from_pdf(path: str) -> str:
    text_parts = []
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text()
            if page_text:
                text_parts.append(page_text)
    return "\n".join(text_parts)


def extract_text_from_txt(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def extract_text(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pdf":
        return extract_text_from_pdf(path)
    elif ext in (".txt",):
        return extract_text_from_txt(path)
    else:
        raise ValueError(f"Unsupported file type: {ext}")


def load_resumes(folder: str) -> dict:
    """Returns {filename: raw_text} for every .pdf/.txt file in folder."""
    resumes = {}
    paths = sorted(glob.glob(os.path.join(folder, "*.pdf")) +
                    glob.glob(os.path.join(folder, "*.txt")))
    for path in paths:
        filename = os.path.basename(path)
        try:
            resumes[filename] = extract_text(path)
        except Exception as e:
            print(f"Warning: could not parse {filename}: {e}")
    return resumes


# ---------------------------------------------------------------------------
# STEP 2: Preprocessing
# ---------------------------------------------------------------------------
def clean_text(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9\s\-\+#]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


# ---------------------------------------------------------------------------
# STEP 3: Scoring - TF-IDF + cosine similarity
# ---------------------------------------------------------------------------
def score_resumes(job_description: str, resumes: dict) -> pd.DataFrame:
    filenames = list(resumes.keys())
    raw_texts = [resumes[f] for f in filenames]
    cleaned_texts = [clean_text(t) for t in raw_texts]
    cleaned_jd = clean_text(job_description)

    corpus = [cleaned_jd] + cleaned_texts
    vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2))
    tfidf_matrix = vectorizer.fit_transform(corpus)

    jd_vector = tfidf_matrix[0:1]
    resume_vectors = tfidf_matrix[1:]
    similarities = cosine_similarity(jd_vector, resume_vectors)[0]

    rows = []
    jd_skills_found = extract_skills(cleaned_jd)

    for filename, raw_text, cleaned, sim in zip(filenames, raw_texts, cleaned_texts, similarities):
        resume_skills = extract_skills(cleaned)
        matched = sorted(jd_skills_found & resume_skills)
        missing = sorted(jd_skills_found - resume_skills - GENERIC_SOFT_SKILLS)

        rows.append({
            "filename": filename,
            "match_score": round(float(sim) * 100, 2),
            "matched_skills": ", ".join(matched) if matched else "-",
            "missing_skills": ", ".join(missing) if missing else "-",
            "matched_skill_count": len(matched),
        })

    df = pd.DataFrame(rows)
    df = df.sort_values(["match_score"], ascending=False).reset_index(drop=True)
    df.insert(0, "rank", range(1, len(df) + 1))
    return df


def extract_skills(cleaned_text: str) -> set:
    found = set()
    for skill in SKILL_VOCAB:
        if skill in cleaned_text:
            found.add(skill)
    return found


# ---------------------------------------------------------------------------
# STEP 4: Basic bias-check notes (advanced/optional requirement)
# ---------------------------------------------------------------------------
UNIVERSITY_KEYWORDS = ["university", "institute", "college"]


def bias_check_notes(resumes: dict, df: pd.DataFrame) -> list:
    """
    Flags simple patterns worth a human reviewer's attention - this is NOT
    a bias detector, just a lightweight sanity-check layer to remind users
    that automated screening can over-index on surface features.
    """
    notes = []
    scores = df["match_score"]
    if scores.max() - scores.min() < 5:
        notes.append(
            "All resumes scored within a narrow band (<5 points apart) - "
            "the JD-resume vocabulary overlap may be too generic to "
            "meaningfully differentiate candidates. Recommend manual review."
        )

    top_score = scores.max()
    if top_score < 30:
        notes.append(
            "No resume scored above 30% match. This may indicate the JD "
            "uses different terminology than candidates, or the applicant "
            "pool genuinely doesn't fit well - manual review recommended "
            "before rejecting anyone automatically."
        )

    notes.append(
        "This tool ranks based on keyword/phrase overlap with the job "
        "description. It does not verify claims, assess actual competence, "
        "or account for equivalent experience described in different "
        "wording. Do not use match_score as a sole hiring decision."
    )
    notes.append(
        "Caution: resumes that heavily mirror the JD's exact wording "
        "(e.g. copy-pasted skill lists) will score artificially high. "
        "Cross-check top-ranked resumes for genuine project/experience "
        "evidence, not just keyword density."
    )
    return notes


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    with open("job_description.txt", "r", encoding="utf-8") as f:
        jd_text = f.read()

    print("Loading and parsing resumes...")
    resumes = load_resumes("sample_resumes")
    print(f"Parsed {len(resumes)} resumes ({sum(1 for f in resumes if f.endswith('.pdf'))} PDF, "
          f"{sum(1 for f in resumes if f.endswith('.txt'))} TXT)\n")

    print("Scoring resumes against job description...")
    ranked_df = score_resumes(jd_text, resumes)

    os.makedirs("output", exist_ok=True)
    ranked_df.to_csv("output/ranked_shortlist.csv", index=False)

    print("=" * 70)
    print("RANKED SHORTLIST")
    print("=" * 70)
    print(ranked_df[["rank", "filename", "match_score", "matched_skill_count"]].to_string(index=False))

    print("\n" + "=" * 70)
    print("BIAS-CHECK / REVIEW NOTES")
    print("=" * 70)
    for note in bias_check_notes(resumes, ranked_df):
        print(f"- {note}")

    print(f"\nFull results saved to output/ranked_shortlist.csv")
