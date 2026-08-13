# Resume / CV Screening Assistant

**Internship:** SafeX Solutions — AI/ML Track (Week 2)
**Intern:** Maryam Yaqoob (FA23-BAI-025), COMSATS University Islamabad
**Group Leader:** Malaika Adnan

## Objective
Build a small AI tool that scores and ranks resumes against a given job/internship
description, so SafeX and its clients can quickly shortlist relevant candidates
from a large pool of applications.

## Project structure
```
resume_screener/
├── app.py                       # Streamlit UI
├── resume_screener.py           # Core engine (parsing, scoring, bias notes)
├── generate_sample_resumes.py   # Generates the 12 mock sample resumes
├── job_description.txt          # Sample job description
├── sample_resumes/              # 12 mock resumes (6 .txt + 6 .pdf)
├── output/
│   └── ranked_shortlist.csv     # Example ranked output (CLI run)
└── README.md
```

## Approach

### 1. Data
Since real candidate resumes cannot be used (privacy), 12 **fictional, anonymized**
mock resumes were created covering a spread of relevance to a sample "Junior Data
Analyst / Python Developer" job description — from strong technical fits (Data
Science, Python/SQL/ML backgrounds) to weak fits (Marketing, HR, Graphic Design,
Finance). Six resumes are saved as `.txt`, six as `.pdf`, to exercise both parsing
paths required by the task.

### 2. Text extraction
- **PDF** → `pdfplumber` extracts text page by page.
- **Plain text** → read directly.
- A single `extract_text()` function dispatches by file extension, so the rest of
  the pipeline doesn't care what format a resume came in.

### 3. Scoring — TF-IDF + cosine similarity
Each resume and the job description are cleaned (lowercased, punctuation
stripped) and vectorized together using **TF-IDF** (`scikit-learn`,
unigrams + bigrams, English stopwords removed). The resume's similarity to the
job description is computed as the **cosine similarity** between their TF-IDF
vectors, scaled to a 0–100 `match_score`.

TF-IDF + cosine similarity was chosen over a transformer embedding model
(e.g. `sentence-transformers`) because it requires no model download, runs
fully offline, and is fast and transparent enough to explain to a
non-technical stakeholder — a good fit for this scale of task. It also
naturally rewards resumes that use the same domain vocabulary as the JD,
which is a reasonable first-pass filter.

### 4. Matched / missing skills
A small curated skills vocabulary (Python, SQL, pandas, machine learning,
Power BI, etc., pulled from common JD language) is checked against both the
job description and each resume. This produces an explainable
**matched_skills** / **missing_skills** breakdown per candidate — so a
reviewer can see *why* a resume scored the way it did, not just the number.

### 5. Ranking
Resumes are sorted by `match_score` descending and given a `rank`. Output is
saved to `output/ranked_shortlist.csv` and shown in the Streamlit UI with
matched/missing skills columns.

### 6. UI
`app.py` (Streamlit) lets a user:
- Paste or upload a job description
- Upload multiple resumes (PDF or TXT)
- See a ranked, sortable table with progress-bar match scores
- Download the shortlist as CSV
- Expand any resume to view its raw parsed text (for verifying extraction
  quality)

## Example results (sample data)
Top of the ranked shortlist against the sample JD (`job_description.txt`):

| Rank | Resume | Match Score | Matched skills (count) |
|------|--------|-------------|--------------------------|
| 1 | resume_03_candidate_C.txt | 22.70% | 11 |
| 2 | resume_07_candidate_G.pdf | 22.18% | 10 |
| 3 | resume_01_candidate_A.txt | 18.75% | 10 |
| 4 | resume_05_candidate_E.txt | 14.67% | 7 |

The three lowest-ranked resumes (HR, Marketing, Sales backgrounds) all scored
under 3% — consistent with them being genuinely poor fits for a Python/data
role, which is a reasonable sanity check on the pipeline.

Full output: `output/ranked_shortlist.csv`

## Bias-check / review notes (built into the tool)
The tool prints/displays a short set of caution notes alongside every run,
for example:
- Flags when all scores are clustered tightly together (weak differentiation,
  needs manual review).
- Flags when no resume scores reasonably high (may mean JD wording doesn't
  match candidate wording, not that candidates are unqualified).
- A standing reminder that **match_score reflects keyword/phrase overlap
  only** — it does not verify claims or assess real competence, and should
  never be the sole basis for a hiring decision.
- A caution that resumes which closely mirror the JD's exact wording (e.g.
  copy-pasted skill lists) can score artificially high, so top-ranked
  resumes should be spot-checked for genuine supporting experience.

## Ethical notes on automated resume screening
- **Keyword bias:** Any keyword/TF-IDF-based tool will favor candidates who
  happen to use the same terminology as the job description, which
  disadvantages equally qualified candidates who describe their experience
  differently (e.g. "cleaned datasets" vs. "data cleaning").
- **Not a substitute for human judgment:** This tool is a *first-pass filter*
  to help a recruiter triage a large pool faster — not a decision-maker. Final
  shortlisting and interview decisions should always involve human review.
- **University-name bias risk:** Automated tools can implicitly reward
  resumes from well-known universities purely through associated vocabulary
  (e.g. more polished project descriptions). This tool does not use
  university name as a scoring feature, but reviewers should stay alert to
  this pattern when reading resumes manually.
- **Small vocabulary limitation:** The skills list used here is manually
  curated and JD-specific — it will miss valid but differently-worded skills
  (e.g. "Looker" not being recognized as similar to "Power BI"/"Tableau").

## Minimum requirements checklist
- [x] Correctly parses text from PDF and plain text resumes
- [x] Produces a ranked shortlist with a numeric match score
- [x] Simple working UI (Streamlit)

## Advanced (optional) requirements
- [x] Highlights matched/missing skills per resume
- [x] Basic bias-check notes included in both CLI and UI output

## Tools used
- Python 3
- `pdfplumber` (PDF text extraction)
- `scikit-learn` (TF-IDF, cosine similarity)
- `pandas`
- `streamlit` (UI)
- `fpdf2` (used only to generate the mock sample PDF resumes for testing)

## How to run

**CLI (produces `output/ranked_shortlist.csv`):**
```bash
pip install pdfplumber scikit-learn pandas streamlit
python resume_screener.py
```

**Streamlit UI:**
```bash
streamlit run app.py
```
Then open the local URL shown in the terminal, upload/paste a job description
and resumes, and click "Rank resumes".

**Regenerate sample resumes (optional, already included in repo):**
```bash
pip install fpdf2
python generate_sample_resumes.py
```

## Demo
A screen recording of uploading resumes and viewing rankings in the Streamlit
UI should be attached separately for submission (per task requirements).
