# Sentiment Analysis on Sample Client Feedback

**Internship:** SafeX Solutions — AI/ML Track (Week 1)
**Intern:** Maryam Yaqoob (FA23-BAI-025), COMSATS University Islamabad
**Group Leader:** Malaika Adnan

## Objective
Run sentiment analysis on a set of mock client feedback comments, summarize the
positive/neutral/negative distribution with a chart, and flag the 3 most
negative comments for follow-up.

## Approach
1. **Data:** 25 sample client feedback comments were written to mimic realistic
   SaaS/customer-support feedback (mix of product praise, support complaints,
   billing issues, neutral remarks, etc.).
2. **Sentiment Engine:** `vaderSentiment` (VADER — Valence Aware Dictionary and
   sEntiment Reasoner) was used. VADER is rule-based and tuned for short,
   informal text like reviews and social comments, which fits client feedback
   well. It was chosen over a full Hugging Face transformer pipeline for this
   task because the dataset is small and VADER requires no model download —
   it's fast, lightweight, and fully offline-capable.
3. **Classification thresholds** (standard VADER convention, based on the
   compound score which ranges from -1 to +1):
   - `compound >= 0.05` → **Positive**
   - `compound <= -0.05` → **Negative**
   - otherwise → **Neutral**
4. **Output:**
   - `sentiment_results.csv` — every comment with its compound score and label
   - `sentiment_distribution_chart.png` — bar chart of Positive/Neutral/Negative counts
   - `flagged_negative_comments.csv` — the 3 lowest-scoring comments

## Results
| Sentiment | Count | Percentage |
|-----------|-------|------------|
| Positive  | 11    | 44.0%      |
| Neutral   | 5     | 20.0%      |
| Negative  | 9     | 36.0%      |

**Top 3 flagged negative comments (lowest compound score, for follow-up):**
1. (-0.648) "I'm really disappointed with the delayed response time this week."
2. (-0.593) "It's fine, average service, wouldn't say I'm impressed or disappointed."
3. (-0.571) "I am extremely frustrated, we've reported this bug three times now."

## Limitations
- **Negation handling:** Comment #2 above ("wouldn't say I'm impressed or
  disappointed") was scored negative even though the intent is closer to
  neutral. VADER weights the word "disappointed" heavily and doesn't fully
  resolve the surrounding negation/hedging — a known limitation of
  lexicon-based sentiment tools on nuanced or sarcastic phrasing.
- **Small sample size:** 25 comments is enough to demonstrate the pipeline but
  too small to draw statistically reliable conclusions about real client
  sentiment trends.
- **Domain generality:** VADER's lexicon is general-purpose (tuned on social
  media text), not fine-tuned specifically for customer-support language, so
  edge cases in industry-specific phrasing may be misclassified.

## Tools Used
- Python 3
- `vaderSentiment`
- `pandas`
- `matplotlib`

## How to Run
```bash
pip install vaderSentiment matplotlib pandas
python sentiment_analysis.py
```
