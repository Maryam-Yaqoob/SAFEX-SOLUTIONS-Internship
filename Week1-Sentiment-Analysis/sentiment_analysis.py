"""
Sentiment Analysis on Sample Client Feedback
SafeX Solutions - AI/ML Internship - Week 1 Task
Author: Maryam Yaqoob (FA23-BAI-025)

Objective:
Run sentiment analysis on a set of mock/sample client feedback comments,
summarize the positive/neutral/negative distribution with a chart, and
flag the 3 most negative comments for follow-up.
"""

import pandas as pd
import matplotlib.pyplot as plt
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer

# ---------------------------------------------------------------------------
# STEP 1: Sample client feedback comments (mock data, 25 comments)
# ---------------------------------------------------------------------------
feedback_comments = [
    "The support team resolved my issue within minutes, amazing service!",
    "I'm really disappointed with the delayed response time this week.",
    "The product works exactly as described, very satisfied.",
    "Customer service was rude and unhelpful during my last call.",
    "It's an okay experience, nothing special but does the job.",
    "Absolutely love the new dashboard update, so much easier to use!",
    "The billing system charged me twice and no one has fixed it yet.",
    "Decent product overall, though the setup process was confusing.",
    "Your team went above and beyond to help us migrate our data. Thank you!",
    "The app keeps crashing every time I try to export a report.",
    "Support responded quickly but the solution didn't actually fix my problem.",
    "Great value for money, would definitely recommend to other businesses.",
    "I've had a mediocre experience so far, some features feel unfinished.",
    "This is the worst customer support experience I've ever had.",
    "The onboarding call was very informative and the rep was patient with us.",
    "Nothing to complain about, everything works as expected.",
    "The new update broke our integration and cost us a full day of work.",
    "Fantastic UI, our whole team switched over without any training needed.",
    "It's fine, average service, wouldn't say I'm impressed or disappointed.",
    "I am extremely frustrated, we've reported this bug three times now.",
    "Quick turnaround on our support ticket, really appreciate the effort.",
    "The pricing is a bit high for what we're getting compared to competitors.",
    "Excellent product, excellent support, couldn't ask for more.",
    "Painfully slow load times are making our workflow unbearable.",
    "Solid platform, minor bugs here and there but support fixes them fast.",
]

# ---------------------------------------------------------------------------
# STEP 2: Apply sentiment analysis (VADER)
# ---------------------------------------------------------------------------
analyzer = SentimentIntensityAnalyzer()

results = []
for comment in feedback_comments:
    scores = analyzer.polarity_scores(comment)
    compound = scores["compound"]

    # Standard VADER thresholding for classification
    if compound >= 0.05:
        label = "Positive"
    elif compound <= -0.05:
        label = "Negative"
    else:
        label = "Neutral"

    results.append({
        "comment": comment,
        "compound_score": compound,
        "sentiment": label
    })

df = pd.DataFrame(results)

# ---------------------------------------------------------------------------
# STEP 3: Summarize positive/neutral/negative distribution
# ---------------------------------------------------------------------------
distribution = df["sentiment"].value_counts().reindex(
    ["Positive", "Neutral", "Negative"], fill_value=0
)

print("=" * 60)
print("SENTIMENT DISTRIBUTION SUMMARY")
print("=" * 60)
print(distribution.to_string())
print()
print(f"Total comments analyzed: {len(df)}")
print(f"Positive: {distribution['Positive']} ({distribution['Positive']/len(df)*100:.1f}%)")
print(f"Neutral:  {distribution['Neutral']} ({distribution['Neutral']/len(df)*100:.1f}%)")
print(f"Negative: {distribution['Negative']} ({distribution['Negative']/len(df)*100:.1f}%)")
print()

# Save full results to CSV
df_sorted = df.sort_values("compound_score")
df.to_csv("sentiment_results.csv", index=False)

# ---------------------------------------------------------------------------
# STEP 4: Chart of sentiment distribution
# ---------------------------------------------------------------------------
colors = {"Positive": "#4CAF50", "Neutral": "#9E9E9E", "Negative": "#E53935"}
plt.figure(figsize=(7, 5))
bars = plt.bar(distribution.index, distribution.values,
                color=[colors[k] for k in distribution.index])

for bar in bars:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width() / 2, height + 0.2,
              str(int(height)), ha="center", fontweight="bold")

plt.title("Client Feedback Sentiment Distribution", fontsize=13, fontweight="bold")
plt.ylabel("Number of Comments")
plt.xlabel("Sentiment Category")
plt.ylim(0, max(distribution.values) + 3)
plt.tight_layout()
plt.savefig("sentiment_distribution_chart.png", dpi=150)
plt.close()

print("Chart saved as sentiment_distribution_chart.png")
print()

# ---------------------------------------------------------------------------
# STEP 5: Flag the 3 most negative comments for follow-up
# ---------------------------------------------------------------------------
most_negative = df.sort_values("compound_score").head(3)

print("=" * 60)
print("TOP 3 MOST NEGATIVE COMMENTS (FLAGGED FOR FOLLOW-UP)")
print("=" * 60)
for i, row in enumerate(most_negative.itertuples(), 1):
    print(f"{i}. (score: {row.compound_score:.3f}) {row.comment}")

most_negative.to_csv("flagged_negative_comments.csv", index=False)
print()
print("Flagged comments saved to flagged_negative_comments.csv")
