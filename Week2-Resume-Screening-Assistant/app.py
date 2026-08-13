"""
Resume/CV Screening Assistant - Streamlit UI
SafeX Solutions - AI/ML Internship - Week 2 Task
Author: Maryam Yaqoob (FA23-BAI-025)

Run with: streamlit run app.py
"""

import os
import tempfile
import streamlit as st
import pandas as pd

from resume_screener import (
    extract_text, score_resumes, bias_check_notes,
)

st.set_page_config(page_title="Resume Screening Assistant", layout="wide")

st.title("Resume / CV Screening Assistant")
st.caption("SafeX Solutions - AI/ML Internship demo tool. Upload a job description "
           "and a batch of resumes to get a ranked, explainable shortlist.")

st.warning(
    "This tool is a decision-support aid, not an automated hiring decision-maker. "
    "Match scores reflect keyword/phrase overlap only - always have a human review "
    "the shortlist before rejecting or advancing any candidate.",
    icon="⚠️",
)

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("1. Job description")
    jd_input_mode = st.radio("Provide job description via:", ["Paste text", "Upload .txt file"], horizontal=True)
    if jd_input_mode == "Paste text":
        jd_text = st.text_area("Paste the job description here", height=280,
                                placeholder="Paste the full job description text...")
    else:
        jd_file = st.file_uploader("Upload job description (.txt)", type=["txt"])
        jd_text = jd_file.read().decode("utf-8", errors="ignore") if jd_file else ""

with col2:
    st.subheader("2. Resumes")
    uploaded_resumes = st.file_uploader(
        "Upload resumes (PDF or TXT) - multiple files allowed",
        type=["pdf", "txt"], accept_multiple_files=True,
    )
    st.caption("Sample resumes are in the sample_resumes/ folder if you want to test quickly.")

run_button = st.button("Rank resumes", type="primary", disabled=not (jd_text and uploaded_resumes))

if not jd_text and not uploaded_resumes:
    st.info("Add a job description and at least one resume to get started.")

if run_button:
    with st.spinner("Parsing resumes and scoring against job description..."):
        resumes = {}
        with tempfile.TemporaryDirectory() as tmpdir:
            for uploaded_file in uploaded_resumes:
                tmp_path = os.path.join(tmpdir, uploaded_file.name)
                with open(tmp_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())
                try:
                    resumes[uploaded_file.name] = extract_text(tmp_path)
                except Exception as e:
                    st.error(f"Could not parse {uploaded_file.name}: {e}")

        if not resumes:
            st.error("No resumes could be parsed. Check the file formats and try again.")
        else:
            ranked_df = score_resumes(jd_text, resumes)

            st.subheader("Ranked shortlist")
            st.dataframe(
                ranked_df[["rank", "filename", "match_score", "matched_skills", "missing_skills"]],
                use_container_width=True,
                hide_index=True,
                column_config={
                    "match_score": st.column_config.ProgressColumn(
                        "match_score (%)", min_value=0, max_value=100, format="%.1f%%"
                    ),
                },
            )

            csv_bytes = ranked_df.to_csv(index=False).encode("utf-8")
            st.download_button("Download shortlist as CSV", csv_bytes,
                                file_name="ranked_shortlist.csv", mime="text/csv")

            st.subheader("Bias-check / review notes")
            for note in bias_check_notes(resumes, ranked_df):
                st.markdown(f"- {note}")

            with st.expander("View parsed resume text (for debugging/verification)"):
                selected = st.selectbox("Choose a resume", list(resumes.keys()))
                st.text(resumes[selected][:3000])
