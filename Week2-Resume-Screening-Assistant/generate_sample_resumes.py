"""
Generates 12 anonymized mock resumes for testing the screening tool:
6 saved as .txt, 6 saved as .pdf (to demonstrate parsing both formats).
All names/emails/data below are fictional sample data.
"""

import os
from fpdf import FPDF
from fpdf.enums import XPos, YPos

OUTPUT_DIR = "sample_resumes"
os.makedirs(OUTPUT_DIR, exist_ok=True)

resumes = {
    "resume_01_candidate_A": """
Candidate A
Email: candidateA@example.com | Phone: 0300-0000001

SUMMARY
Recent Computer Science graduate with strong Python and data analysis skills.
Completed 2 internships focused on data cleaning and dashboard building.

SKILLS
Python, pandas, numpy, SQL, matplotlib, seaborn, Excel, statistics, Git

EXPERIENCE
Data Analyst Intern - TechCorp (6 months)
- Cleaned and analyzed large datasets using pandas
- Built dashboards in matplotlib and seaborn to report weekly KPIs
- Wrote SQL queries to extract data from PostgreSQL databases

EDUCATION
BS Computer Science, 2026

PROJECTS
- Built a student performance prediction model using scikit-learn
- Automated a monthly Excel reporting pipeline in Python
""",

    "resume_02_candidate_B": """
Candidate B
Email: candidateB@example.com | Phone: 0300-0000002

SUMMARY
Marketing graduate with 1 year of experience in social media management
and content strategy.

SKILLS
Social media marketing, content writing, Canva, basic Excel, communication,
customer engagement

EXPERIENCE
Marketing Assistant - BrandCo (1 year)
- Managed social media calendars and campaigns
- Wrote copy for email marketing
- Tracked campaign performance in Excel

EDUCATION
BBA Marketing, 2025
""",

    "resume_03_candidate_C": """
Candidate C
Email: candidateC@example.com | Phone: 0300-0000003

SUMMARY
Data Science student with hands-on machine learning project experience
and strong statistics background.

SKILLS
Python, pandas, scikit-learn, SQL, statistics, data visualization,
machine learning, Git, communication skills

EXPERIENCE
ML Research Assistant - University Lab (8 months)
- Built classification models using scikit-learn
- Performed exploratory data analysis with pandas and seaborn
- Presented findings to non-technical stakeholders

EDUCATION
BS Data Science, expected 2027

PROJECTS
- Sentiment analysis tool using Python and NLP libraries
- SQL-based sales dashboard for a mock retail dataset
""",

    "resume_04_candidate_D": """
Candidate D
Email: candidateD@example.com | Phone: 0300-0000004

SUMMARY
Mechanical engineering graduate exploring a transition into data roles,
self-taught in basic Python.

SKILLS
AutoCAD, SolidWorks, basic Python, Excel, problem-solving, teamwork

EXPERIENCE
Mechanical Design Intern - BuildWorks (4 months)
- Assisted in CAD modeling for industrial components
- Used Excel for basic material cost tracking

EDUCATION
BS Mechanical Engineering, 2025
""",

    "resume_05_candidate_E": """
Candidate E
Email: candidateE@example.com | Phone: 0300-0000005

SUMMARY
Business analyst with strong SQL and Power BI experience, some exposure
to Python for automation.

SKILLS
SQL, Power BI, Excel, Python (basic), data visualization, stakeholder
communication, data cleaning

EXPERIENCE
Business Analyst - RetailPlus (1.5 years)
- Built Power BI dashboards for sales and inventory tracking
- Wrote complex SQL queries for reporting
- Automated recurring reports using Python scripts

EDUCATION
BBA, 2024
""",

    "resume_06_candidate_F": """
Candidate F
Email: candidateF@example.com | Phone: 0300-0000006

SUMMARY
HR graduate with experience in recruitment and employee engagement,
minimal technical background.

SKILLS
Recruitment, onboarding, MS Office, communication, conflict resolution

EXPERIENCE
HR Coordinator - PeopleFirst (1 year)
- Managed candidate screening and interview scheduling
- Maintained employee records in Excel

EDUCATION
BBA Human Resource Management, 2025
""",
}

pdf_resumes = {
    "resume_07_candidate_G": """
Candidate G
Email: candidateG@example.com | Phone: 0300-0000007

SUMMARY
Computer Science student specializing in machine learning and data
engineering, strong Python and SQL skills.

SKILLS
Python, pandas, numpy, scikit-learn, SQL, machine learning, data
visualization, matplotlib, Git, API integration, statistics

EXPERIENCE
Data Science Intern - Insight Analytics (6 months)
- Built and evaluated ML models using scikit-learn
- Cleaned and merged data from multiple SQL sources
- Created visualizations to communicate insights to stakeholders

EDUCATION
BS Computer Science, expected 2026

PROJECTS
- Churn prediction model, Kaggle housing price regression project
""",

    "resume_08_candidate_H": """
Candidate H
Email: candidateH@example.com | Phone: 0300-0000008

SUMMARY
Graphic designer with strong Adobe Creative Suite skills, minimal
data or programming background.

SKILLS
Photoshop, Illustrator, InDesign, branding, typography, communication

EXPERIENCE
Junior Graphic Designer - CreativeHub (1 year)
- Designed marketing materials and brand assets
- Collaborated with marketing team on campaign visuals

EDUCATION
BFA Graphic Design, 2025
""",

    "resume_09_candidate_I": """
Candidate I
Email: candidateI@example.com | Phone: 0300-0000009

SUMMARY
Statistics graduate with strong analytical foundation and growing
Python and SQL skills.

SKILLS
Statistics, Python, pandas, SQL, Excel, data cleaning, data
visualization, communication skills

EXPERIENCE
Research Assistant - Statistics Department (1 year)
- Performed statistical analysis on survey datasets using Python
- Built visualizations to summarize research findings
- Queried and joined tables in SQL for reporting

EDUCATION
BS Statistics, 2025

PROJECTS
- Built an automated data cleaning pipeline in pandas
""",

    "resume_10_candidate_J": """
Candidate J
Email: candidateJ@example.com | Phone: 0300-0000010

SUMMARY
Sales executive with strong client relationship skills and basic
Excel reporting experience.

SKILLS
Sales, negotiation, CRM tools, Excel, communication, customer
relationship management

EXPERIENCE
Sales Executive - MarketReach (2 years)
- Managed client accounts and closed deals
- Tracked sales performance in Excel

EDUCATION
BBA Sales and Marketing, 2023
""",

    "resume_11_candidate_K": """
Candidate K
Email: candidateK@example.com | Phone: 0300-0000011

SUMMARY
Software engineering student with full-stack development experience
and growing interest in data analysis and Python scripting.

SKILLS
Python, Java, SQL, Git, pandas (basic), data visualization (basic),
problem-solving, teamwork

EXPERIENCE
Software Development Intern - CodeWorks (5 months)
- Built backend APIs using Python
- Wrote SQL queries for application data
- Assisted in building a basic internal reporting dashboard

EDUCATION
BS Software Engineering, expected 2026

PROJECTS
- Personal finance tracker using Python and pandas
""",

    "resume_12_candidate_L": """
Candidate L
Email: candidateL@example.com | Phone: 0300-0000012

SUMMARY
Finance graduate with strong Excel modeling skills, minimal exposure
to programming or SQL.

SKILLS
Financial modeling, Excel, budgeting, forecasting, communication,
attention to detail

EXPERIENCE
Finance Intern - CapitalWorks (6 months)
- Built financial models in Excel
- Assisted in quarterly budget forecasting

EDUCATION
BBA Finance, 2025
""",
}


def make_pdf(text: str, path: str) -> None:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=11)
    for line in text.strip("\n").split("\n"):
        pdf.multi_cell(0, 6, line if line.strip() else " ",
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.output(path)


if __name__ == "__main__":
    for name, content in resumes.items():
        with open(os.path.join(OUTPUT_DIR, f"{name}.txt"), "w", encoding="utf-8") as f:
            f.write(content.strip())
        print(f"Created {name}.txt")

    for name, content in pdf_resumes.items():
        make_pdf(content, os.path.join(OUTPUT_DIR, f"{name}.pdf"))
        print(f"Created {name}.pdf")

    print(f"\nDone. {len(resumes)} .txt + {len(pdf_resumes)} .pdf resumes created in '{OUTPUT_DIR}/'")
