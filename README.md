# Healthcare Claims: Predictive Cost & Risk Analysis

## Project Overview
This repository contains a comprehensive data science workflow focused on healthcare insurance analytics. The project moves from raw data wrangling and relational database design to advanced predictive modeling, culminating in a stakeholder-facing visualization dashboard.

## Live Links
* **Interactive Analytics Dashboard:** https://public.tableau.com/authoring/RiskPredictiveCostAnalysis/RiskPredictiveCostAnalysis#1

## Core Objectives
* **Cost Driver Identification:** Quantifying the financial impact of lifestyle factors on annual healthcare expenditures.
* **Risk Stratification:** Developing a multi-tier risk scoring system to identify high-cost member segments.
* **Predictive Accuracy:** Transitioning from baseline statistical models to advanced machine learning to minimize forecasting error.

## Technical Stack
* **Languages:** Python (Pandas, Scikit-learn, NumPy), SQL (SQLite).
* **Frameworks:** Flask (Model Deployment).
* **Visualization:** Tableau (Business Intelligence Reporting).
* **Database Management:** 3NF Relational Schema Design.

## Key Technical Milestones

### 1. Data Engineering & SQL Architecture
* Conducted extensive **Data Wrangling** on 1,300+ records to handle categorical encoding and feature engineering.
* Implemented a relational database structure to separate demographic attributes from financial claim records, ensuring data integrity and scalable querying.

### 2. Machine Learning Pipeline
* **Baseline Modeling:** Established a Linear Regression baseline ($R^2$: 0.09) using age-based parameters.
* **Advanced Modeling:** Developed a **Random Forest Regressor** ($R^2$: 0.86), successfully capturing non-linear interactions between BMI and lifestyle indicators to reduce prediction error.

### 3. Stakeholder Visualization
* Designed a **Tableau Dashboard** to translate complex model residuals and cost distributions into an easily understood, "user-friendly" format for business decision-makers.

### 4. Web Deployment
* Built and deployed a **Flask-based REST API** and web interface, allowing for real-time cost estimation based on user-inputted health metrics.

## How to Use
1. Clone the repository: `git clone [Your Repo Link]`
2. Install dependencies: `pip install -r requirements.txt`
3. Launch the local web server: `python app.py`
4. View the interface at: `http://127.0.0.1:5000/`

*Note: This project was developed as part of a Master’s in Artificial Intelligence curriculum to demonstrate proficiency in applied data science for the insurance industry.*
