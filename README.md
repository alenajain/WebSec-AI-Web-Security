# AI-Based Web Security System

## Overview
This project detects anomalous HTTP requests using Machine Learning.

The system captures HTTP request information and classifies the request as either:

- Normal
- Anomalous

## Technologies Used
- Python
- Flask
- Pandas
- Scikit-learn
- TF-IDF
- Logistic Regression

## Dataset
CSIC 2010 HTTP Dataset along with additional modern normal HTTP requests.

## Working

HTTP Request
→ Flask Server
→ TF-IDF Vectorization
→ Logistic Regression
→ Normal / Anomalous

## Features Used
The model analyzes:

- Method
- User-Agent
- Host
- Cookie
- Content-Type
- Content
- URL

## Model
TF-IDF is used to convert HTTP request text into numerical features.

Logistic Regression is used for classification.

Classification threshold: 0.35

## Results
Final test accuracy: 97.87%

The system can analyze live browser requests and display:
- Classification result
- Normal probability
- Anomalous probability
- Recent request history

## How to Run

### Start AI Backend

Open a terminal:

    conda activate ai_security
    cd backend
    python app.py

### Start Test Server

Open another terminal:

    conda activate ai_security
    cd test_server
    python server.py

Then open:

    http://127.0.0.1:8000/

## Project Structure

    AI_Web_Security/
    ├── backend/
    │   └── app.py
    ├── dataset/
    │   └── csic_database.csv
    ├── model/
    │   ├── logistic_regression_model_final.pkl
    │   └── tfidf_vectorizer_final.pkl
    ├── test_server/
    │   ├── server.py
    │   └── modern_normal_large.csv
    ├── training/
    │   └── train_model.py
    ├── requirements.txt
    └── README.md