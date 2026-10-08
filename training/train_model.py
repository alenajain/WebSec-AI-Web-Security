import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report


# 1. Load datasets
csic = pd.read_csv("../dataset/csic_database.csv")
modern = pd.read_csv("../test_server/modern_normal_large.csv")


# 2. Select HTTP request fields
columns = [
    "Method",
    "User-Agent",
    "host",
    "cookie",
    "content-type",
    "content",
    "URL"
]

csic = csic[columns + ["classification"]]

modern = modern[columns + ["classification"]]
modern = modern.drop_duplicates()


# 3. Use part of modern traffic for training
modern_train, modern_test = train_test_split(
    modern,
    test_size=0.20,
    random_state=42
)

data = pd.concat(
    [csic, modern_train],
    ignore_index=True
)


# 4. Combine HTTP fields into one text
data["request_text"] = (
    data[columns]
    .fillna("")
    .astype(str)
    .agg(" ".join, axis=1)
)

X = data["request_text"]
y = data["classification"]


# 5. Split training and testing data
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


# 6. Convert text into TF-IDF features
vectorizer = TfidfVectorizer(
    max_features=50000,
    ngram_range=(1, 2)
)

X_train = vectorizer.fit_transform(X_train)
X_test = vectorizer.transform(X_test)


# 7. Train Logistic Regression
model = LogisticRegression(
    max_iter=1000,
    random_state=42
)

model.fit(X_train, y_train)


# 8. Evaluate using threshold 0.35
probabilities = model.predict_proba(X_test)[:, 1]

predictions = (
    probabilities >= 0.35
).astype(int)

print(
    "Accuracy:",
    round(
        accuracy_score(y_test, predictions) * 100,
        2
    ),
    "%"
)

print(
    classification_report(
        y_test,
        predictions,
        target_names=["Normal", "Anomalous"]
    )
)


# 9. Save model
joblib.dump(
    model,
    "../model/logistic_regression_model_final.pkl"
)

joblib.dump(
    vectorizer,
    "../model/tfidf_vectorizer_final.pkl"
)

print("Model saved successfully.")