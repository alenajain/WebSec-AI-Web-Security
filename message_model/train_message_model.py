import pandas as pd

# Load SMS Spam Collection dataset
df = pd.read_csv(
    "SMSSpamCollection",
    sep="\t",
    names=["label", "message"]
)

print("Dataset shape:", df.shape)
print("\nLabel counts:")
print(df["label"].value_counts())

print("\nFirst 5 messages:")
print(df.head())
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report

# Convert labels: ham = 0, spam = 1
df["target"] = df["label"].map({
    "ham": 0,
    "spam": 1
})

X = df["message"]
y = df["target"]

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

# Convert messages into TF-IDF features
vectorizer = TfidfVectorizer(
    max_features=10000,
    ngram_range=(1, 2)
)

X_train_tfidf = vectorizer.fit_transform(X_train)
X_test_tfidf = vectorizer.transform(X_test)

# Train model
model = LogisticRegression(
    max_iter=1000,
    class_weight="balanced",
    random_state=42
)

model.fit(X_train_tfidf, y_train)

# Test model
predictions = model.predict(X_test_tfidf)

print("\n--- MESSAGE MODEL RESULTS ---")
print("Accuracy:", round(accuracy_score(y_test, predictions) * 100, 2), "%")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        target_names=["Normal", "Spam/Scam"]
    )
)
import joblib

joblib.dump(model, "message_model.pkl")
joblib.dump(vectorizer, "message_vectorizer.pkl")

print("\nModel and vectorizer saved successfully.")