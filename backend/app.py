from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib

app = Flask(__name__)
CORS(app)

# Load trained model
model = joblib.load("../model/logistic_regression_model_final.pkl")
vectorizer = joblib.load("../model/tfidf_vectorizer_final.pkl")

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()

    columns = [
        "Method", "User-Agent", "host", "cookie",
        "content-type", "content", "URL"
    ]

    # Combine HTTP request information
    request_text = " ".join(
        str(data.get(column, "")) for column in columns
    )

    # Convert request to TF-IDF features
    X = vectorizer.transform([request_text])

    # Get anomaly probability
    probabilities = model.predict_proba(X)[0]
    anomaly_probability = probabilities[1]

    # Classification threshold
    prediction = 1 if anomaly_probability >= 0.35 else 0
    result = "Anomalous" if prediction == 1 else "Normal"

    return jsonify({
        "prediction": prediction,
        "result": result,
        "normal_probability": float(probabilities[0]),
        "anomalous_probability": float(probabilities[1])
    })

if __name__ == "__main__":
    app.run(debug=True)