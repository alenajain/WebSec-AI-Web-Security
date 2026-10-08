const form = document.getElementById("requestForm");

let totalRequests = 0;
let normalRequests = 0;
let anomalousRequests = 0;

form.addEventListener("submit", async function (event) {
    event.preventDefault();

    const data = {
        Method: document.getElementById("Method").value,
        "User-Agent": document.getElementById("User-Agent").value,
        host: document.getElementById("host").value,
        cookie: document.getElementById("cookie").value,
        "content-type": document.getElementById("content-type").value,
        content: document.getElementById("content").value,
        URL: document.getElementById("URL").value
    };
    // Check required fields
if (
    !data.Method.trim() ||
    !data["User-Agent"].trim() ||
    !data.host.trim() ||
    !data.URL.trim()
) {
    alert("Please fill in Method, User-Agent, Host and URL.");
    return;
}

    try {
        console.log("Data being sent:", data);
        const response = await fetch("http://127.0.0.1:5000/predict", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        });

        const result = await response.json();

        // Show result
        const resultBox = document.getElementById("result");
        const resultText = document.getElementById("resultText");
        const statusIcon = document.getElementById("statusIcon");

        const normalPercentage =
            result.normal_probability * 100;

        const anomalousPercentage =
            result.anomalous_probability * 100;

        resultBox.classList.remove(
            "hidden",
            "normal-result",
            "anomalous-result"
        );

        if (result.prediction === 1) {
            resultText.textContent = "ANOMALOUS";
            statusIcon.textContent = "🚨";
            resultBox.classList.add("anomalous-result");

            anomalousRequests++;
        } else {
            resultText.textContent = "NORMAL";
            statusIcon.textContent = "🛡️";
            resultBox.classList.add("normal-result");

            normalRequests++;
        }

        totalRequests++;

        // Update probabilities
        document.getElementById("normalProbability").textContent =
            normalPercentage.toFixed(2) + "%";

        document.getElementById("anomalousProbability").textContent =
            anomalousPercentage.toFixed(2) + "%";

        document.getElementById("normalBar").style.width =
            normalPercentage + "%";

        document.getElementById("anomalousBar").style.width =
            anomalousPercentage + "%";

        // Update statistics
        document.getElementById("totalCount").textContent =
            totalRequests;

        document.getElementById("normalCount").textContent =
            normalRequests;

        document.getElementById("anomalousCount").textContent =
            anomalousRequests;

        // Add to history
        addToHistory(data, result);

    } catch (error) {
        console.error(error);
        alert("Could not connect to the Flask server.");
    }
});


function addToHistory(data, result) {

    const history = document.getElementById("history");

    const emptyMessage =
        history.querySelector(".empty-history");

    if (emptyMessage) {
        emptyMessage.remove();
    }

    const historyItem = document.createElement("div");
    historyItem.classList.add("history-item");

    // Time
    const time = document.createElement("div");
    time.classList.add("history-time");

    const now = new Date();

    time.textContent = now.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit"
    });

    // Request information
    const requestInfo = document.createElement("div");
    requestInfo.classList.add("history-request");

    const method = document.createElement("strong");
    method.textContent = data.Method;

    const url = document.createElement("span");

    // Remove HTTP version from display
    let displayURL = data.URL
    .replace(" HTTP/1.1", "")
    .replace(" HTTP/1.0", "");

// Show only the path instead of the full localhost URL
try {
    const parsedURL = new URL(displayURL);
    displayURL = parsedURL.pathname + parsedURL.search;
} catch (error) {
    // Keep the original URL if it cannot be parsed
}

url.textContent = displayURL;
url.title = data.URL;

    requestInfo.appendChild(method);
    requestInfo.appendChild(document.createElement("br"));
    requestInfo.appendChild(url);

    // Prediction
    const status = document.createElement("div");
    status.classList.add("history-status");

    if (result.prediction === 1) {

        status.textContent =
            "ANOMALOUS — " +
            (result.anomalous_probability * 100).toFixed(2) +
            "%";

        status.classList.add("history-anomalous");

    } else {

        status.textContent =
            "NORMAL — " +
            (result.normal_probability * 100).toFixed(2) +
            "%";

        status.classList.add("history-normal");
    }

    historyItem.appendChild(time);
    historyItem.appendChild(requestInfo);
    historyItem.appendChild(status);

    history.prepend(historyItem);
}