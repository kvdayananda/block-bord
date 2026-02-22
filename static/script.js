resultDiv.classList.remove("hidden");
resultDiv.innerHTML = "Scanning...";
async function scanText() {
    const text = document.getElementById("inputText").value;

    const response = await fetch("/scan", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ content: text })
    });

    const data = await response.json();

    const resultDiv = document.getElementById("result");
    resultDiv.classList.remove("hidden");

    resultDiv.innerHTML = `
        <h2>Risk Level: ${data.risk_level}</h2>
        <p>Risk Score: ${data.risk_score}%</p>
        <ul>${data.reasons.map(r => `<li>${r}</li>`).join("")}</ul>
    `;

    resultDiv.className = "";

    if (data.risk_level === "SAFE") {
        resultDiv.classList.add("safe");
    } else if (data.risk_level === "SUSPICIOUS") {
        resultDiv.classList.add("suspicious");
    } else {
        resultDiv.classList.add("high");
    }
}