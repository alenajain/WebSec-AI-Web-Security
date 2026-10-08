document.addEventListener("DOMContentLoaded", function () {

    const overlay = document.getElementById("scanOverlay");

    if (!overlay) return;

    const form =
        document.querySelector(".scan-form") ||
        document.querySelector(".message-form");

    const status = document.getElementById("scanStatus");

    if (!form) return;

    form.addEventListener("submit", function () {

        overlay.classList.add("active");

        const messages = form.classList.contains("message-form")
            ? [
                "Reading the message...",
                "Looking for pressure and threats...",
                "Inspecting embedded links...",
                "Running AI analysis..."
              ]
            : [
                "Inspecting the destination...",
                "Checking URL warning signs...",
                "Looking for suspicious patterns...",
                "Running AI analysis..."
              ];

        let index = 0;
        status.textContent = messages[0];

        setInterval(function () {
            index = (index + 1) % messages.length;
            status.textContent = messages[index];
        }, 650);
    });

});