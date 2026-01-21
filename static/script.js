window.addEventListener("DOMContentLoaded", function () {
  var checkBtn = document.getElementById("checkBtn");
  var toggleBtn = document.getElementById("toggleMode");
  var output = document.getElementById("output");
  var input = document.getElementById("urlInput");

  checkBtn.addEventListener("click", checkWebsite);

  toggleBtn.addEventListener("click", () => {
    document.body.classList.toggle("dark-mode");
  });

function openPopup(data) {
    let popup = window.open("", "_blank", "width=450,height=550");

    popup.document.write(`
      <html>
      <head>
        <title>Website Analysis</title>
        <style>
          body { font-family: Arial; padding: 20px; background: #f8f8f8; }
          .good { color: green; font-weight: bold; }
          .bad { color: red; font-weight: bold; }
          .box {
            background: white; padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 12px rgba(0,0,0,0.2);
          }
        </style>
      </head>
      <body>
        <h2>🔍 Website Analysis Report</h2>

        <div class="box">
          <p><b>URL:</b> ${data.url}</p>
          <p><b>Domain Name:</b> ${data.domain_name}</p>
          <p><b>IP Address:</b> ${data.ip || "Not Available"}</p>
          <p><b>Registration Date:</b> ${data.registrar_date}</p>
          <p><b>Trust Score:</b> ${data.trust_score}/100</p>

          <p><b>Status:</b>
            <span class="${data.status === "Genuine" ? "good" : "bad"}">
              ${data.status}
            </span>
          </p>

          <p><b>Reason:</b> ${data.reason}</p>

          <!-- ⭐ NEW PURPOSE LINE ADDED HERE -->
          <p><b>Purpose:</b> ${data.purpose || "Not available"}</p>

        </div>
      </body>
      </html>
    `);
}


  async function checkWebsite() {
    let url = input.value.trim();
    if (!url) {
      output.className = "output fail";
      output.textContent = "Please enter a URL.";
      return;
    }

    output.textContent = "Checking...";

    try {
      let res = await fetch("/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url })
      });

      let data = await res.json();

      output.className = data.status === "Genuine" ? "output success" : "output fail";
      output.textContent = `${data.url} — ${data.status} (${data.reason})`;

      openPopup(data);

    } catch (err) {
      output.textContent = "Error checking website.";
    }
  }
});
