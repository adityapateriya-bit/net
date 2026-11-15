// NetScan dashboard: talks to the Java backend's /api endpoints.
const $ = (id) => document.getElementById(id);

const form = $("scanForm");
const hostInput = $("host");
const portsInput = $("ports");
const timeout = $("timeout");
const scanBtn = $("scanBtn");
const errorBox = $("error");

let lastResults = [];
let activeFilter = "ALL";

// ---- setup -----------------------------------------------------------------

fetch("/api/config")
  .then((r) => r.json())
  .then((cfg) => {
    if (cfg.publicMode) {
      const badge = $("modeBadge");
      badge.hidden = false;
      badge.title = "Running on a public server: private and loopback addresses are blocked. Run NetScan locally to scan your own network.";
      $("localBtn").hidden = true;
    } else {
      hostInput.value = "127.0.0.1";
    }
  })
  .catch(() => {});

timeout.addEventListener("input", () => ($("timeoutVal").textContent = timeout.value));

document.querySelectorAll('input[name="preset"]').forEach((radio) =>
  radio.addEventListener("change", () => {
    const custom = radio.value === "custom" && radio.checked;
    portsInput.hidden = !custom;
    if (custom) portsInput.focus();
  })
);

$("localBtn").addEventListener("click", () => (hostInput.value = "127.0.0.1"));

$("myIpBtn").addEventListener("click", async () => {
  try {
    const { ip } = await (await fetch("/api/whoami")).json();
    hostInput.value = ip;
  } catch {
    showError("Could not detect your IP address.");
  }
});

document.querySelectorAll(".stat").forEach((btn) =>
  btn.addEventListener("click", () => {
    activeFilter = btn.dataset.filter;
    document.querySelectorAll(".stat").forEach((b) => b.classList.toggle("active", b === btn));
    renderRows();
  })
);

// ---- scanning --------------------------------------------------------------

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  hideError();

  const preset = document.querySelector('input[name="preset"]:checked').value;
  const ports = preset === "custom" ? portsInput.value.trim() : preset;
  const host = hostInput.value.trim();

  if (!host) return showError("Enter a target host or IP address.");
  if (!ports) return showError("Enter the ports to scan.");
  if (!$("authorized").checked) return showError("Please confirm you are authorised to scan this target.");

  setLoading(true);
  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ host, ports, timeout: timeout.value, authorized: "true" }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Scan failed.");
    showResults(data);
  } catch (err) {
    showError(err.message);
  } finally {
    setLoading(false);
  }
});

function showResults(data) {
  lastResults = data.results;
  const s = data.summary;
  $("nOpen").textContent = s.open;
  $("nClosed").textContent = s.closed;
  $("nFiltered").textContent = s.filtered;
  $("nTotal").textContent = s.total;

  const target = data.host === data.ip ? data.ip : ${data.host} (${data.ip});
  const when = new Date(data.startedAt).toLocaleString();
  $("meta").textContent = ${target} · ${s.total} ports in ${(data.durationMs / 1000).toFixed(2)} s · ${when};

  const csv = $("csvBtn");
  csv.href = /api/scans/${data.id}.csv;

  // Default to showing open ports when there are any — that's what people care about.
  activeFilter = s.open > 0 ? "OPEN" : "ALL";
  document.querySelectorAll(".stat").forEach((b) => b.classList.toggle("active", b.dataset.filter === activeFilter));

  renderRows();
  $("resultsCard").hidden = false;
  $("resultsCard").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderRows() {
  const label = { OPEN: "Open", CLOSED: "Closed", FILTERED: "No response" };
  const rows = lastResults.filter((r) => activeFilter === "ALL" || r.status === activeFilter);
  const tbody = $("rows");
  tbody.replaceChildren(
    ...rows.map((r) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${r.port}</td>
        <td><span class="pill ${r.status}">${label[r.status]}</span></td>
        <td></td>
        <td>${r.status === "FILTERED" ? "timeout" : r.latencyMs + " ms"}</td>`;
      tr.children[2].textContent = r.service; // textContent: never inject server strings as HTML
      return tr;
    })
  );
  $("emptyRow").hidden = rows.length > 0;
}

// ---- ui helpers ------------------------------------------------------------

function setLoading(on) {
  scanBtn.disabled = on;
  scanBtn.classList.toggle("loading", on);
  scanBtn.querySelector(".btn-text").textContent = on ? "Scanning…" : "Start scan";
}

function showError(msg) {
  errorBox.textContent = msg;
  errorBox.hidden = false;
}

function hideError() {
  errorBox.hidden = true;
}
