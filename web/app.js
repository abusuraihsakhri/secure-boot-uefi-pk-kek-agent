"use strict";

const form = document.getElementById("simulation-form");
const button = document.getElementById("run");
const runtime = document.getElementById("runtime");
const summary = document.getElementById("summary");
const checks = document.getElementById("checks");
const json = document.getElementById("json");
let enginePromise = null;

async function readSource(name) {
  const response = await fetch("./" + name, { cache: "no-cache" });
  if (!response.ok) throw new Error("Cannot load " + name + " (HTTP " + response.status + ")");
  return response.text();
}

async function initPython() {
  if (typeof loadPyodide !== "function") {
    throw new Error("Pyodide script is unavailable. Check your network connection.");
  }
  runtime.textContent = "Loading the Python WebAssembly runtime…";
  const py = await loadPyodide({ indexURL: "https://cdn.jsdelivr.net/pyodide/v0.27.7/full/" });
  const sources = await Promise.all([readSource("simulator.py"), readSource("browser_bridge.py")]);
  py.FS.writeFile("/home/pyodide/simulator.py", sources[0]);
  py.FS.writeFile("/home/pyodide/browser_bridge.py", sources[1]);
  await py.runPythonAsync("import sys\nimport importlib\nimportlib.invalidate_caches()\nsys.path.insert(0, '/home/pyodide')\nfrom browser_bridge import evaluate");
  runtime.textContent = "Python simulator ready. All evaluations execute in this tab.";
  return py;
}

function render(data) {
  summary.className = "summary " + (data.boot_allowed ? "ok" : "fail");
  summary.textContent = (data.boot_allowed ? "ALLOWED" : "REJECTED") +
    " · " + data.executed_checks + " component checks · " + data.policy + " policy";
  checks.replaceChildren();
  for (const item of data.results) {
    const li = document.createElement("li");
    const label = document.createElement("span");
    label.className = "label " + (item.valid ? "accepted" : "rejected");
    label.textContent = (item.valid ? "PASS · " : "FAIL · ") + item.component;
    const detail = document.createElement("span");
    detail.className = "detail";
    detail.textContent = item.reason;
    li.append(label, detail);
    checks.append(li);
  }
  json.textContent = JSON.stringify(data, null, 2);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!form.reportValidity()) return;
  button.disabled = true;
  summary.className = "summary";
  summary.textContent = "Running simulation…";
  checks.replaceChildren();
  try {
    if (enginePromise === null) enginePromise = initPython().catch(error => {
      enginePromise = null;
      throw error;
    });
    const py = await enginePromise;
    const input = {
      label: document.getElementById("label").value,
      policy: document.getElementById("policy").value,
      scenario: document.getElementById("scenario").value
    };
    const evaluation = py.globals.get("evaluate");
    try {
      render(JSON.parse(evaluation(JSON.stringify(input))));
    } finally {
      evaluation.destroy();
    }
  } catch (error) {
    summary.className = "summary fail";
    summary.textContent = "Simulation unavailable: " + String(error.message || error);
    json.textContent = "No report produced.";
    runtime.textContent = "Runtime failed; check internet access and page assets.";
  } finally {
    button.disabled = false;
  }
});
