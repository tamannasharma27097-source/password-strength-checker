/**
 * script.js
 * ---------
 * Main frontend logic for the Advanced Password Strength & Breach
 * Detection System. Vanilla JS only - no frameworks.
 *
 * Handles:
 *  - Live password analysis (calls /api/check)
 *  - Strength meter / gauge / composition chart rendering
 *  - Breach detection display
 *  - Password generator (calls /api/generate)
 *  - Session-only password history
 *  - PDF export (calls /api/export)
 *  - Theme toggle, toasts, cyber tips, keyboard shortcuts
 */

document.addEventListener("DOMContentLoaded", () => {
  // ---------- Loading screen ----------
  const loadingScreen = document.getElementById("loading-screen");
  window.addEventListener("load", () => {
    setTimeout(() => loadingScreen.classList.add("hidden"), 600);
  });
  // Fallback in case load already fired
  setTimeout(() => loadingScreen && loadingScreen.classList.add("hidden"), 2500);

  if (window.AOS) AOS.init({ duration: 700, once: true });

  // ---------- Elements ----------
  const passwordInput = document.getElementById("passwordInput");
  const toggleVisibilityBtn = document.getElementById("togglePasswordVisibility");
  const copyInputBtn = document.getElementById("copyInputBtn");

  const strengthLabel = document.getElementById("strengthLabel");
  const scoreLabel = document.getElementById("scoreLabel");
  const strengthBarFill = document.getElementById("strengthBarFill");

  const statLength = document.getElementById("statLength");
  const statUpper = document.getElementById("statUpper");
  const statLower = document.getElementById("statLower");
  const statNumber = document.getElementById("statNumber");
  const statSpecial = document.getElementById("statSpecial");
  const statUnique = document.getElementById("statUnique");
  const statRepeated = document.getElementById("statRepeated");
  const statEntropy = document.getElementById("statEntropy");
  const patternFlags = document.getElementById("patternFlags");

  const breachResult = document.getElementById("breachResult");
  const suggestionsList = document.getElementById("suggestionsList");

  const gaugeArc = document.getElementById("gaugeArc");
  const gaugeNumber = document.getElementById("gaugeNumber");
  const crackTimeValue = document.getElementById("crackTimeValue");

  const compositionCanvas = document.getElementById("compositionChart");
  const compositionCtx = compositionCanvas ? compositionCanvas.getContext("2d") : null;

  const exportPdfBtn = document.getElementById("exportPdfBtn");
  const historyTableBody = document.getElementById("historyTableBody");
  const themeToggle = document.getElementById("theme-toggle");
  const cyberTipText = document.getElementById("cyberTipText");

  const GAUGE_ARC_LENGTH = 283; // matches stroke-dasharray in the SVG

  let lastAnalysisPayload = null; // used for PDF export
  let historyCount = 0;
  let debounceTimer = null;

  // ---------- Toasts ----------
  function showToast(message, type = "success") {
    const container = document.getElementById("toastContainer");
    const toast = document.createElement("div");
    toast.className = `cyber-toast ${type === "error" ? "error" : ""}`;
    const icon = type === "error" ? "fa-triangle-exclamation" : "fa-circle-check";
    toast.innerHTML = `<i class="fa-solid ${icon}"></i><span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
  }

  // ---------- Animated number counter ----------
  function animateNumber(el, target, duration = 500) {
    const start = parseFloat(el.textContent) || 0;
    const startTime = performance.now();
    function step(now) {
      const progress = Math.min((now - startTime) / duration, 1);
      const value = start + (target - start) * progress;
      el.textContent = Number.isInteger(target) ? Math.round(value) : value.toFixed(1);
      if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  // ---------- Password visibility ----------
  toggleVisibilityBtn.addEventListener("click", () => {
    const isPassword = passwordInput.type === "password";
    passwordInput.type = isPassword ? "text" : "password";
    toggleVisibilityBtn.innerHTML = `<i class="fa-solid ${isPassword ? "fa-eye-slash" : "fa-eye"}"></i>`;
  });

  copyInputBtn.addEventListener("click", () => {
    if (!passwordInput.value) return;
    navigator.clipboard.writeText(passwordInput.value).then(() => showToast("Password copied to clipboard"));
  });

  // ---------- Strength color helper ----------
  function colorForLabel(label) {
    switch (label) {
      case "Very Weak": return "var(--neon-red)";
      case "Weak": return "#ff7a3d";
      case "Fair": return "var(--neon-yellow)";
      case "Strong": return "#7be07a";
      case "Very Strong": return "var(--neon-green)";
      default: return "var(--text-muted)";
    }
  }

  // ---------- Composition donut chart (pure canvas) ----------
  function drawComposition(analysis) {
    if (!compositionCtx) return;
    const segments = [
      { label: "Upper", value: analysis.uppercase_count, color: "#00e08f" },
      { label: "Lower", value: analysis.lowercase_count, color: "#26e5ff" },
      { label: "Numbers", value: analysis.number_count, color: "#ffd23f" },
      { label: "Special", value: analysis.special_count, color: "#b26bff" },
    ];
    const total = segments.reduce((sum, s) => sum + s.value, 0);

    const w = compositionCanvas.width = compositionCanvas.clientWidth * 2;
    const h = compositionCanvas.height = 180 * 2;
    compositionCtx.clearRect(0, 0, w, h);

    const cx = w / 2, cy = h / 2, radius = Math.min(w, h) / 2 - 12;

    if (total === 0) {
      compositionCtx.beginPath();
      compositionCtx.arc(cx, cy, radius, 0, Math.PI * 2);
      compositionCtx.strokeStyle = "rgba(255,255,255,0.1)";
      compositionCtx.lineWidth = 24;
      compositionCtx.stroke();
      return;
    }

    let startAngle = -Math.PI / 2;
    segments.forEach((seg) => {
      if (seg.value === 0) return;
      const sliceAngle = (seg.value / total) * Math.PI * 2;
      compositionCtx.beginPath();
      compositionCtx.arc(cx, cy, radius, startAngle, startAngle + sliceAngle);
      compositionCtx.strokeStyle = seg.color;
      compositionCtx.lineWidth = 28;
      compositionCtx.lineCap = "butt";
      compositionCtx.stroke();
      startAngle += sliceAngle;
    });

    // Legend text in center
    compositionCtx.fillStyle = "#e7f5f0";
    compositionCtx.font = "bold 28px Rajdhani, sans-serif";
    compositionCtx.textAlign = "center";
    compositionCtx.fillText(`${total}`, cx, cy - 4);
    compositionCtx.font = "14px Rajdhani, sans-serif";
    compositionCtx.fillStyle = "#93a6ac";
    compositionCtx.fillText("characters", cx, cy + 20);
  }

  // ---------- Pattern flags ----------
  function renderPatternFlags(analysis) {
    patternFlags.innerHTML = "";
    const flags = [
      { label: "Dictionary Word", bad: analysis.is_dictionary_word },
      { label: "Sequential Pattern", bad: analysis.is_sequential },
      { label: "Keyboard Pattern", bad: analysis.is_keyboard_pattern },
    ];
    flags.forEach((f) => {
      const pill = document.createElement("span");
      pill.className = `flag-pill ${f.bad ? "flag-bad" : "flag-good"}`;
      pill.innerHTML = `<i class="fa-solid ${f.bad ? "fa-xmark" : "fa-check"}"></i> ${f.label}`;
      patternFlags.appendChild(pill);
    });
  }

  // ---------- Breach display ----------
  function renderBreach(breach) {
    breachResult.className = "breach-result-box";
    if (breach.found) {
      breachResult.classList.add("breach-danger");
      breachResult.innerHTML = `
        <i class="fa-solid fa-triangle-exclamation"></i>
        <div>
          <div><strong>⚠ Password Found in Breach Dataset</strong></div>
          <div class="breach-meta-row">
            <span class="breach-meta-chip">Risk: ${breach.risk_level}</span>
            <span class="breach-meta-chip">Year: ${breach.breach_year}</span>
            <span class="breach-meta-chip">Exposed: ${breach.exposure_count.toLocaleString()} times</span>
            <span class="breach-meta-chip">${breach.source_name}</span>
          </div>
          <div class="mt-2 small text-muted">${breach.disclaimer}</div>
        </div>`;
    } else {
      breachResult.classList.add("breach-safe");
      breachResult.innerHTML = `
        <i class="fa-solid fa-shield-check"></i>
        <div>
          <div><strong>${breach.message}</strong></div>
          <div class="mt-1 small text-muted">${breach.disclaimer}</div>
        </div>`;
    }
  }

  // ---------- Suggestions ----------
  function renderSuggestions(suggestions) {
    suggestionsList.innerHTML = "";
    suggestions.forEach((s, i) => {
      const li = document.createElement("li");
      li.style.animationDelay = `${i * 40}ms`;
      li.textContent = s;
      suggestionsList.appendChild(li);
    });
  }

  // ---------- History ----------
  function addHistoryEntry(analysis, breach) {
    if (historyCount === 0) historyTableBody.innerHTML = "";
    historyCount++;

    const row = document.createElement("tr");
    const time = new Date().toLocaleTimeString();
    const breachBadge = breach.found
      ? `<span style="color:var(--neon-red)"><i class="fa-solid fa-triangle-exclamation"></i> Breached</span>`
      : `<span style="color:var(--neon-green)"><i class="fa-solid fa-shield-check"></i> Safe</span>`;

    row.innerHTML = `
      <td>${historyCount}</td>
      <td>${time}</td>
      <td>${analysis.strength_label}</td>
      <td>${analysis.strength_score} / 100</td>
      <td>${breachBadge}</td>`;
    historyTableBody.prepend(row);
  }

  // ---------- Main analysis update ----------
  function updateDashboard(data) {
    const { analysis, breach, suggestions } = data;
    lastAnalysisPayload = { password: passwordInput.value, analysis, breach, suggestions };

    strengthLabel.textContent = analysis.strength_label;
    strengthLabel.style.color = colorForLabel(analysis.strength_label);
    scoreLabel.textContent = `${analysis.strength_score} / 100`;
    strengthBarFill.style.width = `${analysis.strength_score}%`;

    animateNumber(statLength, analysis.password_length);
    animateNumber(statUpper, analysis.uppercase_count);
    animateNumber(statLower, analysis.lowercase_count);
    animateNumber(statNumber, analysis.number_count);
    animateNumber(statSpecial, analysis.special_count);
    animateNumber(statUnique, analysis.unique_characters);
    animateNumber(statRepeated, analysis.repeated_characters);
    animateNumber(statEntropy, analysis.entropy);

    renderPatternFlags(analysis);
    renderBreach(breach);
    renderSuggestions(suggestions);
    drawComposition(analysis);

    // Gauge
    const offset = GAUGE_ARC_LENGTH - (GAUGE_ARC_LENGTH * analysis.strength_score) / 100;
    gaugeArc.style.strokeDashoffset = offset;
    animateNumber(gaugeNumber, analysis.strength_score);

    crackTimeValue.textContent = analysis.crack_time_display;

    addHistoryEntry(analysis, breach);
  }

  function resetDashboard() {
    strengthLabel.textContent = "Very Weak";
    strengthLabel.style.color = "var(--text-muted)";
    scoreLabel.textContent = "0 / 100";
    strengthBarFill.style.width = "0%";
    [statLength, statUpper, statLower, statNumber, statSpecial, statUnique, statRepeated, statEntropy]
      .forEach((el) => (el.textContent = "0"));
    patternFlags.innerHTML = "";
    breachResult.className = "breach-result-box breach-neutral";
    breachResult.innerHTML = `<i class="fa-solid fa-circle-info"></i><span>Start typing a password to check the local offline dataset.</span>`;
    suggestionsList.innerHTML = `<li>Start typing to get personalized suggestions.</li>`;
    gaugeArc.style.strokeDashoffset = GAUGE_ARC_LENGTH;
    gaugeNumber.textContent = "0";
    crackTimeValue.textContent = "Less than 1 second";
    if (compositionCtx) compositionCtx.clearRect(0, 0, compositionCanvas.width, compositionCanvas.height);
  }

  async function analyzeCurrentPassword() {
    const password = passwordInput.value;
    if (!password) {
      resetDashboard();
      return;
    }
    try {
      const res = await fetch("/api/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password }),
      });
      const data = await res.json();
      updateDashboard(data);
    } catch (err) {
      showToast("Analysis request failed. Is the Flask server running?", "error");
    }
  }

  passwordInput.addEventListener("input", () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(analyzeCurrentPassword, 150);
  });

  // ---------- PDF export ----------
  exportPdfBtn.addEventListener("click", async () => {
    if (!lastAnalysisPayload || !lastAnalysisPayload.password) {
      showToast("Type a password to analyze before exporting.", "error");
      return;
    }
    try {
      const res = await fetch("/api/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(lastAnalysisPayload),
      });
      if (!res.ok) throw new Error("Export failed");
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "Password_Security_Report.pdf";
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      showToast("PDF report downloaded successfully");
    } catch (err) {
      showToast("Could not generate PDF report.", "error");
    }
  });

  // ============================================================
  // PASSWORD GENERATOR
  // ============================================================
  const lengthOptions = document.getElementById("lengthOptions");
  const lengthValue = document.getElementById("lengthValue");
  const generateBtn = document.getElementById("generateBtn");
  const regenerateBtn = document.getElementById("regenerateBtn");
  const generatedOutput = document.getElementById("generatedPasswordOutput");
  const copyGeneratedBtn = document.getElementById("copyGeneratedBtn");
  const generatedStrengthBadge = document.getElementById("generatedStrengthBadge");

  let selectedLength = 16;

  lengthOptions.addEventListener("click", (e) => {
    const btn = e.target.closest(".length-btn");
    if (!btn) return;
    document.querySelectorAll(".length-btn").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    selectedLength = parseInt(btn.dataset.len, 10);
    lengthValue.textContent = selectedLength;
  });

  async function runGenerate() {
    const payload = {
      length: selectedLength,
      uppercase: document.getElementById("optUpper").checked,
      lowercase: document.getElementById("optLower").checked,
      numbers: document.getElementById("optNumbers").checked,
      symbols: document.getElementById("optSymbols").checked,
      exclude_similar: document.getElementById("optExcludeSimilar").checked,
      exclude_ambiguous: document.getElementById("optExcludeAmbiguous").checked,
    };
    try {
      const res = await fetch("/api/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      generatedOutput.value = data.password;
      generatedStrengthBadge.textContent = data.analysis.strength_label;
      generatedStrengthBadge.style.color = colorForLabel(data.analysis.strength_label);
      generatedStrengthBadge.style.borderColor = colorForLabel(data.analysis.strength_label);
    } catch (err) {
      showToast("Password generation failed.", "error");
    }
  }

  generateBtn.addEventListener("click", runGenerate);
  regenerateBtn.addEventListener("click", runGenerate);

  copyGeneratedBtn.addEventListener("click", () => {
    if (!generatedOutput.value) return;
    navigator.clipboard.writeText(generatedOutput.value).then(() => showToast("Generated password copied"));
  });

  // ---------- Cyber tip ----------
  async function loadTip() {
    try {
      const res = await fetch("/api/tip");
      const data = await res.json();
      cyberTipText.textContent = data.tip;
    } catch (err) {
      cyberTipText.textContent = "Always use unique passwords for every account.";
    }
  }
  loadTip();

  // ---------- Theme toggle ----------
  const root = document.documentElement;
  themeToggle.addEventListener("click", () => {
    const isDark = root.getAttribute("data-theme") !== "light";
    root.setAttribute("data-theme", isDark ? "light" : "dark");
    themeToggle.innerHTML = `<i class="fa-solid ${isDark ? "fa-sun" : "fa-moon"}"></i>`;
  });

  // ---------- Keyboard shortcuts ----------
  document.addEventListener("keydown", (e) => {
    if (e.ctrlKey && e.key.toLowerCase() === "g") {
      e.preventDefault();
      document.getElementById("generator").scrollIntoView({ behavior: "smooth" });
    }
  });

  // Initial state
  resetDashboard();
  runGenerate();
});
