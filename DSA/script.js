// ============================================================
// THREAT INTELLIGENCE KILL-CHAIN CORRELATION ENGINE
// FRONTEND MONITORING SCRIPT
// ============================================================

// ============================================================
// HELPER
// ============================================================

const $ = (id) => document.getElementById(id);

// ============================================================
// LOGIN ELEMENTS
// ============================================================

const loginScreen = $("loginScreen");
const loginForm = $("loginForm");
const username = $("username");
const password = $("password");
const loginMessage = $("loginMessage");

// ============================================================
// DASHBOARD ELEMENTS
// ============================================================

const monitor = $("monitor");

const eventStream = $("eventStream");
const timeline = $("timeline");

const attemptCount = $("attemptCount");
const riskScore = $("riskScore");
const correlationScore = $("correlationScore");
const systemStatus = $("systemStatus");

const sourceIP = $("sourceIP");
const ipEvents = $("ipEvents");
const uniqueUsers = $("uniqueUsers");
const ipThreatStatus = $("ipThreatStatus");

const resetBtn = $("resetBtn");

const threatAlert = $("threatAlert");
const riskLabel = $("riskLabel");
const scoreFill = $("scoreFill");

// ============================================================
// DSA PIPELINE
// ============================================================

function activatePipelineNodes(count) {

  const nodes = document.querySelectorAll(".pipeline-node");

  nodes.forEach((node, index) => {

    node.classList.remove("active");

    if (index < count) {
      node.classList.add("active");
    }

  });
}

// ============================================================
// KILL CHAIN
// ============================================================

function activateKillChain(count) {

  const stages = document.querySelectorAll(".kill-stage");

  stages.forEach((stage, index) => {

    stage.classList.remove("active");

    if (index < count) {
      stage.classList.add("active");
    }

  });
}

// ============================================================
// RISK LEVEL
// ============================================================

function getRiskLevel(score) {

  if (score >= 85) return "CRITICAL";
  if (score >= 65) return "HIGH";
  if (score >= 40) return "MEDIUM";
  if (score > 0) return "LOW";

  return "SAFE";
}

// ============================================================
// HTML ESCAPE
// ============================================================

function escapeHTML(value) {

  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ============================================================
// FORMAT TIME
// ============================================================

function formatTime(event) {

  if (event.time) {
    return event.time;
  }

  if (event.timestamp) {

    const date = new Date(event.timestamp);

    if (!isNaN(date.getTime())) {
      return date.toLocaleTimeString();
    }

  }

  return "--:--:--";
}

// ============================================================
// RENDER DASHBOARD
// ============================================================

function render(data) {

  const attempts = data.attempts || [];

  const count = attempts.length;

  const risk = Number(data.risk || 0);

  const correlation = Number(
    data.correlation || 0
  );

  // ==========================================================
  // BASIC STATS
  // ==========================================================

  if (attemptCount) {
    attemptCount.textContent = count;
  }

  if (riskScore) {
    riskScore.textContent = risk;
  }

  if (correlationScore) {
    correlationScore.textContent =
      correlation + "%";
  }

  // ==========================================================
  // RISK LABEL
  // ==========================================================

  const level = getRiskLevel(risk);

  if (riskLabel) {
    riskLabel.textContent = level;
  }

  if (scoreFill) {

    scoreFill.style.width =
      Math.min(risk, 100) + "%";

  }

  // ==========================================================
  // SYSTEM STATUS
  // ==========================================================

  if (systemStatus) {

    if (data.correlated) {

      systemStatus.textContent =
        "THREAT DETECTED";

    } else if (count > 0) {

      systemStatus.textContent =
        "MONITORING";

    } else {

      systemStatus.textContent =
        "SYSTEM READY";

    }

  }

  // ==========================================================
  // NO EVENTS
  // ==========================================================

  if (count === 0) {

    if (eventStream) {
      eventStream.innerHTML = `
        <div class="event empty">
          <div class="id">---</div>
          <div>
            <b>NO AUTHENTICATION EVENTS</b>
            <small>Monitoring system ready</small>
          </div>
          <div class="fail">READY</div>
        </div>
      `;
    }

    if (timeline) {
      timeline.innerHTML = `
        <div class="timeline-row">
          <div class="time">
            <b>--:--:--</b>
            <span>
              <strong>SYSTEM READY</strong><br>
              Waiting for authentication activity.
            </span>
          </div>
        </div>
      `;
    }

    if (sourceIP) {
      sourceIP.textContent = "---";
    }

    if (ipEvents) {
      ipEvents.textContent = "0";
    }

    if (uniqueUsers) {
      uniqueUsers.textContent = "0";
    }

    if (ipThreatStatus) {
      ipThreatStatus.textContent = "SAFE";
    }

    activatePipelineNodes(0);
    activateKillChain(0);

    if (threatAlert) {
      threatAlert.classList.add("hidden");
    }

    return;
  }

  // ==========================================================
  // LATEST EVENT
  // ==========================================================

  const latest =
    attempts[attempts.length - 1];

  if (sourceIP) {
    sourceIP.textContent =
      latest.ip || "UNKNOWN";
  }

  // ==========================================================
  // EVENT STREAM
  // ==========================================================

  if (eventStream) {

    eventStream.innerHTML =
      attempts
        .slice()
        .reverse()
        .map((event, index) => {

          const time =
            formatTime(event);

          return `
            <div class="event ${index === 0 ? "latest" : ""}">

              <div class="id">
                ${escapeHTML(event.id)}
              </div>

              <div>

                <b>
                  ${escapeHTML(event.username)}
                </b>

                <small>
                  ${escapeHTML(event.ip)}
                  ·
                  ${escapeHTML(time)}
                </small>

              </div>

              <div class="fail">
                ${escapeHTML(event.status || "FAILED")}
              </div>

            </div>
          `;

        })
        .join("");

  }

  // ==========================================================
  // IP ANALYSIS
  // ==========================================================

  const ipMap = {};
  const userSet = new Set();

  attempts.forEach(event => {

    const ip =
      event.ip || "UNKNOWN";

    ipMap[ip] =
      (ipMap[ip] || 0) + 1;

    if (event.username) {
      userSet.add(event.username);
    }

  });

  const latestIP =
    latest.ip || "UNKNOWN";

  const latestIPCount =
    ipMap[latestIP] || 0;

  if (ipEvents) {
    ipEvents.textContent =
      latestIPCount;
  }

  if (uniqueUsers) {
    uniqueUsers.textContent =
      userSet.size;
  }

  if (ipThreatStatus) {

    if (latestIPCount >= 5) {

      ipThreatStatus.textContent =
        "HIGH RISK";

    } else if (latestIPCount >= 3) {

      ipThreatStatus.textContent =
        "SUSPICIOUS";

    } else {

      ipThreatStatus.textContent =
        "MONITORING";

    }

  }

  // ==========================================================
  // TIMELINE
  // ==========================================================

  if (timeline) {

    timeline.innerHTML = `
      <div class="timeline-row">

        ${attempts.map(event => {

          const time =
            formatTime(event);

          return `
            <div class="time">

              <b>
                ${escapeHTML(time)}
              </b>

              <span>

                <strong>
                  ${escapeHTML(event.id)}
                </strong>

                <br>

                ${escapeHTML(
                  event.reason ||
                  "Authentication failure detected."
                )}

              </span>

            </div>
          `;

        }).join("")}

      </div>
    `;

  }

  // ==========================================================
  // DSA PIPELINE
  //
  // ARRAYLIST
  // HASHMAP
  // QUEUE
  // STACK
  // CORRELATION ENGINE
  // ==========================================================

  if (count >= 1) {

    activatePipelineNodes(1);

  }

  if (count >= 2) {

    activatePipelineNodes(2);

  }

  if (count >= 3) {

    activatePipelineNodes(3);

  }

  if (count >= 4) {

    activatePipelineNodes(4);

  }

  if (count >= 5) {

    activatePipelineNodes(5);

  }

  // ==========================================================
  // KILL CHAIN
  //
  // 1. Reconnaissance
  // 2. Initial Access
  // 3. Credential Access
  // 4. Privilege Escalation
  // 5. Command & Control
  // ==========================================================

  if (count >= 3) {
    activateKillChain(1);
  }

  if (count >= 2) {
    activateKillChain(2);
  }

  if (count >= 5) {
    activateKillChain(3);
  }

  if (count >= 6) {
    activateKillChain(4);
  }

  if (count >= 7) {
    activateKillChain(5);
  }

  // ==========================================================
  // THREAT ALERT
  // ==========================================================

  if (data.correlated) {

    if (threatAlert) {
      threatAlert.classList.remove("hidden");
    }

  } else {

    if (threatAlert) {
      threatAlert.classList.add("hidden");
    }

  }

}

// ============================================================
// LOGIN API
// ============================================================

async function apiLogin(user, pass) {

  const response =
    await fetch("/api/login", {

      method: "POST",

      headers: {
        "Content-Type": "application/json"
      },

      body: JSON.stringify({

        username: user,
        password: pass

      })

    });

  if (!response.ok) {

    throw new Error(
      "Server returned HTTP " +
      response.status
    );

  }

  return await response.json();

}

// ============================================================
// LOGIN FORM
// ============================================================

loginForm.addEventListener(
  "submit",
  async (e) => {

    e.preventDefault();

    const user =
      username.value.trim();

    const pass =
      password.value;

    // ========================================================
    // EMPTY INPUT
    // ========================================================

    if (!user || !pass) {

      loginMessage.textContent =
        "ENTER USERNAME AND PASSWORD";

      loginMessage.classList.remove(
        "success"
      );

      return;

    }

    // ========================================================
    // VERIFYING
    // ========================================================

    loginMessage.textContent =
      "VERIFYING CREDENTIALS...";

    loginMessage.classList.remove(
      "success"
    );

    try {

      const data =
        await apiLogin(
          user,
          pass
        );

      // ======================================================
      // CORRECT LOGIN
      // ONLY HERE DASHBOARD OPENS
      // ======================================================

      if (data.success === true) {

        loginMessage.textContent =
          "LOGIN SUCCESSFUL";

        loginMessage.classList.add(
          "success"
        );

        password.value = "";

        setTimeout(() => {

          loginScreen.classList.add(
            "hidden"
          );

          monitor.classList.remove(
            "hidden"
          );

          render(data);

        }, 300);

        return;

      }

      // ======================================================
      // WRONG LOGIN
      //
      // SERVER HAS ALREADY RECORDED THE EVENT.
      //
      // DO NOT OPEN DASHBOARD.
      // ======================================================

      loginMessage.textContent =
        "ACCESS DENIED — FAILED LOGIN RECORDED";

      loginMessage.classList.remove(
        "success"
      );

      password.value = "";

      // Keep login screen visible.
      // Dashboard remains locked.

    }

    catch (error) {

      console.error(
        "LOGIN ERROR:",
        error
      );

      loginMessage.textContent =
        "CANNOT REACH MONITORING SERVER";

      loginMessage.classList.remove(
        "success"
      );

    }

  }
);

// ============================================================
// RESET MONITORING
// ============================================================

resetBtn.addEventListener(
  "click",
  async () => {

    try {

      const response =
        await fetch(
          "/api/reset",
          {
            method: "POST"
          }
        );

      if (!response.ok) {
        throw new Error(
          "Reset failed"
        );
      }

      location.reload();

    }

    catch (error) {

      console.error(
        "RESET ERROR:",
        error
      );

    }

  }
);

// ============================================================
// LIVE STATUS POLLING
//
// Once dashboard is open, the server state is refreshed
// every second so events from other LAN laptops can appear.
// ============================================================

async function poll() {

  if (
    monitor.classList.contains(
      "hidden"
    )
  ) {

    return;

  }

  try {

    const response =
      await fetch(
        "/api/status"
      );

    if (!response.ok) {
      return;
    }

    const data =
      await response.json();

    render(data);

  }

  catch (error) {

    console.error(
      "STATUS ERROR:",
      error
    );

  }

}

// ============================================================
// START LIVE MONITORING
// ============================================================

setInterval(
  poll,
  1000
);