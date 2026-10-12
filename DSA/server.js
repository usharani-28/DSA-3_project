// ============================================================
// THREAT INTELLIGENCE KILL-CHAIN CORRELATION ENGINE
// LAN DEMO SERVER
// ============================================================

const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");

const PORT = 3000;

// ============================================================
// VALID DEMO USERS
// ============================================================

const validUsers = {
  "2520090157": "samyu@123",
  "2520090049": "usha@123"
};

// ============================================================
// CENTRAL STATE
// All laptops connected to this server share this state
// ============================================================

let state = {
  attempts: [],
  nextEvent: 1,
  risk: 0,
  correlated: false
};

// ============================================================
// GET THIS LAPTOP'S LAN IP
// ============================================================

function getLocalIPv4() {
  const interfaces = os.networkInterfaces();

  for (const name of Object.keys(interfaces)) {
    for (const net of interfaces[name]) {
      if (
        net.family === "IPv4" &&
        !net.internal
      ) {
        return net.address;
      }
    }
  }

  return "localhost";
}

// ============================================================
// GET CLIENT IP
// ============================================================

function clientIP(req) {
  let ip =
    req.headers["x-forwarded-for"] ||
    req.socket.remoteAddress ||
    "unknown";

  if (Array.isArray(ip)) {
    ip = ip[0];
  }

  ip = String(ip).split(",")[0].trim();

  // Convert IPv4-mapped IPv6 address
  if (ip.startsWith("::ffff:")) {
    ip = ip.substring(7);
  }

  return ip;
}

// ============================================================
// SEND JSON RESPONSE
// ============================================================

function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*"
  });

  res.end(JSON.stringify(data));
}

// ============================================================
// CALCULATE CORRELATION
// ============================================================

function correlation() {
  const count = state.attempts.length;

  if (count === 0) return 0;

  return Math.min(99, 35 + count * 11);
}

// ============================================================
// CALCULATE RISK SCORE
// ============================================================

function calculateRisk(count) {

  if (count <= 0) return 0;
  if (count === 1) return 18;
  if (count === 2) return 28;
  if (count === 3) return 42;
  if (count === 4) return 58;
  if (count === 5) return 76;

  return Math.min(96, 76 + (count - 5) * 4);
}

// ============================================================
// LOGIN API
// ============================================================

function handleLogin(req, res) {

  let body = "";

  req.on("data", chunk => {
    body += chunk.toString();
  });

  req.on("end", () => {

    try {

      const data = JSON.parse(body || "{}");

      const username = String(
        data.username || "unknown"
      ).slice(0, 80);

      const password = String(
        data.password || ""
      );

      const ip = clientIP(req);

      const now = new Date();

      // ======================================================
      // CHECK REAL DEMO LOGIN
      // ======================================================

      const isValidLogin =
        validUsers[username] === password;

      // ======================================================
      // CORRECT PASSWORD
      // Do NOT create a threat event
      // ======================================================

      if (isValidLogin) {

        return sendJSON(res, 200, {

          ok: true,

          success: true,

          message: "LOGIN SUCCESSFUL",

          username: username,

          ip: ip,

          timestamp: now.toISOString(),

          attempts: state.attempts,

          risk: state.risk,

          correlation: correlation(),

          correlated: state.correlated

        });
      }

      // ======================================================
      // WRONG PASSWORD
      // Create security event
      // ======================================================

      const event = {

        id:
          "EV" +
          String(state.nextEvent).padStart(3, "0"),

        username: username,

        ip: ip,

        timestamp: now.toISOString(),

        status: "FAILED",

        riskScore: 0,

        passwordLength: password.length

      };

      state.nextEvent++;

      state.attempts.push(event);

      // ======================================================
      // UPDATE RISK
      // ======================================================

      state.risk =
        calculateRisk(state.attempts.length);

      event.riskScore = state.risk;

      // ======================================================
      // CORRELATION AFTER 5 OR MORE FAILURES
      // ======================================================

      state.correlated =
        state.attempts.length >= 5;

      // ======================================================
      // RESPONSE
      // ======================================================

      return sendJSON(res, 200, {

        ok: true,

        success: false,

        message: "INVALID CREDENTIALS",

        event: event,

        attempts: state.attempts,

        risk: state.risk,

        correlation: correlation(),

        correlated: state.correlated,

        serverIP: getLocalIPv4()

      });

    } catch (error) {

      return sendJSON(res, 400, {

        ok: false,

        message: "Invalid request"

      });

    }

  });
}

// ============================================================
// RESET API
// ============================================================

function handleReset(req, res) {

  state = {

    attempts: [],

    nextEvent: 1,

    risk: 0,

    correlated: false

  };

  sendJSON(res, 200, {

    ok: true,

    message: "Threat monitoring reset"

  });
}

// ============================================================
// STATUS API
// Used for LIVE updates from other laptops
// ============================================================

function handleStatus(req, res) {

  sendJSON(res, 200, {

    ok: true,

    attempts: state.attempts,

    risk: state.risk,

    correlation: correlation(),

    correlated: state.correlated,

    serverIP: getLocalIPv4()

  });
}

// ============================================================
// SERVE STATIC FILES
// ============================================================

function serveStatic(req, res) {

  let requestedPath =
    req.url.split("?")[0];

  if (requestedPath === "/") {
    requestedPath = "/index.html";
  }

  // Prevent path traversal
  requestedPath =
    path.normalize(requestedPath)
      .replace(/^(\.\.[\/\\])+/, "");

  const filePath =
    path.join(__dirname, requestedPath);

  fs.readFile(filePath, (err, data) => {

    if (err) {

      res.writeHead(404, {
        "Content-Type": "text/plain"
      });

      res.end("404 - File Not Found");

      return;
    }

    const ext =
      path.extname(filePath).toLowerCase();

    const contentTypes = {

      ".html": "text/html",

      ".css": "text/css",

      ".js": "application/javascript",

      ".json": "application/json",

      ".png": "image/png",

      ".jpg": "image/jpeg",

      ".jpeg": "image/jpeg",

      ".svg": "image/svg+xml",

      ".ico": "image/x-icon"

    };

    res.writeHead(200, {

      "Content-Type":
        contentTypes[ext] ||
        "application/octet-stream"

    });

    res.end(data);

  });
}

// ============================================================
// MAIN SERVER
// ============================================================

const server = http.createServer((req, res) => {

  // ==========================================================
  // CORS
  // ==========================================================

  if (req.method === "OPTIONS") {

    res.writeHead(204, {

      "Access-Control-Allow-Origin": "*",

      "Access-Control-Allow-Methods":
        "GET, POST, OPTIONS",

      "Access-Control-Allow-Headers":
        "Content-Type"

    });

    res.end();

    return;
  }

  // ==========================================================
  // LOGIN
  // ==========================================================

  if (
    req.url === "/api/login" &&
    req.method === "POST"
  ) {

    handleLogin(req, res);

    return;
  }

  // ==========================================================
  // RESET
  // ==========================================================

  if (
    req.url === "/api/reset" &&
    req.method === "POST"
  ) {

    handleReset(req, res);

    return;
  }

  // ==========================================================
  // LIVE STATUS
  // ==========================================================

  if (
    req.url === "/api/status" &&
    req.method === "GET"
  ) {

    handleStatus(req, res);

    return;
  }

  // ==========================================================
  // STATIC FILES
  // ==========================================================

  serveStatic(req, res);

});

// ============================================================
// LISTEN ON ALL NETWORK INTERFACES
// ============================================================

server.listen(
  PORT,
  "0.0.0.0",
  () => {

    const localIP =
      getLocalIPv4();

    console.log("");
    console.log(
      "=============================================="
    );

    console.log(
      " THREAT INTELLIGENCE KILL-CHAIN ENGINE"
    );

    console.log(
      "=============================================="
    );

    console.log("");

    console.log(
      "Local:"
    );

    console.log(
      `http://localhost:${PORT}`
    );

    console.log("");

    console.log(
      "Network:"
    );

    console.log(
      `http://${localIP}:${PORT}`
    );

    console.log("");

    console.log(
      "Use the Network address on another laptop"
    );

    console.log(
      "connected to the same Wi-Fi/LAN."
    );

    console.log("");

    console.log(
      "Valid Demo Users:"
    );

    console.log(
      "2520090157  ->  samyu@123"
    );

    console.log(
      "2520090049  ->  usha@123"
    );

    console.log("");

    console.log(
      "=============================================="
    );

    console.log("");

  }
);