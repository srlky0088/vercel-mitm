const http = require("http");
const https = require("https");

const httpsAgent = new https.Agent({
  keepAlive: true,
  maxSockets: 50,
  timeout: 15000,
});

const httpAgent = new http.Agent({
  keepAlive: true,
  maxSockets: 50,
  timeout: 15000,
});

const IGNORE_REQ_HEADERS = new Set([
  "host",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
  "proxy-authorization",
  "proxy-authenticate",
  "proxy-connection",
  "x-proxy-method",
  "x-proxy-protocol",
  "x-proxy-host",
  "x-proxy-path",
  "x-proxy-port",
  "x-real-content-length",
]);

const IGNORE_RES_HEADERS = new Set([
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
]);

function cleanReqHeaders(headers) {
  const result = {};
  for (const key in headers) {
    if (!IGNORE_REQ_HEADERS.has(key.toLowerCase())) {
      result[key] = headers[key];
    }
  }
  return result;
}

function cleanResHeaders(headers) {
  const result = {};
  for (const key in headers) {
    if (!IGNORE_RES_HEADERS.has(key.toLowerCase())) {
      result[key] = headers[key];
    }
  }
  return result;
}

const app = http.createServer((req, res) => {
  // ===== Health Check =====
  if (req.method === "GET" && req.url === "/forward") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(
      JSON.stringify({
        status: "ok",
        uptime: process.uptime(),
        mem: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
      }),
    );
  }

  // ===== Forward Request =====
  if (req.method === "POST" && req.url === "/forward") {
    const method = req.headers["x-proxy-method"];
    const protocol = req.headers["x-proxy-protocol"];
    const host = req.headers["x-proxy-host"];
    const path = req.headers["x-proxy-path"] || "/";
    const port = req.headers["x-proxy-port"];

    if (!method || !protocol || !host) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      return res.end("Missing x-proxy-* headers");
    }

    if (protocol !== "http" && protocol !== "https") {
      res.writeHead(400, { "Content-Type": "text/plain" });
      return res.end("Invalid protocol");
    }

    const isHttps = protocol === "https";
    const targetPort = port || (isHttps ? 443 : 80);

    const targetHeaders = cleanReqHeaders(req.headers);

    if (req.headers["x-real-content-length"]) {
      targetHeaders["content-length"] = req.headers["x-real-content-length"];
    }
    targetHeaders.host = host;

    const options = {
      hostname: host,
      port: targetPort,
      path: path,
      method: method,
      headers: targetHeaders,
      rejectUnauthorized: false,
      agent: isHttps ? httpsAgent : httpAgent,
    };

    let destroyed = false;

    try {
      const proxyReq = (isHttps ? https : http).request(options, (proxyRes) => {
        if (destroyed) return;

        const resHeaders = cleanResHeaders(proxyRes.headers);
        res.writeHead(proxyRes.statusCode, resHeaders);

        proxyRes.pipe(res, { end: true });

        proxyRes.on("error", () => {
          if (!destroyed) {
            destroyed = true;
            proxyReq.destroy();
          }
        });
      });

      proxyReq.on("error", (err) => {
        if (destroyed) return;
        destroyed = true;
        if (!res.headersSent) {
          res.writeHead(502, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              error: "Bad Gateway",
              target: `${protocol}://${host}${path}`,
              reason: err.message,
            }),
          );
        } else {
          res.destroy();
        }
      });

      proxyReq.setTimeout(15000);
      proxyReq.on("timeout", () => {
        if (!destroyed) {
          destroyed = true;
          proxyReq.destroy(new Error("Target timeout"));
        }
      });

      req.pipe(proxyReq, { end: true });

      req.on("error", () => {
        if (!destroyed) {
          destroyed = true;
          proxyReq.destroy();
        }
      });

      res.on("close", () => {
        if (!destroyed) {
          destroyed = true;
          proxyReq.destroy();
        }
      });
    } catch (err) {
      if (!res.headersSent) {
        res.writeHead(500);
        res.end("Internal Server Error");
      }
    }
    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not Found");
});

module.exports = app;
