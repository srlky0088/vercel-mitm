const http = require("http");
const https = require("https");
const tls = require("tls");
const crypto = require("crypto");
const forge = require("node-forge");
const fs = require("fs");

const PORT = process.env.PORT || 3000;

const VERCEL_IP = "vercel.com";
const VERCEL_PORT = 443;
const VERCEL_HOST = "server-six-wheat-69.vercel.app";
const VERCEL_PATH = "/forward";

function healthCheck() {
  return new Promise((resolve) => {
    const req = https.request(
      {
        hostname: VERCEL_IP,
        port: VERCEL_PORT,
        path: VERCEL_PATH,
        method: "GET",
        headers: { Host: VERCEL_HOST },
        rejectUnauthorized: false,
        servername: VERCEL_HOST,
        timeout: 10000,
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode === 200));
      },
    );
    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
    req.end();
  });
}

let caKey, caCert;
if (fs.existsSync("ca.key") && fs.existsSync("ca.crt")) {
  caKey = forge.pki.privateKeyFromPem(fs.readFileSync("ca.key", "utf8"));
  caCert = forge.pki.certificateFromPem(fs.readFileSync("ca.crt", "utf8"));
} else {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(
    cert.validity.notBefore.getFullYear() + 10,
  );
  const attrs = [{ name: "commonName", value: "MyProxy CA" }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: "basicConstraints", cA: true, critical: true },
    { name: "keyUsage", keyCertSign: true, cRLSign: true },
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  caKey = keys.privateKey;
  caCert = cert;
  fs.writeFileSync("ca.key", forge.pki.privateKeyToPem(keys.privateKey));
  fs.writeFileSync("ca.crt", forge.pki.certificateToPem(cert));
  console.log("✅ CA generated! Install ca.crt then restart.");
  process.exit(0);
}

const certCache = new Map();
function getFakeCert(hostname) {
  if (certCache.has(hostname)) return certCache.get(hostname).pem;
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const pubKeyPem = publicKey.export({ type: "spki", format: "pem" });
  const privKeyPem = privateKey.export({ type: "pkcs8", format: "pem" });
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(pubKeyPem);
  cert.serialNumber =
    Date.now().toString(16) + crypto.randomBytes(4).toString("hex");
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 2);
  cert.setSubject([{ name: "commonName", value: hostname }]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions([
    { name: "basicConstraints", cA: false },
    {
      name: "subjectAltName",
      altNames: [
        { type: 2, value: hostname },
        { type: 2, value: `*.${hostname.split(".").slice(-2).join(".")}` },
      ],
    },
    { name: "keyUsage", digitalSignature: true, keyEncipherment: true },
    { name: "extKeyUsage", serverAuth: true },
  ]);
  cert.sign(caKey, forge.md.sha256.create());
  const pem = { key: privKeyPem, cert: forge.pki.certificateToPem(cert) };
  certCache.set(hostname, { pem, ts: Date.now() });
  return pem;
}

const vercelAgent = new https.Agent({
  rejectUnauthorized: false,
  servername: VERCEL_HOST,
  keepAlive: true,
  maxSockets: 50,
  maxFreeSockets: 256,
  keepAliveMsecs: 30000,
  timeout: 15000,
  scheduling: "lifo",
});

function sendToVercel(
  method,
  targetProtocol,
  targetHost,
  targetPath,
  headers,
  bodyStream,
) {
  return new Promise((resolve, reject) => {
    const proxyHeaders = { ...headers };
    let realCL =
      proxyHeaders["content-length"] || proxyHeaders["Content-Length"];
    for (const key of [
      "connection",
      "proxy-connection",
      "keep-alive",
      "transfer-encoding",
      "content-length",
      "Content-Length",
    ])
      delete proxyHeaders[key];
    proxyHeaders["Host"] = VERCEL_HOST;
    proxyHeaders["x-proxy-method"] = method;
    proxyHeaders["x-proxy-protocol"] = targetProtocol;
    proxyHeaders["x-proxy-host"] = targetHost;
    proxyHeaders["x-proxy-path"] = targetPath;
    if (realCL) proxyHeaders["x-real-content-length"] = realCL;

    const options = {
      hostname: VERCEL_IP,
      port: VERCEL_PORT,
      path: VERCEL_PATH,
      method: "POST",
      headers: proxyHeaders,
      agent: vercelAgent,
      rejectUnauthorized: false,
      servername: VERCEL_HOST,
    };
    const proxyReq = https.request(options, (proxyRes) => {
      if (proxyRes.statusCode >= 400) {
        let err = "";
        proxyRes.on("data", (c) => (err += c));
        proxyRes.on("end", () =>
          reject(new Error(`Vercel responded ${proxyRes.statusCode}: ${err}`)),
        );
      } else resolve(proxyRes);
    });
    proxyReq.on("error", reject);
    proxyReq.setTimeout(30000, () =>
      proxyReq.destroy(new Error("Vercel Timeout (30s)")),
    );
    if (bodyStream) bodyStream.pipe(proxyReq, { end: true });
    else proxyReq.end();
  });
}

const CHUNK_SIZE = 4 * 1024 * 1024;
const LARGE_FILE_EXTENSIONS = [
  ".zip",
  ".rar",
  ".7z",
  ".exe",
  ".msi",
  ".mp4",
  ".mkv",
  ".avi",
  ".mov",
  ".iso",
  ".gz",
  ".tar",
];

async function forwardRequest(
  method,
  protocol,
  host,
  reqPath,
  headers,
  bodyStream,
  clientRes,
) {
  const hasRange = headers["Range"] || headers["range"];
  const isLargeFile = LARGE_FILE_EXTENSIONS.some((ext) =>
    reqPath.toLowerCase().endsWith(ext),
  );

  if (method === "GET" && !hasRange && isLargeFile) {
    try {
      const headRes = await sendToVercel(
        "HEAD",
        protocol,
        host,
        reqPath,
        headers,
        null,
      );
      const contentLength = parseInt(
        headRes.headers["content-length"] || "0",
        10,
      );
      const acceptRanges = headRes.headers["accept-ranges"];
      if (acceptRanges === "bytes" && contentLength > CHUNK_SIZE) {
        console.log(`📦 [CHUNKING] ${contentLength} bytes -> ${reqPath}`);
        clientRes.writeHead(200, {
          "Content-Length": contentLength,
          "Content-Type":
            headRes.headers["content-type"] || "application/octet-stream",
          "Accept-Ranges": "bytes",
        });
        let offset = 0;
        while (offset < contentLength) {
          const end = Math.min(offset + CHUNK_SIZE - 1, contentLength - 1);
          const rangeHeader = { ...headers, Range: `bytes=${offset}-${end}` };
          const chunkRes = await sendToVercel(
            "GET",
            protocol,
            host,
            reqPath,
            rangeHeader,
            null,
          );
          await new Promise((resolve, reject) => {
            chunkRes.pipe(clientRes, { end: false });
            chunkRes.on("end", resolve);
            chunkRes.on("error", reject);
          });
          offset = end + 1;
        }
        clientRes.end();
        return;
      }
    } catch (e) {}
  }

  try {
    const proxyRes = await sendToVercel(
      method,
      protocol,
      host,
      reqPath,
      headers,
      bodyStream,
    );
    clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(clientRes, { end: true, highWaterMark: 1024 * 1024 });
  } catch (err) {
    if (!clientRes.headersSent) {
      clientRes.writeHead(502, { "Content-Type": "text/plain" });
      clientRes.end(`Proxy Error\n${err.message}`);
    } else clientRes.destroy();
  }
}

const tlsServer = new tls.Server({
  requestCert: false,
  rejectUnauthorized: false,
  SNICallback: (hostname, cb) => {
    try {
      const fakeCert = getFakeCert(hostname);
      cb(
        null,
        tls.createSecureContext({ key: fakeCert.key, cert: fakeCert.cert }),
      );
    } catch (err) {
      cb(err);
    }
  },
});

const innerHttpServer = new http.Server();
innerHttpServer.on("request", (req, res) => {
  req.setTimeout(120000);
  res.setTimeout(120000);
  const hostname = req.socket.servername || req.headers.host?.split(":")[0];
  if (!hostname) {
    res.writeHead(400);
    return res.end();
  }
  forwardRequest(req.method, "https", hostname, req.url, req.headers, req, res);
});

tlsServer.on("secureConnection", (tlsSocket) => {
  tlsSocket.on("error", () => {});
  innerHttpServer.emit("connection", tlsSocket);
});

const server = http.createServer((req, res) => {
  if (!req.url.startsWith("http")) {
    res.writeHead(400);
    return res.end("Absolute URL required");
  }
  try {
    const targetUrl = new URL(req.url);
    forwardRequest(
      req.method,
      targetUrl.protocol.slice(0, -1),
      targetUrl.host,
      targetUrl.pathname + targetUrl.search,
      req.headers,
      req,
      res,
    );
  } catch {
    res.writeHead(400);
    res.end("Invalid URL");
  }
});

server.on("connect", (req, clientSocket, head) => {
  const [hostname, port] = [
    req.url.split(":")[0],
    parseInt(req.url.split(":")[1]) || 443,
  ];
  clientSocket.on("error", () => {});
  clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n", (err) => {
    if (err) {
      clientSocket.destroy();
      return;
    }
    if (head?.length > 0) clientSocket.unshift(head);
    tlsServer.emit("connection", clientSocket);
  });
});

process.on("uncaughtException", (err) =>
  console.error("💥 Uncaught:", err.message),
);
process.on("unhandledRejection", (err) => console.error("💥 Unhandled:", err));

(async () => {
  console.log("🚀 Starting Vercel MITM proxy...");
  if (await healthCheck()) console.log("✅ Vercel Proxy OK");
  else console.warn("⚠️ Vercel Proxy Unreachable");
  server.listen(PORT, "0.0.0.0", () =>
    console.log(`✅ MITM HTTP Proxy running on port ${PORT}`),
  );
})();
