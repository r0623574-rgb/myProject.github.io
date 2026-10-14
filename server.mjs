import crypto from "node:crypto";
import { spawn } from "node:child_process";
import http from "node:http";
import { URL } from "node:url";

const port = 8787;
const appUrl = "http://localhost:5173";
const callbackUrl =
  process.env.GITHUB_CALLBACK_URL || "http://localhost:8787/api/auth/callback";
const pendingStates = new Set();
const sessions = new Map();

function sendJson(response, status, data, extraHeaders = {}) {
  response.writeHead(status, {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": appUrl,
    "Access-Control-Allow-Credentials": "true",
    ...extraHeaders,
  });
  response.end(JSON.stringify(data));
}

function getCookies(request) {
  return Object.fromEntries(
    (request.headers.cookie || "")
      .split(";")
      .filter(Boolean)
      .map((item) => item.trim().split("=")),
  );
}

async function readBody(request) {
  const chunks = [];

  for await (const chunk of request) {
    chunks.push(chunk);
  }

  return JSON.parse(Buffer.concat(chunks).toString() || "{}");
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host}`);

  if (request.method === "OPTIONS") {
    response.writeHead(204, {
      "Access-Control-Allow-Origin": appUrl,
      "Access-Control-Allow-Credentials": "true",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    });
    response.end();
    return;
  }

  if (url.pathname === "/api/auth/github") {
    if (!process.env.GITHUB_CLIENT_ID || !process.env.GITHUB_CLIENT_SECRET) {
      sendJson(response, 500, {
        error: "GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET are required",
      });
      return;
    }

    const state = crypto.randomBytes(24).toString("hex");
    pendingStates.add(state);

    const githubUrl = new URL("https://github.com/login/oauth/authorize");
    githubUrl.searchParams.set("client_id", process.env.GITHUB_CLIENT_ID);
    githubUrl.searchParams.set("redirect_uri", callbackUrl);
    githubUrl.searchParams.set("scope", "read:user user:email");
    githubUrl.searchParams.set("state", state);

    response.writeHead(302, { Location: githubUrl.toString() });
    response.end();
    return;
  }

  if (url.pathname === "/api/auth/callback") {
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");

    if (!code || !state || !pendingStates.has(state)) {
      response.writeHead(400);
      response.end("Invalid GitHub OAuth response");
      return;
    }

    pendingStates.delete(state);

    const tokenResponse = await fetch(
      "https://github.com/login/oauth/access_token",
      {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          client_id: process.env.GITHUB_CLIENT_ID,
          client_secret: process.env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: callbackUrl,
        }),
      },
    );
    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok || !tokenData.access_token) {
      response.writeHead(502);
      response.end("GitHub token exchange failed");
      return;
    }

    const profileResponse = await fetch("https://api.github.com/user", {
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${tokenData.access_token}`,
        "User-Agent": "personal-finance-tracker",
      },
    });
    const profile = await profileResponse.json();

    if (!profileResponse.ok || !profile.id) {
      response.writeHead(502);
      response.end("GitHub profile request failed");
      return;
    }

    let email = profile.email;

    if (!email) {
      const emailsResponse = await fetch("https://api.github.com/user/emails", {
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${tokenData.access_token}`,
          "User-Agent": "personal-finance-tracker",
        },
      });
      const emails = await emailsResponse.json();
      email = emails.find((item) => item.primary)?.email || emails[0]?.email;
    }

    if (!email) {
      response.writeHead(400);
      response.end("GitHub account does not provide an email");
      return;
    }

    const sessionId = crypto.randomBytes(32).toString("hex");
    sessions.set(sessionId, {
      providerUserId: String(profile.id),
      name: profile.name || profile.login,
      email,
      avatar: profile.avatar_url,
    });

    response.writeHead(302, {
      Location: `${appUrl}/login?github=success`,
      "Set-Cookie": `finance_session=${sessionId}; HttpOnly; SameSite=Lax; Path=/`,
    });
    response.end();
    return;
  }

  if (url.pathname === "/api/auth/session") {
    const session = sessions.get(getCookies(request).finance_session);

    if (!session) {
      sendJson(response, 401, { error: "Not authenticated" });
      return;
    }

    sendJson(response, 200, session);
    return;
  }

  if (url.pathname === "/api/auth/logout" && request.method === "POST") {
    const sessionId = getCookies(request).finance_session;
    sessions.delete(sessionId);
    sendJson(
      response,
      200,
      { ok: true },
      {
        "Set-Cookie":
          "finance_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
      },
    );
    return;
  }

  response.writeHead(404);
  response.end("Not found");
});

server.listen(port, () => {
  const vite = spawn("npx.cmd", ["vite", "--host", "localhost"], {
    stdio: "inherit",
    shell: true,
  });

  vite.on("exit", (code) => {
    server.close();
    process.exit(code || 0);
  });
});
