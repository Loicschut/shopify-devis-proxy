// server.js (CommonJS, Node 18+)

const express = require("express");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

/* -------------------- Vérification App Proxy -------------------- */

function safeEqual(a, b) {
  try {
    return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
  } catch {
    return false;
  }
}
function hmacBase64(secret, raw) {
  return crypto.createHmac("sha256", secret).update(raw, "utf8").digest("base64");
}
function hmacHex(secret, raw) {
  return crypto.createHmac("sha256", secret).update(raw, "utf8").digest("hex");
}

function verifyProxy(req) {
  const secret = process.env.APP_PROXY_SHARED_SECRET || "";
  if (!secret) return false;

  const headerSig =
    req.headers["x-shopify-proxy-signature"] || req.headers["x-shopify-hmac-sha256"];

  const { signature: legacySig, ...rest } = req.query || {};

  if (headerSig) {
    const raw1 = req.originalUrl; // "/devis?..."
    const sig1 = hmacBase64(secret, raw1);
    if (safeEqual(headerSig, sig1)) return true;

    const raw2 = `/apps${raw1.startsWith("/") ? "" : "/"}${raw1}`; // "/apps/devis?..."
    const sig2 = hmacBase64(secret, raw2);
    if (safeEqual(headerSig, sig2)) return true;
  }

  if (legacySig) {
    const sorted = Object.keys(rest)
      .sort()
      .map((k) => `${k}=${rest[k]}`)
      .join("");
    const hex = hmacHex(secret, sorted);
    if (safeEqual(legacySig, hex)) return true;
  }

  return false;
}

/* --------------------------- Helpers Admin API --------------------------- */

async function adminGraphQL(query, variables = {}) {
  const shop = process.env.SHOP_DOMAIN;
  const version = process.env.ADMIN_API_VERSION;
  const token = process.env.ADMIN_ACCESS_TOKEN;
  if (!shop || !version || !token) {
    throw new Error("Missing env: SHOP_DOMAIN, ADMIN_API_VERSION, or ADMIN_ACCESS_TOKEN");
  }

  const url = `https://${shop}/admin/api/${version}/graphql.json`;

  const resp = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": token,
    },
    body: JSON.stringify({ query, variables }),
  });

  if (!resp.ok) {
    const txt = await resp.text().catch(() => "");
    throw new Error(`[AdminAPI] HTTP ${resp.status}: ${txt}`);
  }

  const json = await resp.json();
  if (json.errors) {
    throw new Error(`[AdminAPI] GraphQL errors: ${JSON.stringify(json.errors)}`);
  }
  return json.data;
}

function gidToLegacyId(gid) {
  if (!gid) return null;
  const s = String(gid);
  if (s.startsWith("gid://")) {
    const last = s.split("/").pop();
    if (/^\d+$/.test(last)) return last;
  }
  if (/^\d+$/.test(s)) return s;
  return null;
}

function mapDraftOrderNode(node, includeItems = false) {
  return {
    id: node.id,
    legacyResourceId: node.legacyResourceId,
    name: node.name,
    createdAt: node.createdAt,
    status: node.status,
    invoiceUrl: node.invoiceUrl,
    total: node.totalPriceSet?.presentmentMoney
      ? `${node.totalPriceSet.presentmentMoney.amount} ${node.totalPriceSet.presentmentMoney.currencyCode}`
      : null,
    ...(includeItems && node.lineItems
      ? {
          lineItems: (node.lineItems.edges || []).map(({ node: li }) => ({
            title: li.title,
            quantity: li.quantity,
            variantTitle: li.variantTitle || "",
          })),
        }
      : {}),
  };
}

/* ------------------------------ Endpoints ------------------------------- */

// GET /devis?customer_id=<gid|id>&after=<cursor>&include=items
app.get("/devis", async (req, res) => {
  try {
    if (!verifyProxy(req)) return res.status(401).json({ error: "invalid_signature" });

    const customerParam = req.query.customer_id;
    if (!customerParam) return res.status(400).json({ error: "missing customer_id" });

    const customerLegacyId = gidToLegacyId(customerParam);
    if (!customerLegacyId) return res.status(400).json({ error: "bad customer_id" });

    const after = req.query.after || null;
    const includeItems = String(req.query.include || "").toLowerCase() === "items";

    const lineItemsFrag = includeItems
      ? `
        lineItems(first: 50) {
          edges { node { title quantity variantTitle } }
        }`
      : ``;

    const query = `
      query ListDraftOrders($first:Int!, $after:String, $q:String!) {
        draftOrders(first: $first, after: $after, query: $q) {
          pageInfo { hasNextPage hasPreviousPage startCursor endCursor }
          edges {
            cursor
            node {
              id
              legacyResourceId
              name
              createdAt
              status
              invoiceUrl
              totalPriceSet { presentmentMoney { amount currencyCode } }
              customer { id }
              ${lineItemsFrag}
            }
          }
        }
      }
    `;

    const variables = { first: 10, after, q: `customer_id:${customerLegacyId}` };
    const data = await adminGraphQL(query, variables);

    const edges = data?.draftOrders?.edges || [];
    const pageInfo = data?.draftOrders?.pageInfo || {};
    const quotes = edges.map(({ node }) => mapDraftOrderNode(node, includeItems));

    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
    res.setHeader("Pragma", "no-cache");
    return res.json({ quotes, pageInfo });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server_error" });
  }
});

// GET /devis/:id?include=items  (id = legacy numérique OU GID)
app.get("/devis/:id", async (req, res) => {
  try {
    if (!verifyProxy(req)) return res.status(401).json({ error: "invalid_signature" });

    const rawId = req.params.id;
    const includeItems = String(req.query.include || "").toLowerCase() === "items";

    const legacy = gidToLegacyId(rawId);
    const gid = legacy && !String(rawId).startsWith("gid://")
      ? `gid://shopify/DraftOrder/${legacy}`
      : rawId;

    const lineItemsFrag = includeItems
      ? `
        lineItems(first: 50) { edges { node { title quantity variantTitle } } }
      `
      : ``;

    const query = `
      query OneDraftOrder($id: ID!) {
        draftOrder(id: $id) {
          id
          legacyResourceId
          name
          createdAt
          status
          invoiceUrl
          totalPriceSet { presentmentMoney { amount currencyCode } }
          ${lineItemsFrag}
        }
      }
    `;

    const data = await adminGraphQL(query, { id: gid });
    const n = data?.draftOrder;
    if (!n) return res.status(404).json({ error: "not_found" });

    const quote = mapDraftOrderNode(n, includeItems);

    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
    res.setHeader("Pragma", "no-cache");
    return res.json({ quote });
  } catch (e) {
    if (String(e.message).includes("HTTP 404")) return res.status(404).json({ error: "not_found" });
    console.error(e);
    return res.status(500).json({ error: "server_error" });
  }
});

// Root
app.get("/", (_req, res) => {
  res
    .type("text/plain")
    .send("Shopify Draft Orders App Proxy is running. Use /devis");
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Proxy running on port ${PORT}`);
});
