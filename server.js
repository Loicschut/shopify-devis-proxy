import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import "dotenv/config";

const app = express();
const PORT = process.env.PORT || 3000;

/* -------------------- Vérification App Proxy robuste -------------------- */

function safeEqual(a, b) {
  try {
    return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
  } catch { return false; }
}
function hmacBase64(secret, raw) {
  return crypto.createHmac("sha256", secret).update(raw, "utf8").digest("base64");
}
function hmacHex(secret, raw) {
  return crypto.createHmac("sha256", secret).update(raw, "utf8").digest("hex");
}

/** Vérifie la signature de l’App Proxy.
 * - Shopify envoie généralement x-shopify-proxy-signature (base64) ou x-shopify-hmac-sha256.
 * - On hash l’URL brute (req.originalUrl) pour respecter l’ordre des paramètres.
 * - On gère aussi l’ancien ?signature= en hex.
 */
function verifyProxy(req) {
  const secret = process.env.APP_PROXY_SHARED_SECRET || "";
  if (!secret) return false;

  const headerSig =
    req.headers["x-shopify-proxy-signature"] ||
    req.headers["x-shopify-hmac-sha256"];

  const { signature: legacySig, ...rest } = req.query || {};

  if (headerSig) {
    const raw1 = req.originalUrl;                           // "/devis?customer_id=...&after=..."
    const sig1 = hmacBase64(secret, raw1);
    if (safeEqual(headerSig, sig1)) return true;

    const raw2 = `/apps${raw1.startsWith("/") ? "" : "/"}${raw1}`; // "/apps/devis?..."
    const sig2 = hmacBase64(secret, raw2);
    if (safeEqual(headerSig, sig2)) return true;
  }

  if (legacySig) {
    const sorted = Object.keys(rest).sort().map(k => `${k}=${rest[k]}`).join("");
    const hex = hmacHex(secret, sorted);
    if (safeEqual(legacySig, hex)) return true;
  }

  return false;
}

/* --------------------------- Endpoint App Proxy -------------------------- */

app.get("/devis", async (req, res) => {
  try {
    if (!verifyProxy(req)) {
      return res.status(401).json({ error: "invalid_signature" });
    }

    const customerGid = req.query.customer_id;
    const after = req.query.after || null;
    if (!customerGid) {
      return res.status(400).json({ error: "missing customer_id" });
    }

    const numericId = customerGid.split("/").pop(); // ID numérique

    const query = `#graphql
  query ListDraftOrders($after: String, $q: String!) {
    draftOrders(first: 10, after: $after, query: $q) {
      pageInfo { hasNextPage hasPreviousPage startCursor endCursor }
      edges {
        node {
          id
          name
          createdAt
          status
          invoiceUrl
          totalPriceSet { presentmentMoney { amount currencyCode } }
          customer { id }
        }
      }
    }
  }
`;


const variables = { after, q: `customer_id:${numericId}` };

    const resp = await fetch(
      `https://${process.env.SHOP_DOMAIN}/admin/api/${process.env.ADMIN_API_VERSION}/graphql.json`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Shopify-Access-Token": process.env.ADMIN_ACCESS_TOKEN || ""
        },
        body: JSON.stringify({ query, variables })
      }
    );

    if (!resp.ok) {
   const txt = await resp.text();
   console.error("[AdminAPI] HTTP", resp.status, txt);
   return res.status(resp.status).json({ error: "admin_api_error" });
 }

    const json = await resp.json();
    if (json.errors) {
   console.error("[AdminAPI] GraphQL errors:", JSON.stringify(json.errors));
   return res.status(500).json({ error: "graphql_errors" });
 }

    const edges = json?.data?.draftOrders?.edges || [];
    const pageInfo = json?.data?.draftOrders?.pageInfo || {};
    const quotes = edges.map(({ node }) => ({
      id: node.id,
      name: node.name,
      createdAt: node.createdAt,
      status: node.status,
      invoiceUrl: node.invoiceUrl,
      total: node.totalPriceSet?.presentmentMoney
        ? `${node.totalPriceSet.presentmentMoney.amount} ${node.totalPriceSet.presentmentMoney.currencyCode}`
        : null
    }));

    return res.json({ quotes, pageInfo });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server_error" });
  }
});

app.get("/", (_req, res) => {
  res.type("text/plain").send("Shopify Draft Orders App Proxy is running. /devis is the proxy endpoint.");
});

app.listen(PORT, () => {
  console.log(`Proxy running on port ${PORT}`);
});
