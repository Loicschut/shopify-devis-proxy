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

/** Vérifie la signature de l’App Proxy. */
function verifyProxy(req) {
  const secret = process.env.APP_PROXY_SHARED_SECRET || "";
  if (!secret) return false;

  const headerSig =
    req.headers["x-shopify-proxy-signature"] ||
    req.headers["x-shopify-hmac-sha256"];

  const { signature: legacySig, ...rest } = req.query || {};

  if (headerSig) {
    const raw1 = req.originalUrl; // "/devis?customer_id=...&after=..."
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

/* --------------------------- Helpers GraphQL ---------------------------- */

async function adminGraphQL(query, variables = {}) {
  const url = `https://${process.env.SHOP_DOMAIN}/admin/api/${process.env.ADMIN_API_VERSION}/graphql.json`;
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": process.env.ADMIN_ACCESS_TOKEN || ""
    },
    body: JSON.stringify({ query, variables })
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

/** Convertit un GID "gid://shopify/DraftOrder/123" en "123" */
function gidToLegacyId(gid) {
  if (!gid) return null;
  if (String(gid).startsWith("gid://")) {
    const last = String(gid).split("/").pop();
    if (/^\d+$/.test(last)) return last;
  }
  if (/^\d+$/.test(String(gid))) return String(gid);
  return null;
}

/** Normalise un DraftOrder GraphQL -> objet simple pour le front */
function mapDraftOrderNode(node, includeItems = false) {
  return {
    id: node.id, // GID
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
            variantTitle: li.variantTitle || ""
          }))
        }
      : {})
  };
}

/* --------------------------- Endpoint LISTE ----------------------------- */
/** GET /devis?customer_id=<gid|id>&after=<cursor>&include=items
 *  Renvoie { quotes[], pageInfo } ; si include=items, ajoute quotes[].lineItems[]
 */
app.get("/devis", async (req, res) => {
  try {
    if (!verifyProxy(req)) {
      return res.status(401).json({ error: "invalid_signature" });
    }

    const customerParam = req.query.customer_id;
    if (!customerParam) {
      return res.status(400).json({ error: "missing customer_id" });
    }

    const customerLegacyId = gidToLegacyId(customerParam);
    if (!customerLegacyId) {
      return res.status(400).json({ error: "bad customer_id" });
    }

    const after = req.query.after || null;
    const includeItems = String(req.query.include || "").toLowerCase() === "items";

    // On inclut les items seulement si demandé, pour éviter des coûts inutiles
    const lineItemsFrag = includeItems
      ? `
        lineItems(first: 50) {
          edges {
            node { title quantity variantTitle }
          }
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

    // Filtre par client : draft order ne supporte pas un query très riche, mais "customer_id:<legacyId>" marche
    const variables = {
      first: 10,
      after,
      q: `customer_id:${customerLegacyId}`
    };

    const data = await adminGraphQL(query, variables);
    const edges = data?.draftOrders?.edges || [];
    const pageInfo = data?.draftOrders?.pageInfo || {};

    const quotes = edges.map(({ node }) => mapDraftOrderNode(node, includeItems));

    // Anti-cache côté proxy
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
    res.setHeader("Pragma", "no-cache");

    return res.json({ quotes, pageInfo });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server_error" });
  }
});

/* -------------------------- Endpoint DÉTAIL ----------*
