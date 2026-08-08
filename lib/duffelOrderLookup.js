const { validateReconciledOrder } = require("./flightRecovery");

function createDuffelOrderLookup({
  token,
  apiVersion = "v2",
  fetchImpl = globalThis.fetch,
  timeoutMs = 15_000,
  baseURL = "https://api.duffel.com",
  maximumPages = 20,
  maximumItems = 2_000,
} = {}) {
  if (!String(token || "").startsWith("duffel_test_")) {
    throw new Error("Duffel recovery lookup requires a test token");
  }
  if (typeof fetchImpl !== "function") throw new Error("Duffel recovery lookup requires fetch");

  return {
    async findOrderForSession(session) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const verified = [];
      const seenCursors = new Set();
      let after = null;
      let itemCount = 0;
      try {
        for (let page = 0; page < maximumPages; page += 1) {
          const url = new URL("/air/orders", baseURL);
          url.searchParams.set("offer_id", session.duffel_offer_id);
          url.searchParams.set("limit", "200");
          if (after) url.searchParams.set("after", after);
          const response = await fetchImpl(url, {
            method: "GET",
            headers: {
              Accept: "application/json",
              Authorization: `Bearer ${token}`,
              "Duffel-Version": apiVersion,
            },
            signal: controller.signal,
          });
          const payload = await response.json().catch((error) => { throw error; });
          if (!response.ok || !Array.isArray(payload?.data)) {
            throw new Error(`Duffel order lookup failed with HTTP ${response.status}`);
          }
          itemCount += payload.data.length;
          if (itemCount > maximumItems) throw new Error("Duffel order lookup exceeded its item limit");
          verified.push(...payload.data.filter((order) => validateReconciledOrder(order, session)));
          if (verified.length > 1) return { status: "ambiguous", matchCount: verified.length };
          const next = String(payload?.meta?.after || "").trim() || null;
          if (!next) {
            return verified.length === 1
              ? { status: "found", order: verified[0], requestId: payload?.meta?.request_id || null }
              : { status: "unknown", matchCount: 0 };
          }
          if (seenCursors.has(next)) throw new Error("Duffel order lookup returned a repeated cursor");
          seenCursors.add(next);
          after = next;
        }
        throw new Error("Duffel order lookup exceeded its page limit");
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

module.exports = { createDuffelOrderLookup };
