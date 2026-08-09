function createHotelDuffelBookingLookup({
  token,
  apiVersion = "v2",
  timeoutMs = 15_000,
  fetchImpl = fetch,
  baseURL = "https://api.duffel.com",
  maximumPages = 20,
  maximumItems = 2_000,
}) {
  const testToken = String(token || "").trim();
  if (!testToken.startsWith("duffel_test_")) throw new Error("Hotel recovery requires a Duffel TEST token");

  async function findBookingForSession(session) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const matches = [];
    const seenCursors = new Set();
    let after = null;
    let itemCount = 0;
    try {
      for (let page = 0; page < maximumPages; page += 1) {
        const url = new URL("/stays/bookings", baseURL);
        url.searchParams.set("limit", "200");
        if (after) url.searchParams.set("after", after);
        const response = await fetchImpl(url, {
          headers: {
            Accept: "application/json",
            "Accept-Encoding": "gzip",
            Authorization: `Bearer ${testToken}`,
            "Duffel-Version": apiVersion,
          },
          signal: controller.signal,
        });
        const body = await response.json().catch(() => null);
        if (!response.ok || !Array.isArray(body?.data)) {
          throw new Error(`Duffel Stays booking lookup failed (${response.status})`);
        }
        itemCount += body.data.length;
        if (itemCount > maximumItems) throw new Error("Duffel Stays booking lookup exceeded its item limit");
        matches.push(...body.data.filter((booking) =>
          String(booking?.metadata?.zippi_booking_session_id || "") === String(session?.id || "")
        ));
        if (matches.length > 1) return { status: "ambiguous", requestId: body?.meta?.request_id || null };
        const next = String(body?.meta?.after || "").trim() || null;
        if (!next) {
          return matches.length === 1
            ? { status: "found", booking: matches[0], requestId: body?.meta?.request_id || null }
            : { status: "not_found", requestId: body?.meta?.request_id || null };
        }
        if (seenCursors.has(next)) throw new Error("Duffel Stays booking lookup returned a repeated cursor");
        seenCursors.add(next);
        after = next;
      }
      throw new Error("Duffel Stays booking lookup exceeded its page limit");
    } finally {
      clearTimeout(timer);
    }
  }

  return { findBookingForSession };
}

module.exports = { createHotelDuffelBookingLookup };
