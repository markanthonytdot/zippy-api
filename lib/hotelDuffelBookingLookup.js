function createHotelDuffelBookingLookup({ token, apiVersion = "v2", timeoutMs = 15_000, fetchImpl = fetch }) {
  const testToken = String(token || "").trim();
  if (!testToken.startsWith("duffel_test_")) throw new Error("Hotel recovery requires a Duffel TEST token");

  async function findBookingForSession(session) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl("https://api.duffel.com/stays/bookings?limit=200", {
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
      const matches = body.data.filter((booking) =>
        String(booking?.metadata?.zippi_booking_session_id || "") === String(session?.id || "")
      );
      if (matches.length === 0) return { status: "not_found", requestId: body?.meta?.request_id || null };
      if (matches.length !== 1) return { status: "ambiguous", requestId: body?.meta?.request_id || null };
      return { status: "found", booking: matches[0], requestId: body?.meta?.request_id || null };
    } finally {
      clearTimeout(timer);
    }
  }

  return { findBookingForSession };
}

module.exports = { createHotelDuffelBookingLookup };
