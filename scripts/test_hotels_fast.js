#!/usr/bin/env node
/* eslint-disable no-console */

const assert = (cond, msg) => {
  if (!cond) {
    console.error("FAIL:", msg);
    process.exit(1);
  }
};

const base = (process.env.API_BASE || "http://localhost:3000").replace(/\/$/, "");
const userId = process.env.USER_ID || "test-user";
const city = process.env.HOTEL_CITY || "Miami";
const daysAhead = Number(process.env.CHECKIN_DAYS_AHEAD || 7);
const checkIn = new Date(Date.now() + daysAhead * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

const headers = {
  "Content-Type": "application/json",
  "x-user-id": userId,
};

async function main() {
  const body = { city, checkIn, nights: 1, adults: 1, max: 10 };
  const searchRes = await fetch(`${base}/v1/hotels/search?fast=1`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  const searchJson = await searchRes.json();
  assert(searchJson.ok === true, "search ok");
  assert(Array.isArray(searchJson.items), "items array");
  assert(searchJson.items.length > 0, "search returned at least one hotel");

  const items = searchJson.items || [];
  const byId = new Map();
  for (const item of items) {
    const hotelId = String(item?.hotelId || "").trim();
    assert(hotelId, "search item hotelId present");
    byId.set(hotelId, item);
    assert(item.name, "search item name present");
  }

  const requestedHotelIds = items.slice(0, 3).map((item) => String(item.hotelId || "").trim()).filter(Boolean);
  assert(requestedHotelIds.length > 0, "requestedHotelIds present");
  const pricesRes = await fetch(`${base}/v1/hotels/prices`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      hotelIds: requestedHotelIds,
      checkIn,
      nights: 1,
      adults: 1,
    }),
  });
  const pricesJson = await pricesRes.json();
  assert(pricesJson.ok === true, "prices ok");
  assert(Array.isArray(pricesJson.items), "prices items array");
  assert(pricesJson.items.length === requestedHotelIds.length, "prices item count matches request");
  for (const item of pricesJson.items) {
    const hotelId = String(item?.hotelId || "").trim();
    assert(hotelId, "prices item hotelId present");
    assert(byId.has(hotelId), "prices item hotelId exists in search results");
    assert(item.price_status, "prices item price_status present");
    assert(item.error !== "missing_search_context", "search to prices continuity is preserved");

    const searchItem = byId.get(hotelId);
    if (searchItem?.offer) {
      assert(item.price_status === "priced", "search item with offer is priced");
      assert(item.offer && typeof item.offer === "object", "priced item offer present");
      assert(item.price && typeof item.price === "object", "priced item price present");
    }
  }

  console.log("PASS: hotels fast mode check");
}

main().catch((err) => {
  console.error("ERROR:", err?.message || err);
  process.exit(1);
});
