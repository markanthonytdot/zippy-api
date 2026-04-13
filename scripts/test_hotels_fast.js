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
  assert(pricesJson.items.length >= requestedHotelIds.length, "prices has at least one row per requested hotel");
  const pricesByHotelId = new Map();
  for (const item of pricesJson.items) {
    const hotelId = String(item?.hotelId || "").trim();
    assert(hotelId, "prices item hotelId present");
    assert(byId.has(hotelId), "prices item hotelId exists in search results");
    assert(item.price_status, "prices item price_status present");
    if (!pricesByHotelId.has(hotelId)) pricesByHotelId.set(hotelId, []);
    pricesByHotelId.get(hotelId).push(item);
  }

  for (const requestedHotelId of requestedHotelIds) {
    const grouped = pricesByHotelId.get(requestedHotelId) || [];
    assert(grouped.length > 0, "requested hotel has price rows");
    const continuityBreak = grouped.find((entry) => entry?.error === "missing_search_context");
    assert(!continuityBreak, "search to prices continuity is preserved");

    const searchItem = byId.get(requestedHotelId);
    if (searchItem?.offer) {
      const pricedRows = grouped.filter((entry) => entry?.price_status === "priced");
      assert(pricedRows.length > 0, "search item with offer has at least one priced row");
      for (const entry of pricedRows) {
        assert(entry.offer && typeof entry.offer === "object", "priced item offer present");
        assert(entry.price && typeof entry.price === "object", "priced item price present");
      }
    }
  }

  console.log("PASS: hotels fast mode check");
}

main().catch((err) => {
  console.error("ERROR:", err?.message || err);
  process.exit(1);
});
