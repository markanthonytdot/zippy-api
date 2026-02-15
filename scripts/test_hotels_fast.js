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

  const items = searchJson.items || [];
  for (const item of items) {
    assert(item.price_status, "item price_status present");
    if (item.price_status !== "priced") {
      assert(item.price == null, "non-priced item price null");
      assert(item.offer == null, "non-priced item offer null");
    }
  }

  const unavailableIds = new Set(items.filter((i) => i.price_status === "unavailable").map((i) => i.hotelId));
  const retryIds = searchJson?.next?.data?.hotelIds || [];
  for (const id of retryIds) {
    assert(!unavailableIds.has(id), "unavailable id not in next");
  }

  if (retryIds.length > 0 && searchJson.next?.endpoint) {
    const pricesRes = await fetch(`${base}${searchJson.next.endpoint}`, {
      method: "POST",
      headers,
      body: JSON.stringify({ data: searchJson.next.data }),
    });
    const pricesJson = await pricesRes.json();
    assert(pricesJson.ok === true, "prices ok");
    assert(Array.isArray(pricesJson.items), "prices items array");
    for (const item of pricesJson.items) {
      assert(item.price_status, "prices item price_status present");
      if (item.price_status !== "priced") {
        assert(item.price == null, "prices non-priced item price null");
        assert(item.offer == null, "prices non-priced item offer null");
      }
    }
  }

  console.log("PASS: hotels fast mode check");
}

main().catch((err) => {
  console.error("ERROR:", err?.message || err);
  process.exit(1);
});
