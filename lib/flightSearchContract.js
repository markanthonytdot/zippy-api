const CONTRACT_VERSION = 1;
const BEST_RANKING_METHOD = "weighted-value-v1";
const { calculatePricing, minorToDecimal } = require("./flightBooking");
const {
  SUPPORTED_CUSTOMER_CURRENCIES,
  defaultCurrencySettingsConfig,
  mergeFlightPricingWithCurrencySettings,
  normalizeCurrencySettingsConfig,
  resolveCustomerCurrency,
} = require("./pricingConfig");

function parseDurationMinutes(value) {
  const raw = String(value || "");
  const match = raw.match(/^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?$/i);
  if (!match || !/[0-9][DHM]/i.test(raw)) return null;
  const minutes = Number(match[1] || 0) * 1440 + Number(match[2] || 0) * 60 + Number(match[3] || 0);
  return Number.isFinite(minutes) ? minutes : null;
}

function minutesBetween(start, end) {
  const explicitOffset = /(?:Z|[+-]\d{2}:\d{2})$/i;
  if (!explicitOffset.test(String(start || "")) || !explicitOffset.test(String(end || ""))) return null;
  const minutes = (Date.parse(end) - Date.parse(start)) / 60000;
  return Number.isFinite(minutes) && minutes >= 0 ? minutes : null;
}

function normalizeLocation(value) {
  return {
    iataCode: String(value?.iata_code || ""),
    iataCityCode: String(value?.iata_city_code || ""),
    name: String(value?.name || ""),
  };
}

function normalizeCarrier(value) {
  return { name: String(value?.name || "") };
}

function normalizeSegment(segment) {
  return {
    departingAt: String(segment?.departing_at || ""),
    arrivingAt: String(segment?.arriving_at || ""),
    origin: normalizeLocation(segment?.origin),
    destination: normalizeLocation(segment?.destination),
    marketingCarrier: normalizeCarrier(segment?.marketing_carrier),
    operatingCarrier: normalizeCarrier(segment?.operating_carrier),
    marketingCarrierFlightNumber: String(segment?.marketing_carrier_flight_number || ""),
    operatingCarrierFlightNumber: String(segment?.operating_carrier_flight_number || ""),
  };
}

function sliceDurationMinutes(slice) {
  const supplied = parseDurationMinutes(slice?.duration);
  if (supplied != null) return supplied;
  const segments = Array.isArray(slice?.segments) ? slice.segments : [];
  if (!segments.length) return null;
  return minutesBetween(segments[0]?.departing_at, segments[segments.length - 1]?.arriving_at);
}

function includedBaggage(offer) {
  const incomplete = {
    minimumCheckedPerTraveler: null,
    minimumCabinCarryOnPerTraveler: null,
    minimumPersonalItemsPerTraveler: null,
    complete: false,
    heterogeneous: null,
  };
  const expectedPassengers = Array.isArray(offer?.passengers) ? offer.passengers.length : 0;
  const slices = Array.isArray(offer?.slices) ? offer.slices : [];
  if (!expectedPassengers || !slices.length) return incomplete;

  const checkedCounts = [];
  const cabinCarryOnCounts = [];
  const personalItemCounts = [];
  const cabinCarryOnTypes = new Set(["carry_on", "cabin_bag", "small_carry_on"]);
  for (const slice of slices) {
    const segments = Array.isArray(slice?.segments) ? slice.segments : [];
    if (!segments.length) return incomplete;
    for (const segment of segments) {
      const passengers = Array.isArray(segment?.passengers) ? segment.passengers : [];
      if (passengers.length !== expectedPassengers) return incomplete;
      for (const passenger of passengers) {
        if (!Array.isArray(passenger?.baggages)) return incomplete;
        let checked = 0;
        let cabinCarryOn = 0;
        let personalItems = 0;
        for (const bag of passenger.baggages) {
          const quantity = Number(bag?.quantity);
          if (!Number.isInteger(quantity) || quantity < 0) {
            return incomplete;
          }
          if (bag?.type === "checked") checked += quantity;
          if (cabinCarryOnTypes.has(bag?.type)) cabinCarryOn = Math.max(cabinCarryOn, quantity);
          if (bag?.type === "personal_item") personalItems = Math.max(personalItems, quantity);
        }
        checkedCounts.push(checked);
        cabinCarryOnCounts.push(cabinCarryOn);
        personalItemCounts.push(personalItems);
      }
    }
  }

  return {
    minimumCheckedPerTraveler: Math.min(...checkedCounts),
    minimumCabinCarryOnPerTraveler: Math.min(...cabinCarryOnCounts),
    minimumPersonalItemsPerTraveler: Math.min(...personalItemCounts),
    complete: true,
    heterogeneous: new Set(checkedCounts).size > 1
      || new Set(cabinCarryOnCounts).size > 1
      || new Set(personalItemCounts).size > 1,
  };
}

function normalizePenaltyCondition(value) {
  if (!value || typeof value !== "object") return null;
  const allowed = typeof value.allowed === "boolean" ? value.allowed : null;
  if (allowed == null) return null;
  return {
    allowed,
    penaltyAmount: value.penalty_amount == null ? null : String(value.penalty_amount),
    penaltyCurrency: String(value.penalty_currency || "").trim().toUpperCase() || null,
  };
}

function normalizeConditions(offer) {
  const conditions = offer?.conditions && typeof offer.conditions === "object" ? offer.conditions : null;
  if (!conditions) return null;
  const changeBeforeDeparture = normalizePenaltyCondition(conditions.change_before_departure);
  const refundBeforeDeparture = normalizePenaltyCondition(conditions.refund_before_departure);
  if (!changeBeforeDeparture && !refundBeforeDeparture) return null;
  return { changeBeforeDeparture, refundBeforeDeparture };
}

function normalizeOffer(offer) {
  const slices = (Array.isArray(offer?.slices) ? offer.slices : []).map((slice) => {
    const segments = (Array.isArray(slice?.segments) ? slice.segments : []).map(normalizeSegment);
    return { durationMinutes: sliceDurationMinutes(slice), segments };
  });
  const durations = slices.map((slice) => slice.durationMinutes);
  const rawAmount = String(offer?.total_amount ?? "").trim();
  const numericAmount = Number(rawAmount);
  const rawCurrency = String(offer?.total_currency || "").trim().toUpperCase();
  const validCurrency = /^[A-Z]{3}$/.test(rawCurrency);
  const validAmount = rawAmount && Number.isFinite(numericAmount) && numericAmount >= 0 && validCurrency;

  return {
    id: String(offer?.id || "").trim(),
    totalAmount: validAmount ? rawAmount : null,
    totalCurrency: validCurrency ? rawCurrency : null,
    passengerCount: Array.isArray(offer?.passengers) ? offer.passengers.length : 0,
    slices,
    totalDurationMinutes: durations.length > 0 && durations.every(Number.isFinite)
      ? durations.reduce((sum, duration) => sum + duration, 0)
      : null,
    baggage: includedBaggage(offer),
    cabinClass: String(offer?.cabin_class || ""),
    fareBrandName: String(offer?.fare_brand_name || ""),
    conditions: normalizeConditions(offer),
  };
}

function buildOfferCustomerPricing(offer, pricingOptions) {
  if (!pricingOptions?.pricingConfig || !pricingOptions.exchangeRates?.rates) return null;

  const enabledCurrencies = pricingOptions.enabledCurrencies || [];
  const options = {};
  for (const currency of enabledCurrencies) {
    try {
      const pricing = calculatePricing(
        offer,
        [],
        currency,
        pricingOptions.pricingConfig,
        pricingOptions.exchangeRates
      );
      options[currency] = {
        currency,
        totalAmount: minorToDecimal(pricing.customerTotalMinor, currency),
        totalMinor: pricing.customerTotalMinor,
        offerTotalAmount: minorToDecimal(pricing.customerConvertedMinor, currency),
        offerTotalMinor: pricing.customerConvertedMinor,
        roundingIncrementMinor: pricing.customerRoundingIncrementMinor,
      };
    } catch (_) {
      options[currency] = null;
    }
  }

  const selectedCurrency = pricingOptions.selectedCurrency;
  return {
    selectedCurrency,
    selected: selectedCurrency ? (options[selectedCurrency] || null) : null,
    options,
  };
}

function numericOrInfinity(value) {
  return Number.isFinite(value) ? value : Infinity;
}

function compareId(left, right) {
  if (left.id === right.id) return 0;
  return left.id < right.id ? -1 : 1;
}

function compareRankingEligibility(left, right, mode) {
  return Number(!left.rankingEligibility[mode]) - Number(!right.rankingEligibility[mode]);
}

function rankingAmount(offer, rankingCurrency) {
  const selectedPrice = offer.customerPricing?.selected;
  if (rankingCurrency && selectedPrice?.currency === rankingCurrency && Number.isFinite(Number(selectedPrice.totalAmount))) {
    return Number(selectedPrice.totalAmount);
  }
  return offer.totalAmount == null ? Infinity : Number(offer.totalAmount);
}

function rankOffers(offers, rankingCurrency = null) {
  const cheapest = offers.slice().sort((left, right) => {
    const eligibility = compareRankingEligibility(left, right, "cheapest");
    if (eligibility) return eligibility;
    if (!left.rankingEligibility.cheapest) return compareId(left, right);
    const leftAmount = rankingAmount(left, rankingCurrency);
    const rightAmount = rankingAmount(right, rankingCurrency);
    return leftAmount - rightAmount || compareId(left, right);
  });
  const fastest = offers.slice().sort((left, right) => {
    const eligibility = compareRankingEligibility(left, right, "fastest");
    if (eligibility) return eligibility;
    if (!left.rankingEligibility.fastest) return compareId(left, right);
    return numericOrInfinity(left.totalDurationMinutes) - numericOrInfinity(right.totalDurationMinutes)
      || compareId(left, right);
  });

  const finitePrices = offers.map((offer) => rankingAmount(offer, rankingCurrency)).filter((value, index) =>
    offers[index].rankingEligibility.best && Number.isFinite(value));
  const finiteDurations = offers.filter((offer) => offer.rankingEligibility.best)
    .map((offer) => offer.totalDurationMinutes).filter(Number.isFinite);
  const minPrice = finitePrices.length ? Math.min(...finitePrices) : null;
  const maxPrice = finitePrices.length ? Math.max(...finitePrices) : null;
  const minDuration = finiteDurations.length ? Math.min(...finiteDurations) : null;
  const maxDuration = finiteDurations.length ? Math.max(...finiteDurations) : null;
  const normalizedPenalty = (value, minimum, maximum) => {
    if (!Number.isFinite(value) || minimum == null || maximum == null) return 1_000_000;
    if (maximum === minimum) return 0;
    return Math.round(((value - minimum) / (maximum - minimum)) * 1_000_000);
  };
  const best = offers.slice().sort((left, right) => {
    const eligibility = compareRankingEligibility(left, right, "best");
    if (eligibility) return eligibility;
    if (!left.rankingEligibility.best) return compareId(left, right);
    // Price is the stronger signal, while elapsed journey time keeps "Best" distinct
    // from "Cheapest". IDs are the final tie-breaker so provider response ordering
    // cannot change the public ranking.
    const leftScore = normalizedPenalty(rankingAmount(left, rankingCurrency), minPrice, maxPrice) * 55
      + normalizedPenalty(left.totalDurationMinutes, minDuration, maxDuration) * 45;
    const rightScore = normalizedPenalty(rankingAmount(right, rankingCurrency), minPrice, maxPrice) * 55
      + normalizedPenalty(right.totalDurationMinutes, minDuration, maxDuration) * 45;
    return leftScore - rightScore || compareId(left, right);
  });

  return {
    best: best.map((offer) => offer.id),
    cheapest: cheapest.map((offer) => offer.id),
    fastest: fastest.map((offer) => offer.id),
  };
}

function rankingCurrencyForOffers(offers, requestedCurrency) {
  const requested = String(requestedCurrency || "").trim().toUpperCase();
  if (/^[A-Z]{3}$/.test(requested)) return requested;
  const observed = [...new Set(offers.map((offer) => offer.totalCurrency).filter((currency) => /^[A-Z]{3}$/.test(currency)))].sort();
  return observed.length === 1 ? observed[0] : null;
}

function normalizeSearchPricingOptions(rawOptions) {
  if (!rawOptions || typeof rawOptions !== "object" || Array.isArray(rawOptions)) return null;

  const currencySettings = normalizeCurrencySettingsConfig(
    rawOptions.currencySettings,
    defaultCurrencySettingsConfig()
  );
  const selectedCurrencyResolution = resolveCustomerCurrency({
    currencySettings,
    requestedCurrency: rawOptions.requestedCurrency,
    countryCode: rawOptions.countryCode,
  });
  const enabledCurrencies = SUPPORTED_CUSTOMER_CURRENCIES.filter((code) => currencySettings.currencies[code].enabled);
  return {
    selectedCurrency: selectedCurrencyResolution.currency,
    selectedCurrencySource: selectedCurrencyResolution.source,
    pricingConfig: mergeFlightPricingWithCurrencySettings(rawOptions.pricingConfig, currencySettings),
    currencySettings,
    exchangeRates: rawOptions.exchangeRates || null,
    enabledCurrencies,
  };
}

function buildFlightSearchContract(rawOffers, requestedCurrencyOrOptions) {
  const pricingOptions = normalizeSearchPricingOptions(
    typeof requestedCurrencyOrOptions === "string" || requestedCurrencyOrOptions == null
      ? null
      : requestedCurrencyOrOptions
  );
  const requestedCurrency = typeof requestedCurrencyOrOptions === "string"
    ? requestedCurrencyOrOptions
    : requestedCurrencyOrOptions?.requestedCurrency;
  const offers = [];
  const seenIds = new Set();
  for (const rawOffer of Array.isArray(rawOffers) ? rawOffers : []) {
    const offer = normalizeOffer(rawOffer);
    if (!offer.id || seenIds.has(offer.id)) continue;
    seenIds.add(offer.id);
    offers.push({
      ...offer,
      customerPricing: buildOfferCustomerPricing(rawOffer, pricingOptions),
    });
  }

  const rankingCurrency = pricingOptions?.selectedCurrency || rankingCurrencyForOffers(offers, requestedCurrency);
  const rankedOffers = offers.map((offer) => ({
    ...offer,
    rankingEligibility: {
      best: Boolean(rankingCurrency
        && ((offer.customerPricing?.selected?.currency === rankingCurrency && offer.customerPricing?.selected?.totalAmount != null)
          || (offer.totalCurrency === rankingCurrency && offer.totalAmount != null))
        && Number.isFinite(offer.totalDurationMinutes) && offer.totalDurationMinutes >= 0),
      cheapest: Boolean(rankingCurrency
        && ((offer.customerPricing?.selected?.currency === rankingCurrency && offer.customerPricing?.selected?.totalAmount != null)
          || (offer.totalCurrency === rankingCurrency && offer.totalAmount != null))),
      fastest: Number.isFinite(offer.totalDurationMinutes) && offer.totalDurationMinutes >= 0,
    },
  }));
  const rankingAvailability = {
    best: rankedOffers.some((offer) => offer.rankingEligibility.best),
    cheapest: rankedOffers.some((offer) => offer.rankingEligibility.cheapest),
    fastest: rankedOffers.some((offer) => offer.rankingEligibility.fastest),
  };
  return {
    contractVersion: CONTRACT_VERSION,
    rankingMethod: BEST_RANKING_METHOD,
    rankingCurrency,
    customerPricing: pricingOptions ? {
      selectedCurrency: pricingOptions.selectedCurrency,
      selectedCurrencySource: pricingOptions.selectedCurrencySource,
      enabledCurrencies: pricingOptions.enabledCurrencies,
    } : null,
    rankingAvailability,
    offers: rankedOffers,
    rankings: rankOffers(rankedOffers, rankingCurrency),
  };
}

module.exports = {
  BEST_RANKING_METHOD,
  CONTRACT_VERSION,
  buildFlightSearchContract,
  includedBaggage,
  normalizeOffer,
  parseDurationMinutes,
  rankingCurrencyForOffers,
  rankOffers,
};
