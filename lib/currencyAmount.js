const ZERO_DECIMAL_CURRENCIES = new Set([
  "BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW", "MGA", "PYG", "RWF", "UGX", "VND", "VUV", "XAF", "XOF", "XPF",
]);
const THREE_DECIMAL_CURRENCIES = new Set(["BHD", "JOD", "KWD", "OMR", "TND"]);

function currencyExponent(currency) {
  const code = String(currency || "").trim().toUpperCase();
  if (ZERO_DECIMAL_CURRENCIES.has(code)) return 0;
  if (THREE_DECIMAL_CURRENCIES.has(code)) return 3;
  return 2;
}

function decimalToMinorExact(value, currency) {
  const raw = String(value ?? "").trim();
  const match = raw.match(/^(\d+)(?:\.(\d+))?$/);
  if (!match) throw new Error("Duffel returned an invalid price.");
  const exponent = currencyExponent(currency);
  const fractional = match[2] || "";
  if (fractional.length > exponent && /[1-9]/.test(fractional.slice(exponent))) {
    throw new Error("Duffel returned a price with unsupported precision.");
  }
  const digits = `${match[1]}${fractional.slice(0, exponent).padEnd(exponent, "0")}`;
  const minor = Number(BigInt(digits || "0"));
  if (!Number.isSafeInteger(minor)) throw new Error("Duffel returned a price that is too large.");
  return minor;
}

function minorToDecimal(value, currency) {
  const minor = Number(value);
  const exponent = currencyExponent(currency);
  if (!Number.isSafeInteger(minor) || minor < 0) throw new Error("Invalid minor amount");
  if (exponent === 0) return String(minor);
  const raw = String(minor).padStart(exponent + 1, "0");
  return `${raw.slice(0, -exponent)}.${raw.slice(-exponent)}`;
}

module.exports = { currencyExponent, decimalToMinorExact, minorToDecimal };
