const express = require("express");
const app = express();

app.get("/health", (req, res) => {
  res.json({ ok: true, service: "zippy-api" });
});

const port = process.env.PORT || 4001;
app.listen(port, "0.0.0.0", () => {
  console.log("zippy-api listening on port", port);
});
