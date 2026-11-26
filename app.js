const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const config = require("./config");
const routes = require("./routes");
const { notFound, errorHandler } = require("./middleware/errorHandler");

const app = express();
app.set("trust proxy", config.server.trustProxy);
app.disable("x-powered-by");

app.use(helmet());
app.use(express.json({ limit: config.server.jsonBodyLimit }));
app.use(cookieParser());
app.use("/api", (req, res, next) => { res.set("Cache-Control", "no-store"); next(); }); // never cache API/auth responses
app.use("/api", routes);
app.use(notFound);
app.use(errorHandler);

module.exports = app;
