import express from "express";
import { requireJwt } from "./infra/auth";
import { rateLimit } from "./infra/ratelimit";
import { ordersRouter } from "./orders/routes";

const app = express();
app.use(express.json());
app.use(requireJwt());
app.use(rateLimit({ windowMs: 60_000, max: 100 }));
app.use("/orders", ordersRouter);

app.listen(8080);
