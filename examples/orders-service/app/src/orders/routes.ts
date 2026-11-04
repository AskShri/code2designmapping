import { Router } from "express";
import { z } from "zod";
import { createOrder, getOrder } from "./service";

export const CreateOrderRequest = z.object({
  customerEmail: z.string().email(),
  shippingAddress: z.string(),
  items: z.array(z.object({ sku: z.string(), qty: z.number().int() })),
  cardToken: z.string(),
});

export const ordersRouter = Router();

ordersRouter.post("/", async (req, res) => {
  const body = CreateOrderRequest.parse(req.body);
  const order = await createOrder(req.user.id, body);
  res.status(201).json(order);
});

ordersRouter.get("/:id", async (req, res) => {
  const order = await getOrder(req.params.id);
  if (!order) return res.status(404).end();
  res.json(order);
});
