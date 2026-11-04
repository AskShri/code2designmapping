import { pool } from "../infra/db";
import { redis } from "../infra/cache";
import { chargeCard } from "../payments/stripe";

export async function createOrder(userId: string, input: {
  customerEmail: string;
  shippingAddress: string;
  items: { sku: string; qty: number }[];
  cardToken: string;
}) {
  const total = input.items.reduce((sum, i) => sum + i.qty * 100, 0);
  const charge = await chargeCard(input.cardToken, total);
  const { rows } = await pool.query(
    "INSERT INTO orders (user_id, customer_email, shipping_address, total_cents, charge_id) VALUES ($1,$2,$3,$4,$5) RETURNING *",
    [userId, input.customerEmail, input.shippingAddress, total, charge.id],
  );
  await redis.set(`order:${rows[0].id}`, JSON.stringify(rows[0]), "EX", 300);
  return rows[0];
}

export async function getOrder(id: string) {
  const cached = await redis.get(`order:${id}`);
  if (cached) return JSON.parse(cached);
  const { rows } = await pool.query("SELECT * FROM orders WHERE id = $1", [id]);
  return rows[0] ?? null;
}
