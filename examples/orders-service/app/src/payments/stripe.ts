import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function chargeCard(cardToken: string, amountCents: number) {
  return stripe.charges.create({ amount: amountCents, currency: "usd", source: cardToken });
}
