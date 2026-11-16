import { prisma } from "../../../lib/db";

export default async function handler(req, res) {
  const user = await prisma.user.findUnique({ where: { id: req.query.id } });
  res.json(user);
}
