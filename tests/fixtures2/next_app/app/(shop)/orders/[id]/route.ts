import { prisma } from "../../../../lib/db";

export async function GET(req: Request, { params }) {
  return Response.json(await prisma.order.findUnique({ where: { id: params.id } }));
}

export async function DELETE(req: Request, { params }) {
  await prisma.order.delete({ where: { id: params.id } });
  return new Response(null, { status: 204 });
}
