module.exports = async function (fastify) {
  fastify.decorate('authenticate', async (req) => { await req.jwtVerify(); });
};
