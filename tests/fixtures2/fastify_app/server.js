const fastify = require('fastify')();
fastify.register(require('./plugins/auth'));
fastify.register(require('./routes/notes'), { prefix: '/notes' });
fastify.listen({ port: 3000 });
