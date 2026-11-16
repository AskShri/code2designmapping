const { Pool } = require('pg');
const pool = new Pool();

module.exports = async function (fastify, opts) {
  fastify.get('/', async () => (await pool.query('SELECT id, body FROM notes')).rows);
  fastify.post('/', { preHandler: [fastify.authenticate] }, async (req) => {
    await pool.query('INSERT INTO notes (body) VALUES ($1)', [req.body.body]);
  });
};
