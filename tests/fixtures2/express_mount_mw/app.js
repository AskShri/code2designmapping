const express = require('express');
const auth = require('./auth');
const items = require('./routes/items');
const app = express();
app.use(auth.attach);
app.use('/api', auth.requireAuth, items);
app.listen(3000);
