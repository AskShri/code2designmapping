const router = require('express').Router();
router.get('/items', (req, res) => res.json([]));
module.exports = router;
