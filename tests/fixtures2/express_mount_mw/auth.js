exports.attach = (req, res, next) => { req.t = req.get('Authorization'); next(); };
exports.requireAuth = (req, res, next) => req.t ? next() : res.sendStatus(401);
