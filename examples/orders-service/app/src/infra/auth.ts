import type { RequestHandler } from "express";
import jwt from "jsonwebtoken";

export function requireJwt(): RequestHandler {
  return (req, res, next) => {
    const token = req.header("authorization")?.replace("Bearer ", "");
    if (!token) return res.status(401).end();
    req.user = jwt.verify(token, process.env.JWT_PUBLIC_KEY!);
    next();
  };
}
