"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key2 of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key2) && key2 !== except)
        __defProp(to, key2, { get: () => from[key2], enumerable: !(desc = __getOwnPropDesc(from, key2)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/index.ts
var import_express7 = __toESM(require("express"));
var import_cors = __toESM(require("cors"));
var import_helmet = __toESM(require("helmet"));
var import_http9 = __toESM(require("http"));
var import_express_rate_limit3 = __toESM(require("express-rate-limit"));

// src/config.ts
var import_dotenv = __toESM(require("dotenv"));
var import_path = __toESM(require("path"));
var import_zod = require("zod");
import_dotenv.default.config({ path: import_path.default.resolve(__dirname, "../../.env") });
import_dotenv.default.config();
var schema = import_zod.z.object({
  PORT: import_zod.z.coerce.number().default(4e3),
  NODE_ENV: import_zod.z.string().default("development"),
  DATABASE_URL: import_zod.z.string().min(1),
  JWT_SECRET: import_zod.z.string().min(16, "JWT_SECRET \u0434\u043E\u043B\u0436\u0435\u043D \u0431\u044B\u0442\u044C \u043D\u0435 \u043A\u043E\u0440\u043E\u0447\u0435 16 \u0441\u0438\u043C\u0432\u043E\u043B\u043E\u0432"),
  JWT_EXPIRES_IN: import_zod.z.string().default("7d"),
  CORS_ORIGIN: import_zod.z.string().default("*"),
  PUBLIC_APP_URL: import_zod.z.string().default("http://localhost:5173")
});
var parsed = schema.safeParse(process.env);
if (!parsed.success) {
  console.error("\u041E\u0448\u0438\u0431\u043A\u0430 \u043A\u043E\u043D\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u0438 (.env):", parsed.error.flatten().fieldErrors);
  process.exit(1);
}
var config = parsed.data;
var corsOrigin = config.CORS_ORIGIN === "*" ? true : config.CORS_ORIGIN.split(",");

// src/db.ts
var import_client = require("@prisma/client");
var prisma = new import_client.PrismaClient();

// src/logger.ts
var import_pino = __toESM(require("pino"));
var logger = (0, import_pino.default)({ level: process.env.NODE_ENV === "production" ? "info" : "debug" });

// src/http.ts
var import_jsonwebtoken = __toESM(require("jsonwebtoken"));
var import_zod2 = require("zod");

// src/permissions.ts
var P = {
  ADMIN: 1,
  MANAGE_SERVER: 2,
  MANAGE_CHANNELS: 4,
  MANAGE_ROLES: 8,
  KICK: 16,
  BAN: 32,
  CREATE_INVITE: 64,
  SEND_MESSAGES: 128,
  CONNECT_VOICE: 256,
  SPEAK: 512,
  MANAGE_MESSAGES: 1024
};
var ALL = Object.values(P).reduce((a, b) => a | b, 0);
var DEFAULT_PERMS = P.CREATE_INVITE | P.SEND_MESSAGES | P.CONNECT_VOICE | P.SPEAK;
async function getPerms(userId, serverId) {
  const server2 = await prisma.server.findUnique({ where: { id: serverId }, select: { ownerId: true } });
  if (!server2) return null;
  const member = await prisma.member.findUnique({
    where: { userId_serverId: { userId, serverId } },
    include: { roles: { include: { role: true } } }
  });
  if (!member) return null;
  if (server2.ownerId === userId) return ALL;
  const def = await prisma.role.findFirst({ where: { serverId, isDefault: true } });
  let perms = def?.permissions ?? 0;
  for (const mr of member.roles) perms |= mr.role.permissions;
  if (perms & P.ADMIN) return ALL;
  return perms;
}
var has = (perms, flag) => perms !== null && (perms & flag) === flag;

// src/http.ts
var HttpError = class extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
};
var ah = (fn) => (req, res, next) => {
  fn(req, res).catch(next);
};
var signToken = (userId) => import_jsonwebtoken.default.sign({ sub: userId }, config.JWT_SECRET, { expiresIn: config.JWT_EXPIRES_IN });
var verifyToken = (token) => {
  try {
    return import_jsonwebtoken.default.verify(token, config.JWT_SECRET).sub;
  } catch {
    return null;
  }
};
var requireAuth = (req, _res, next) => {
  const h = req.headers.authorization;
  const userId = h?.startsWith("Bearer ") ? verifyToken(h.slice(7)) : null;
  if (!userId) return next(new HttpError(401, "\u0422\u0440\u0435\u0431\u0443\u0435\u0442\u0441\u044F \u0430\u0432\u0442\u043E\u0440\u0438\u0437\u0430\u0446\u0438\u044F"));
  req.userId = userId;
  next();
};
async function requirePerm(userId, serverId, flag) {
  const perms = await getPerms(userId, serverId);
  if (perms === null) throw new HttpError(403, "\u0412\u044B \u043D\u0435 \u0443\u0447\u0430\u0441\u0442\u043D\u0438\u043A \u044D\u0442\u043E\u0433\u043E \u0441\u0435\u0440\u0432\u0435\u0440\u0430");
  if (!has(perms, flag)) throw new HttpError(403, "\u041D\u0435\u0434\u043E\u0441\u0442\u0430\u0442\u043E\u0447\u043D\u043E \u043F\u0440\u0430\u0432");
}
var errorHandler = (err, _req, res, _next) => {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  if (err instanceof import_zod2.ZodError) return res.status(400).json({ error: "\u041D\u0435\u043A\u043E\u0440\u0440\u0435\u043A\u0442\u043D\u044B\u0435 \u0434\u0430\u043D\u043D\u044B\u0435", details: err.flatten().fieldErrors });
  logger.error({ err }, "Unhandled error");
  res.status(500).json({ error: "\u0412\u043D\u0443\u0442\u0440\u0435\u043D\u043D\u044F\u044F \u043E\u0448\u0438\u0431\u043A\u0430 \u0441\u0435\u0440\u0432\u0435\u0440\u0430" });
};

// src/socket.ts
var import_socket = require("socket.io");

// src/access.ts
async function resolveTarget(userId, kind, id) {
  if (kind === "channel") {
    const ch = await prisma.channel.findUnique({ where: { id } });
    if (!ch) throw new HttpError(404, "\u041A\u0430\u043D\u0430\u043B \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D");
    if (ch.type !== "TEXT") throw new HttpError(400, "\u042D\u0442\u043E \u043D\u0435 \u0442\u0435\u043A\u0441\u0442\u043E\u0432\u044B\u0439 \u043A\u0430\u043D\u0430\u043B");
    const perms = await getPerms(userId, ch.serverId);
    if (perms === null) throw new HttpError(403, "\u041D\u0435\u0442 \u0434\u043E\u0441\u0442\u0443\u043F\u0430 \u043A \u043A\u0430\u043D\u0430\u043B\u0443");
    return { kind, id, serverId: ch.serverId, perms, memberIds: [], isGroup: false };
  }
  const dm = await prisma.dmChannel.findUnique({ where: { id }, include: { members: true } });
  if (!dm || !dm.members.some((m) => m.userId === userId)) throw new HttpError(404, "\u0414\u0438\u0430\u043B\u043E\u0433 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D");
  return { kind, id, serverId: null, perms: null, memberIds: dm.members.map((m) => m.userId), isGroup: dm.isGroup };
}
var canSend = (t) => t.kind === "dm" || has(t.perms, P.SEND_MESSAGES);
var canModerate = (t) => t.kind === "channel" && has(t.perms, P.MANAGE_MESSAGES);

// src/socket.ts
var io = null;
var online = /* @__PURE__ */ new Map();
var emitToUser = (userId, event, data) => io?.to(`user:${userId}`).emit(event, data);
var emitToServer = (serverId, event, data) => io?.to(`server:${serverId}`).emit(event, data);
var joinServerRoom = (userId, serverId) => io?.in(`user:${userId}`).socketsJoin(`server:${serverId}`);
var leaveServerRoom = (userId, serverId) => io?.in(`user:${userId}`).socketsLeave(`server:${serverId}`);
async function broadcastPresence(userId) {
  const u = await prisma.user.findUnique({ where: { id: userId }, select: { status: true } });
  if (!u) return;
  const isOn = (online.get(userId) ?? 0) > 0 && u.status !== "INVISIBLE";
  const status = isOn ? u.status : "OFFLINE";
  const memberships = await prisma.member.findMany({ where: { userId }, select: { serverId: true } });
  for (const m of memberships) emitToServer(m.serverId, "presence", { userId, status });
}
function initSocket(server2) {
  io = new import_socket.Server(server2, { cors: { origin: corsOrigin } });
  io.use((socket, next) => {
    const userId = verifyToken(String(socket.handshake.auth?.token ?? ""));
    if (!userId) return next(new Error("unauthorized"));
    socket.data.userId = userId;
    next();
  });
  io.on("connection", async (socket) => {
    const userId = socket.data.userId;
    try {
      socket.join(`user:${userId}`);
      const memberships = await prisma.member.findMany({ where: { userId }, select: { serverId: true } });
      for (const m of memberships) socket.join(`server:${m.serverId}`);
      online.set(userId, (online.get(userId) ?? 0) + 1);
      await broadcastPresence(userId);
    } catch (err) {
      logger.error({ err }, "socket connect failed");
    }
    const lastTyping = /* @__PURE__ */ new Map();
    socket.on("typing", async (p) => {
      try {
        const kind = p?.kind, id = String(p?.id ?? "");
        if (kind !== "channel" && kind !== "dm" || !id) return;
        const key2 = `${kind}:${id}`;
        if (Date.now() - (lastTyping.get(key2) ?? 0) < 1500) return;
        lastTyping.set(key2, Date.now());
        const t = await resolveTarget(userId, kind, id);
        emitToTarget(t, "typing", { kind, id, userId });
      } catch {
      }
    });
    socket.on("presence:refresh", () => {
      broadcastPresence(userId).catch(() => {
      });
    });
    socket.on("disconnect", () => {
      const n = (online.get(userId) ?? 1) - 1;
      if (n <= 0) online.delete(userId);
      else online.set(userId, n);
      broadcastPresence(userId).catch(() => {
      });
    });
  });
  return io;
}
function emitToTarget(t, event, data) {
  if (t.kind === "channel") emitToServer(t.serverId, event, data);
  else for (const id of t.memberIds) emitToUser(id, event, data);
}
var isOnline = (userId) => (online.get(userId) ?? 0) > 0;

// src/routes/auth.ts
var import_express = require("express");
var import_bcryptjs = __toESM(require("bcryptjs"));
var import_crypto = __toESM(require("crypto"));
var import_express_rate_limit = __toESM(require("express-rate-limit"));
var import_zod3 = require("zod");
var authRouter = (0, import_express.Router)();
var limiter = (0, import_express_rate_limit.default)({ windowMs: 15 * 60 * 1e3, limit: 40, standardHeaders: true, legacyHeaders: false });
authRouter.use(limiter);
var username = import_zod3.z.string().trim().min(3).max(32).regex(/^[a-zA-Z0-9_.]+$/, "\u0422\u043E\u043B\u044C\u043A\u043E \u043B\u0430\u0442\u0438\u043D\u0438\u0446\u0430, \u0446\u0438\u0444\u0440\u044B, _ \u0438 .");
var password = import_zod3.z.string().min(8, "\u041C\u0438\u043D\u0438\u043C\u0443\u043C 8 \u0441\u0438\u043C\u0432\u043E\u043B\u043E\u0432").max(128);
var publicUser = (u) => ({
  id: u.id,
  username: u.username,
  displayName: u.displayName,
  avatarUrl: u.avatarUrl,
  bannerUrl: u.bannerUrl,
  bio: u.bio,
  status: u.status === "INVISIBLE" ? "OFFLINE" : u.status
});
var selfUser = (u) => ({ ...publicUser(u), email: u.email, status: u.status });
authRouter.post("/register", ah(async (req, res) => {
  const b = import_zod3.z.object({ username, email: import_zod3.z.string().trim().toLowerCase().email().max(254), password }).parse(req.body);
  const exists = await prisma.user.findFirst({
    where: { OR: [{ username: { equals: b.username, mode: "insensitive" } }, { email: b.email }] }
  });
  if (exists) throw new HttpError(409, "\u0418\u043C\u044F \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044F \u0438\u043B\u0438 email \u0443\u0436\u0435 \u0437\u0430\u043D\u044F\u0442\u044B");
  const user = await prisma.user.create({
    data: { username: b.username, email: b.email, displayName: b.username, passwordHash: await import_bcryptjs.default.hash(b.password, 12) }
  });
  res.status(201).json({ token: signToken(user.id), user: selfUser(user) });
}));
authRouter.post("/login", ah(async (req, res) => {
  const b = import_zod3.z.object({ login: import_zod3.z.string().trim().min(1).max(254), password: import_zod3.z.string().min(1).max(128) }).parse(req.body);
  const user = await prisma.user.findFirst({
    where: { OR: [{ username: { equals: b.login, mode: "insensitive" } }, { email: b.login.toLowerCase() }] }
  });
  const ok = user ? await import_bcryptjs.default.compare(b.password, user.passwordHash) : false;
  if (!user || !ok) throw new HttpError(401, "\u041D\u0435\u0432\u0435\u0440\u043D\u044B\u0439 \u043B\u043E\u0433\u0438\u043D \u0438\u043B\u0438 \u043F\u0430\u0440\u043E\u043B\u044C");
  res.json({ token: signToken(user.id), user: selfUser(user) });
}));
authRouter.post("/forgot", ah(async (req, res) => {
  const { email } = import_zod3.z.object({ email: import_zod3.z.string().trim().toLowerCase().email() }).parse(req.body);
  const user = await prisma.user.findUnique({ where: { email } });
  if (user) {
    const raw = import_crypto.default.randomBytes(32).toString("hex");
    await prisma.passwordReset.create({
      data: { userId: user.id, tokenHash: import_crypto.default.createHash("sha256").update(raw).digest("hex"), expiresAt: new Date(Date.now() + 36e5) }
    });
    logger.info(`\u0421\u0441\u044B\u043B\u043A\u0430 \u0441\u0431\u0440\u043E\u0441\u0430 \u043F\u0430\u0440\u043E\u043B\u044F \u0434\u043B\u044F ${email}: ${config.PUBLIC_APP_URL}/?reset=${raw}`);
  }
  res.json({ ok: true });
}));
authRouter.post("/reset", ah(async (req, res) => {
  const b = import_zod3.z.object({ token: import_zod3.z.string().min(10), password }).parse(req.body);
  const tokenHash = import_crypto.default.createHash("sha256").update(b.token).digest("hex");
  const rec = await prisma.passwordReset.findUnique({ where: { tokenHash } });
  if (!rec || rec.usedAt || rec.expiresAt < /* @__PURE__ */ new Date()) throw new HttpError(400, "\u0421\u0441\u044B\u043B\u043A\u0430 \u043D\u0435\u0434\u0435\u0439\u0441\u0442\u0432\u0438\u0442\u0435\u043B\u044C\u043D\u0430 \u0438\u043B\u0438 \u0443\u0441\u0442\u0430\u0440\u0435\u043B\u0430");
  await prisma.$transaction([
    prisma.user.update({ where: { id: rec.userId }, data: { passwordHash: await import_bcryptjs.default.hash(b.password, 12) } }),
    prisma.passwordReset.update({ where: { id: rec.id }, data: { usedAt: /* @__PURE__ */ new Date() } })
  ]);
  res.json({ ok: true });
}));

// src/routes/users.ts
var import_express2 = require("express");
var import_bcryptjs2 = __toESM(require("bcryptjs"));
var import_zod4 = require("zod");
var usersRouter = (0, import_express2.Router)();
usersRouter.use(requireAuth);
usersRouter.get("/me", ah(async (req, res) => {
  const u = await prisma.user.findUnique({ where: { id: req.userId } });
  if (!u) throw new HttpError(401, "\u041F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044C \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D");
  res.json(selfUser(u));
}));
usersRouter.patch("/me", ah(async (req, res) => {
  const b = import_zod4.z.object({
    displayName: import_zod4.z.string().trim().min(1).max(40).optional(),
    bio: import_zod4.z.string().max(400).optional(),
    status: import_zod4.z.enum(["ONLINE", "DND", "IDLE", "INVISIBLE"]).optional(),
    avatarUrl: import_zod4.z.string().url().max(500).nullable().optional(),
    bannerUrl: import_zod4.z.string().url().max(500).nullable().optional()
  }).parse(req.body);
  res.json(selfUser(await prisma.user.update({ where: { id: req.userId }, data: b })));
}));
usersRouter.post("/me/password", ah(async (req, res) => {
  const b = import_zod4.z.object({ current: import_zod4.z.string().min(1), next: import_zod4.z.string().min(8).max(128) }).parse(req.body);
  const u = await prisma.user.findUniqueOrThrow({ where: { id: req.userId } });
  if (!await import_bcryptjs2.default.compare(b.current, u.passwordHash)) throw new HttpError(403, "\u041D\u0435\u0432\u0435\u0440\u043D\u044B\u0439 \u0442\u0435\u043A\u0443\u0449\u0438\u0439 \u043F\u0430\u0440\u043E\u043B\u044C");
  await prisma.user.update({ where: { id: u.id }, data: { passwordHash: await import_bcryptjs2.default.hash(b.next, 12) } });
  res.json({ ok: true });
}));
usersRouter.post("/me/email", ah(async (req, res) => {
  const b = import_zod4.z.object({ email: import_zod4.z.string().trim().toLowerCase().email(), password: import_zod4.z.string().min(1) }).parse(req.body);
  const u = await prisma.user.findUniqueOrThrow({ where: { id: req.userId } });
  if (!await import_bcryptjs2.default.compare(b.password, u.passwordHash)) throw new HttpError(403, "\u041D\u0435\u0432\u0435\u0440\u043D\u044B\u0439 \u043F\u0430\u0440\u043E\u043B\u044C");
  if (await prisma.user.findUnique({ where: { email: b.email } })) throw new HttpError(409, "Email \u0443\u0436\u0435 \u0437\u0430\u043D\u044F\u0442");
  res.json(selfUser(await prisma.user.update({ where: { id: u.id }, data: { email: b.email } })));
}));
usersRouter.get("/search", ah(async (req, res) => {
  const q = import_zod4.z.string().trim().min(2).max(32).parse(req.query.q);
  const users = await prisma.user.findMany({
    where: { username: { contains: q, mode: "insensitive" }, id: { not: req.userId } },
    take: 20
  });
  res.json(users.map(publicUser));
}));
usersRouter.get("/:id", ah(async (req, res) => {
  const u = await prisma.user.findUnique({ where: { id: req.params.id } });
  if (!u) throw new HttpError(404, "\u041F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044C \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D");
  res.json(publicUser(u));
}));
usersRouter.post("/:id/block", ah(async (req, res) => {
  if (req.params.id === req.userId) throw new HttpError(400, "\u041D\u0435\u043B\u044C\u0437\u044F \u0437\u0430\u0431\u043B\u043E\u043A\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0441\u0435\u0431\u044F");
  await prisma.user.findUniqueOrThrow({ where: { id: req.params.id } }).catch(() => {
    throw new HttpError(404, "\u041F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044C \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D");
  });
  await prisma.$transaction([
    prisma.block.upsert({
      where: { blockerId_blockedId: { blockerId: req.userId, blockedId: req.params.id } },
      create: { blockerId: req.userId, blockedId: req.params.id },
      update: {}
    }),
    prisma.friendship.deleteMany({ where: { OR: [
      { requesterId: req.userId, addresseeId: req.params.id },
      { requesterId: req.params.id, addresseeId: req.userId }
    ] } })
  ]);
  res.json({ ok: true });
}));
usersRouter.delete("/:id/block", ah(async (req, res) => {
  await prisma.block.deleteMany({ where: { blockerId: req.userId, blockedId: req.params.id } });
  res.json({ ok: true });
}));

// src/routes/friends.ts
var import_express3 = require("express");
var import_zod5 = require("zod");
var friendsRouter = (0, import_express3.Router)();
friendsRouter.use(requireAuth);
friendsRouter.get("/", ah(async (req, res) => {
  const rows = await prisma.friendship.findMany({
    where: { OR: [{ requesterId: req.userId }, { addresseeId: req.userId }] },
    include: { requester: true, addressee: true }
  });
  const blocks = await prisma.block.findMany({ where: { blockerId: req.userId }, include: { blocked: true } });
  res.json({
    friends: rows.filter((r) => r.status === "ACCEPTED").map((r) => ({ id: r.id, user: publicUser(r.requesterId === req.userId ? r.addressee : r.requester) })),
    incoming: rows.filter((r) => r.status === "PENDING" && r.addresseeId === req.userId).map((r) => ({ id: r.id, user: publicUser(r.requester) })),
    outgoing: rows.filter((r) => r.status === "PENDING" && r.requesterId === req.userId).map((r) => ({ id: r.id, user: publicUser(r.addressee) })),
    blocked: blocks.map((b) => publicUser(b.blocked))
  });
}));
friendsRouter.post("/request", ah(async (req, res) => {
  const { username: username2 } = import_zod5.z.object({ username: import_zod5.z.string().trim().min(1).max(32) }).parse(req.body);
  const target = await prisma.user.findFirst({ where: { username: { equals: username2, mode: "insensitive" } } });
  if (!target) throw new HttpError(404, "\u041F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044C \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D");
  if (target.id === req.userId) throw new HttpError(400, "\u041D\u0435\u043B\u044C\u0437\u044F \u0434\u043E\u0431\u0430\u0432\u0438\u0442\u044C \u0441\u0430\u043C\u043E\u0433\u043E \u0441\u0435\u0431\u044F");
  const blocked = await prisma.block.findFirst({ where: { OR: [
    { blockerId: req.userId, blockedId: target.id },
    { blockerId: target.id, blockedId: req.userId }
  ] } });
  if (blocked) throw new HttpError(403, "\u041D\u0435\u0432\u043E\u0437\u043C\u043E\u0436\u043D\u043E \u043E\u0442\u043F\u0440\u0430\u0432\u0438\u0442\u044C \u0437\u0430\u043F\u0440\u043E\u0441 \u044D\u0442\u043E\u043C\u0443 \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044E");
  const reverse = await prisma.friendship.findUnique({ where: { requesterId_addresseeId: { requesterId: target.id, addresseeId: req.userId } } });
  if (reverse) {
    if (reverse.status === "ACCEPTED") throw new HttpError(409, "\u0412\u044B \u0443\u0436\u0435 \u0434\u0440\u0443\u0437\u044C\u044F");
    await prisma.friendship.update({ where: { id: reverse.id }, data: { status: "ACCEPTED" } });
    emitToUser(target.id, "friends:update", {});
    return res.json({ ok: true, accepted: true });
  }
  await prisma.friendship.upsert({
    where: { requesterId_addresseeId: { requesterId: req.userId, addresseeId: target.id } },
    create: { requesterId: req.userId, addresseeId: target.id },
    update: {}
  });
  emitToUser(target.id, "friends:update", {});
  res.status(201).json({ ok: true });
}));
friendsRouter.post("/:id/accept", ah(async (req, res) => {
  const f = await prisma.friendship.findUnique({ where: { id: req.params.id } });
  if (!f || f.addresseeId !== req.userId || f.status !== "PENDING") throw new HttpError(404, "\u0417\u0430\u043F\u0440\u043E\u0441 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D");
  await prisma.friendship.update({ where: { id: f.id }, data: { status: "ACCEPTED" } });
  emitToUser(f.requesterId, "friends:update", {});
  res.json({ ok: true });
}));
friendsRouter.delete("/:id", ah(async (req, res) => {
  const f = await prisma.friendship.findUnique({ where: { id: req.params.id } });
  if (!f || f.requesterId !== req.userId && f.addresseeId !== req.userId) throw new HttpError(404, "\u041D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u043E");
  await prisma.friendship.delete({ where: { id: f.id } });
  emitToUser(f.requesterId === req.userId ? f.addresseeId : f.requesterId, "friends:update", {});
  res.json({ ok: true });
}));

// src/routes/servers.ts
var import_express4 = require("express");
var import_crypto2 = __toESM(require("crypto"));
var import_zod6 = require("zod");
var serversRouter = (0, import_express4.Router)();
var invitesRouter = (0, import_express4.Router)();
serversRouter.use(requireAuth);
invitesRouter.use(requireAuth);
var name = import_zod6.z.string().trim().min(1).max(100);
var serverView = async (serverId, userId) => {
  const s = await prisma.server.findUnique({
    where: { id: serverId },
    include: {
      channels: { orderBy: [{ type: "asc" }, { position: "asc" }, { createdAt: "asc" }] },
      roles: { orderBy: { position: "desc" } },
      members: { include: { user: true, roles: true } }
    }
  });
  if (!s) throw new HttpError(404, "\u0421\u0435\u0440\u0432\u0435\u0440 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D");
  return {
    id: s.id,
    name: s.name,
    description: s.description,
    iconUrl: s.iconUrl,
    ownerId: s.ownerId,
    myPermissions: await getPerms(userId, serverId),
    channels: s.channels,
    roles: s.roles,
    members: s.members.map((m) => ({
      user: { ...publicUser(m.user), status: isOnline(m.userId) && m.user.status !== "INVISIBLE" ? m.user.status : "OFFLINE" },
      nickname: m.nickname,
      roleIds: m.roles.map((r) => r.roleId),
      joinedAt: m.joinedAt
    }))
  };
};
serversRouter.get("/", ah(async (req, res) => {
  const rows = await prisma.member.findMany({ where: { userId: req.userId }, include: { server: true } });
  res.json(rows.map((r) => ({ id: r.server.id, name: r.server.name, iconUrl: r.server.iconUrl, ownerId: r.server.ownerId })));
}));
serversRouter.post("/", ah(async (req, res) => {
  const b = import_zod6.z.object({ name, description: import_zod6.z.string().max(300).optional(), iconUrl: import_zod6.z.string().url().max(500).optional() }).parse(req.body);
  const server2 = await prisma.$transaction(async (tx) => {
    const s = await tx.server.create({ data: { name: b.name, description: b.description, iconUrl: b.iconUrl, ownerId: req.userId } });
    await tx.role.create({ data: { serverId: s.id, name: "@everyone", isDefault: true, permissions: DEFAULT_PERMS } });
    await tx.member.create({ data: { userId: req.userId, serverId: s.id } });
    await tx.channel.createMany({ data: [
      { serverId: s.id, name: "\u043E\u0431\u0449\u0438\u0439", type: "TEXT", position: 0 },
      { serverId: s.id, name: "\u0413\u043E\u043B\u043E\u0441\u043E\u0432\u043E\u0439", type: "VOICE", position: 0 }
    ] });
    return s;
  });
  joinServerRoom(req.userId, server2.id);
  res.status(201).json(await serverView(server2.id, req.userId));
}));
serversRouter.get("/:id", ah(async (req, res) => {
  if (await getPerms(req.userId, req.params.id) === null) throw new HttpError(403, "\u0412\u044B \u043D\u0435 \u0443\u0447\u0430\u0441\u0442\u043D\u0438\u043A \u044D\u0442\u043E\u0433\u043E \u0441\u0435\u0440\u0432\u0435\u0440\u0430");
  res.json(await serverView(req.params.id, req.userId));
}));
serversRouter.patch("/:id", ah(async (req, res) => {
  await requirePerm(req.userId, req.params.id, P.MANAGE_SERVER);
  const b = import_zod6.z.object({ name: name.optional(), description: import_zod6.z.string().max(300).nullable().optional(), iconUrl: import_zod6.z.string().url().max(500).nullable().optional() }).parse(req.body);
  await prisma.server.update({ where: { id: req.params.id }, data: b });
  emitToServer(req.params.id, "server:update", { serverId: req.params.id });
  res.json(await serverView(req.params.id, req.userId));
}));
serversRouter.delete("/:id", ah(async (req, res) => {
  const s = await prisma.server.findUnique({ where: { id: req.params.id } });
  if (!s) throw new HttpError(404, "\u0421\u0435\u0440\u0432\u0435\u0440 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D");
  if (s.ownerId !== req.userId) throw new HttpError(403, "\u0423\u0434\u0430\u043B\u0438\u0442\u044C \u0441\u0435\u0440\u0432\u0435\u0440 \u043C\u043E\u0436\u0435\u0442 \u0442\u043E\u043B\u044C\u043A\u043E \u0432\u043B\u0430\u0434\u0435\u043B\u0435\u0446");
  emitToServer(s.id, "server:deleted", { serverId: s.id });
  await prisma.server.delete({ where: { id: s.id } });
  res.json({ ok: true });
}));
serversRouter.post("/:id/leave", ah(async (req, res) => {
  const s = await prisma.server.findUnique({ where: { id: req.params.id } });
  if (!s) throw new HttpError(404, "\u0421\u0435\u0440\u0432\u0435\u0440 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D");
  if (s.ownerId === req.userId) throw new HttpError(400, "\u0412\u043B\u0430\u0434\u0435\u043B\u0435\u0446 \u043D\u0435 \u043C\u043E\u0436\u0435\u0442 \u043F\u043E\u043A\u0438\u043D\u0443\u0442\u044C \u0441\u0435\u0440\u0432\u0435\u0440 \u2014 \u0443\u0434\u0430\u043B\u0438\u0442\u0435 \u0435\u0433\u043E \u0438\u043B\u0438 \u043F\u0435\u0440\u0435\u0434\u0430\u0439\u0442\u0435 \u0432\u043B\u0430\u0434\u0435\u043D\u0438\u0435");
  await prisma.member.deleteMany({ where: { userId: req.userId, serverId: s.id } });
  leaveServerRoom(req.userId, s.id);
  emitToServer(s.id, "members:update", { serverId: s.id });
  res.json({ ok: true });
}));
var channelBody = import_zod6.z.object({ name: import_zod6.z.string().trim().min(1).max(60), type: import_zod6.z.enum(["TEXT", "VOICE"]).default("TEXT"), topic: import_zod6.z.string().max(300).optional() });
serversRouter.post("/:id/channels", ah(async (req, res) => {
  await requirePerm(req.userId, req.params.id, P.MANAGE_CHANNELS);
  const b = channelBody.parse(req.body);
  const count = await prisma.channel.count({ where: { serverId: req.params.id, type: b.type } });
  const ch = await prisma.channel.create({ data: { ...b, serverId: req.params.id, position: count } });
  emitToServer(req.params.id, "channels:update", { serverId: req.params.id });
  res.status(201).json(ch);
}));
serversRouter.patch("/:id/channels/:channelId", ah(async (req, res) => {
  await requirePerm(req.userId, req.params.id, P.MANAGE_CHANNELS);
  const b = channelBody.partial().omit({ type: true }).parse(req.body);
  const ch = await prisma.channel.findFirst({ where: { id: req.params.channelId, serverId: req.params.id } });
  if (!ch) throw new HttpError(404, "\u041A\u0430\u043D\u0430\u043B \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D");
  const upd = await prisma.channel.update({ where: { id: ch.id }, data: b });
  emitToServer(req.params.id, "channels:update", { serverId: req.params.id });
  res.json(upd);
}));
serversRouter.delete("/:id/channels/:channelId", ah(async (req, res) => {
  await requirePerm(req.userId, req.params.id, P.MANAGE_CHANNELS);
  const r = await prisma.channel.deleteMany({ where: { id: req.params.channelId, serverId: req.params.id } });
  if (!r.count) throw new HttpError(404, "\u041A\u0430\u043D\u0430\u043B \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D");
  emitToServer(req.params.id, "channels:update", { serverId: req.params.id });
  res.json({ ok: true });
}));
var roleBody = import_zod6.z.object({
  name: import_zod6.z.string().trim().min(1).max(40),
  color: import_zod6.z.number().int().min(0).max(16777215),
  permissions: import_zod6.z.number().int().min(0).max(ALL)
});
serversRouter.post("/:id/roles", ah(async (req, res) => {
  await requirePerm(req.userId, req.params.id, P.MANAGE_ROLES);
  const b = roleBody.partial({ color: true, permissions: true }).parse(req.body);
  const count = await prisma.role.count({ where: { serverId: req.params.id } });
  const role = await prisma.role.create({ data: { serverId: req.params.id, name: b.name, color: b.color ?? 0, permissions: b.permissions ?? 0, position: count } });
  emitToServer(req.params.id, "server:update", { serverId: req.params.id });
  res.status(201).json(role);
}));
serversRouter.patch("/:id/roles/:roleId", ah(async (req, res) => {
  await requirePerm(req.userId, req.params.id, P.MANAGE_ROLES);
  const b = roleBody.partial().parse(req.body);
  const role = await prisma.role.findFirst({ where: { id: req.params.roleId, serverId: req.params.id } });
  if (!role) throw new HttpError(404, "\u0420\u043E\u043B\u044C \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u0430");
  const mine = await getPerms(req.userId, req.params.id);
  if (b.permissions !== void 0 && !has(mine, b.permissions)) throw new HttpError(403, "\u041D\u0435\u043B\u044C\u0437\u044F \u0432\u044B\u0434\u0430\u0442\u044C \u043F\u0440\u0430\u0432\u0430, \u043A\u043E\u0442\u043E\u0440\u044B\u0445 \u0443 \u0432\u0430\u0441 \u043D\u0435\u0442");
  const upd = await prisma.role.update({ where: { id: role.id }, data: { ...b, ...role.isDefault ? { name: "@everyone" } : {} } });
  emitToServer(req.params.id, "server:update", { serverId: req.params.id });
  res.json(upd);
}));
serversRouter.delete("/:id/roles/:roleId", ah(async (req, res) => {
  await requirePerm(req.userId, req.params.id, P.MANAGE_ROLES);
  const role = await prisma.role.findFirst({ where: { id: req.params.roleId, serverId: req.params.id } });
  if (!role) throw new HttpError(404, "\u0420\u043E\u043B\u044C \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u0430");
  if (role.isDefault) throw new HttpError(400, "\u041D\u0435\u043B\u044C\u0437\u044F \u0443\u0434\u0430\u043B\u0438\u0442\u044C \u0440\u043E\u043B\u044C @everyone");
  await prisma.role.delete({ where: { id: role.id } });
  emitToServer(req.params.id, "server:update", { serverId: req.params.id });
  res.json({ ok: true });
}));
async function assertCanManageMember(actorId, serverId, targetId) {
  const s = await prisma.server.findUniqueOrThrow({ where: { id: serverId } });
  if (targetId === s.ownerId) throw new HttpError(403, "\u041D\u0435\u043B\u044C\u0437\u044F \u0434\u0435\u0439\u0441\u0442\u0432\u043E\u0432\u0430\u0442\u044C \u043F\u0440\u043E\u0442\u0438\u0432 \u0432\u043B\u0430\u0434\u0435\u043B\u044C\u0446\u0430");
  if (targetId === actorId) throw new HttpError(400, "\u041D\u0435\u043B\u044C\u0437\u044F \u043F\u0440\u0438\u043C\u0435\u043D\u0438\u0442\u044C \u043A \u0441\u0435\u0431\u0435");
  const tp = await getPerms(targetId, serverId);
  if (tp !== null && (tp & P.ADMIN || tp === ALL) && s.ownerId !== actorId) throw new HttpError(403, "\u041D\u0435\u043B\u044C\u0437\u044F \u0434\u0435\u0439\u0441\u0442\u0432\u043E\u0432\u0430\u0442\u044C \u043F\u0440\u043E\u0442\u0438\u0432 \u0430\u0434\u043C\u0438\u043D\u0438\u0441\u0442\u0440\u0430\u0442\u043E\u0440\u0430");
}
serversRouter.put("/:id/members/:userId/roles/:roleId", ah(async (req, res) => {
  await requirePerm(req.userId, req.params.id, P.MANAGE_ROLES);
  const role = await prisma.role.findFirst({ where: { id: req.params.roleId, serverId: req.params.id, isDefault: false } });
  if (!role) throw new HttpError(404, "\u0420\u043E\u043B\u044C \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u0430");
  if (!has(await getPerms(req.userId, req.params.id), role.permissions)) throw new HttpError(403, "\u041D\u0435\u043B\u044C\u0437\u044F \u0432\u044B\u0434\u0430\u0442\u044C \u0440\u043E\u043B\u044C \u0441 \u043F\u0440\u0430\u0432\u0430\u043C\u0438, \u043A\u043E\u0442\u043E\u0440\u044B\u0445 \u0443 \u0432\u0430\u0441 \u043D\u0435\u0442");
  const m = await prisma.member.findUnique({ where: { userId_serverId: { userId: req.params.userId, serverId: req.params.id } } });
  if (!m) throw new HttpError(404, "\u0423\u0447\u0430\u0441\u0442\u043D\u0438\u043A \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D");
  await prisma.memberRole.upsert({
    where: { userId_serverId_roleId: { userId: m.userId, serverId: m.serverId, roleId: role.id } },
    create: { userId: m.userId, serverId: m.serverId, roleId: role.id },
    update: {}
  });
  emitToServer(req.params.id, "members:update", { serverId: req.params.id });
  res.json({ ok: true });
}));
serversRouter.delete("/:id/members/:userId/roles/:roleId", ah(async (req, res) => {
  await requirePerm(req.userId, req.params.id, P.MANAGE_ROLES);
  await prisma.memberRole.deleteMany({ where: { userId: req.params.userId, serverId: req.params.id, roleId: req.params.roleId } });
  emitToServer(req.params.id, "members:update", { serverId: req.params.id });
  res.json({ ok: true });
}));
serversRouter.delete("/:id/members/:userId", ah(async (req, res) => {
  await requirePerm(req.userId, req.params.id, P.KICK);
  await assertCanManageMember(req.userId, req.params.id, req.params.userId);
  await prisma.member.deleteMany({ where: { userId: req.params.userId, serverId: req.params.id } });
  leaveServerRoom(req.params.userId, req.params.id);
  emitToUser(req.params.userId, "server:removed", { serverId: req.params.id });
  emitToServer(req.params.id, "members:update", { serverId: req.params.id });
  res.json({ ok: true });
}));
serversRouter.post("/:id/bans/:userId", ah(async (req, res) => {
  await requirePerm(req.userId, req.params.id, P.BAN);
  await assertCanManageMember(req.userId, req.params.id, req.params.userId);
  const { reason } = import_zod6.z.object({ reason: import_zod6.z.string().max(200).optional() }).parse(req.body ?? {});
  await prisma.$transaction([
    prisma.member.deleteMany({ where: { userId: req.params.userId, serverId: req.params.id } }),
    prisma.ban.upsert({
      where: { serverId_userId: { serverId: req.params.id, userId: req.params.userId } },
      create: { serverId: req.params.id, userId: req.params.userId, reason },
      update: { reason }
    })
  ]);
  leaveServerRoom(req.params.userId, req.params.id);
  emitToUser(req.params.userId, "server:removed", { serverId: req.params.id });
  emitToServer(req.params.id, "members:update", { serverId: req.params.id });
  res.json({ ok: true });
}));
serversRouter.delete("/:id/bans/:userId", ah(async (req, res) => {
  await requirePerm(req.userId, req.params.id, P.BAN);
  await prisma.ban.deleteMany({ where: { serverId: req.params.id, userId: req.params.userId } });
  res.json({ ok: true });
}));
serversRouter.post("/:id/invites", ah(async (req, res) => {
  await requirePerm(req.userId, req.params.id, P.CREATE_INVITE);
  const b = import_zod6.z.object({ maxUses: import_zod6.z.number().int().min(1).max(1e3).optional(), expiresInHours: import_zod6.z.number().min(1).max(24 * 365).optional() }).parse(req.body ?? {});
  const invite = await prisma.invite.create({ data: {
    code: import_crypto2.default.randomBytes(6).toString("base64url"),
    serverId: req.params.id,
    creatorId: req.userId,
    maxUses: b.maxUses,
    expiresAt: b.expiresInHours ? new Date(Date.now() + b.expiresInHours * 36e5) : null
  } });
  res.status(201).json(invite);
}));
invitesRouter.post("/:code/join", ah(async (req, res) => {
  const inv = await prisma.invite.findUnique({ where: { code: req.params.code } });
  if (!inv || inv.expiresAt && inv.expiresAt < /* @__PURE__ */ new Date() || inv.maxUses !== null && inv.uses >= inv.maxUses)
    throw new HttpError(404, "\u041F\u0440\u0438\u0433\u043B\u0430\u0448\u0435\u043D\u0438\u0435 \u043D\u0435\u0434\u0435\u0439\u0441\u0442\u0432\u0438\u0442\u0435\u043B\u044C\u043D\u043E");
  if (await prisma.ban.findUnique({ where: { serverId_userId: { serverId: inv.serverId, userId: req.userId } } }))
    throw new HttpError(403, "\u0412\u044B \u0437\u0430\u0431\u043B\u043E\u043A\u0438\u0440\u043E\u0432\u0430\u043D\u044B \u043D\u0430 \u044D\u0442\u043E\u043C \u0441\u0435\u0440\u0432\u0435\u0440\u0435");
  const already = await prisma.member.findUnique({ where: { userId_serverId: { userId: req.userId, serverId: inv.serverId } } });
  if (!already) {
    await prisma.$transaction([
      prisma.member.create({ data: { userId: req.userId, serverId: inv.serverId } }),
      prisma.invite.update({ where: { code: inv.code }, data: { uses: { increment: 1 } } })
    ]);
    joinServerRoom(req.userId, inv.serverId);
    emitToServer(inv.serverId, "members:update", { serverId: inv.serverId });
  }
  res.json(await serverView(inv.serverId, req.userId));
}));

// src/routes/messages.ts
var import_express5 = require("express");
var import_express_rate_limit2 = __toESM(require("express-rate-limit"));
var import_zod7 = require("zod");
var messagesRouter = (0, import_express5.Router)();
messagesRouter.use(requireAuth);
var include = { author: true, replyTo: { include: { author: true } }, reactions: true, mentions: true };
var kindSchema = import_zod7.z.enum(["channel", "dm"]);
var idParams = import_zod7.z.object({ kind: kindSchema, id: import_zod7.z.string().min(1) });
function view(m) {
  const rx = /* @__PURE__ */ new Map();
  for (const r of m.reactions) rx.set(r.emoji, [...rx.get(r.emoji) ?? [], r.userId]);
  return {
    id: m.id,
    channelId: m.channelId,
    dmId: m.dmId,
    author: publicUser(m.author),
    content: m.content,
    replyTo: m.replyTo ? { id: m.replyTo.id, content: String(m.replyTo.content).slice(0, 120), author: publicUser(m.replyTo.author) } : null,
    createdAt: m.createdAt,
    editedAt: m.editedAt,
    pinned: m.pinned,
    reactions: [...rx].map(([emoji, userIds]) => ({ emoji, userIds })),
    mentions: m.mentions.map((x) => x.userId)
  };
}
var whereTarget = (kind, id) => kind === "channel" ? { channelId: id } : { dmId: id };
var targetOf = (m) => m.channelId ? { kind: "channel", id: m.channelId } : { kind: "dm", id: m.dmId };
async function resolveMentions(content, t, authorId) {
  const names = [...new Set([...content.matchAll(/@([a-zA-Z0-9_.]{3,32})/g)].map((m) => m[1].toLowerCase()))].slice(0, 20);
  if (!names.length) return [];
  const users = await prisma.user.findMany({
    where: { OR: names.map((n) => ({ username: { equals: n, mode: "insensitive" } })) },
    select: { id: true }
  });
  let ids = users.map((u) => u.id).filter((id) => id !== authorId);
  if (t.kind === "dm") return ids.filter((id) => t.memberIds.includes(id));
  const ms = await prisma.member.findMany({ where: { serverId: t.serverId, userId: { in: ids } }, select: { userId: true } });
  return ms.map((m) => m.userId);
}
var sendLimiter = (0, import_express_rate_limit2.default)({
  windowMs: 1e4,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => String(req.userId),
  message: { error: "\u0421\u043B\u0438\u0448\u043A\u043E\u043C \u043C\u043D\u043E\u0433\u043E \u0441\u043E\u043E\u0431\u0449\u0435\u043D\u0438\u0439, \u043F\u043E\u0434\u043E\u0436\u0434\u0438\u0442\u0435" }
});
var key = (kind, id) => `${kind}:${id}`;
var markRead = (userId, k) => prisma.readState.upsert({
  where: { userId_targetKey: { userId, targetKey: k } },
  create: { userId, targetKey: k, lastReadAt: /* @__PURE__ */ new Date() },
  update: { lastReadAt: /* @__PURE__ */ new Date() }
});
messagesRouter.get("/unread", ah(async (req, res) => {
  const userId = req.userId;
  const [members, dmMembers, reads] = await Promise.all([
    prisma.member.findMany({ where: { userId }, include: { server: { include: { channels: { where: { type: "TEXT" }, select: { id: true, serverId: true } } } } } }),
    prisma.dmMember.findMany({ where: { userId } }),
    prisma.readState.findMany({ where: { userId } })
  ]);
  const readMap = new Map(reads.map((r) => [r.targetKey, r.lastReadAt]));
  const out = {};
  const jobs = [];
  const add = (k, where, since, serverId) => jobs.push((async () => {
    const after = readMap.get(k) ?? since;
    const [count, mentions] = await Promise.all([
      prisma.message.count({ where: { ...where, authorId: { not: userId }, createdAt: { gt: after } } }),
      prisma.mention.count({ where: { userId, message: { ...where, createdAt: { gt: after } } } })
    ]);
    if (count) out[k] = { count, mentions, serverId };
  })());
  for (const m of members) for (const c of m.server.channels) add(key("channel", c.id), { channelId: c.id }, m.joinedAt, c.serverId);
  for (const d of dmMembers) add(key("dm", d.dmId), { dmId: d.dmId }, d.joinedAt);
  await Promise.all(jobs);
  res.json(out);
}));
messagesRouter.get("/search", ah(async (req, res) => {
  const q = import_zod7.z.object({ q: import_zod7.z.string().trim().min(2).max(100), scope: import_zod7.z.string().optional() }).parse(req.query);
  const userId = req.userId;
  const [members, dmMembers] = await Promise.all([
    prisma.member.findMany({ where: { userId }, include: { server: { include: { channels: { where: { type: "TEXT" } } } } } }),
    prisma.dmMember.findMany({ where: { userId }, select: { dmId: true } })
  ]);
  const chInfo = /* @__PURE__ */ new Map();
  for (const m of members) for (const c of m.server.channels) chInfo.set(c.id, `${m.server.name} \u203A #${c.name}`);
  let chIds = [...chInfo.keys()], dmIds = dmMembers.map((d) => d.dmId);
  if (q.scope) {
    const [k, id] = q.scope.split(":");
    if (k === "channel") {
      chIds = chIds.filter((x) => x === id);
      dmIds = [];
    } else if (k === "dm") {
      dmIds = dmIds.filter((x) => x === id);
      chIds = [];
    }
  }
  const rows = await prisma.message.findMany({
    where: { content: { contains: q.q, mode: "insensitive" }, OR: [{ channelId: { in: chIds } }, { dmId: { in: dmIds } }] },
    orderBy: { createdAt: "desc" },
    take: 30,
    include
  });
  res.json(rows.map((r) => ({ ...view(r), where: r.channelId ? chInfo.get(r.channelId) ?? "" : "\u041B\u0438\u0447\u043D\u044B\u0435 \u0441\u043E\u043E\u0431\u0449\u0435\u043D\u0438\u044F" })));
}));
async function loadItem(userId, msgId) {
  const m = await prisma.message.findUnique({ where: { id: msgId }, include });
  if (!m) throw new HttpError(404, "\u0421\u043E\u043E\u0431\u0449\u0435\u043D\u0438\u0435 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u043E");
  const { kind, id } = targetOf(m);
  const t = await resolveTarget(userId, kind, id);
  return { m, t };
}
var broadcastUpdate = async (t, msgId) => {
  const m = await prisma.message.findUniqueOrThrow({ where: { id: msgId }, include });
  const v = view(m);
  emitToTarget(t, "message:update", { kind: t.kind, id: t.id, serverId: t.serverId, message: v });
  return v;
};
messagesRouter.patch("/item/:msgId", ah(async (req, res) => {
  const { content } = import_zod7.z.object({ content: import_zod7.z.string().trim().min(1).max(4e3) }).parse(req.body);
  const { m, t } = await loadItem(req.userId, req.params.msgId);
  if (m.authorId !== req.userId) throw new HttpError(403, "\u041C\u043E\u0436\u043D\u043E \u0440\u0435\u0434\u0430\u043A\u0442\u0438\u0440\u043E\u0432\u0430\u0442\u044C \u0442\u043E\u043B\u044C\u043A\u043E \u0441\u0432\u043E\u0438 \u0441\u043E\u043E\u0431\u0449\u0435\u043D\u0438\u044F");
  const mentionIds = await resolveMentions(content, t, req.userId);
  await prisma.$transaction([
    prisma.mention.deleteMany({ where: { messageId: m.id } }),
    prisma.message.update({ where: { id: m.id }, data: { content, editedAt: /* @__PURE__ */ new Date(), mentions: { create: mentionIds.map((userId) => ({ userId })) } } })
  ]);
  res.json(await broadcastUpdate(t, m.id));
}));
messagesRouter.delete("/item/:msgId", ah(async (req, res) => {
  const { m, t } = await loadItem(req.userId, req.params.msgId);
  if (m.authorId !== req.userId && !canModerate(t)) throw new HttpError(403, "\u041D\u0435\u0434\u043E\u0441\u0442\u0430\u0442\u043E\u0447\u043D\u043E \u043F\u0440\u0430\u0432");
  await prisma.message.delete({ where: { id: m.id } });
  emitToTarget(t, "message:delete", { kind: t.kind, id: t.id, serverId: t.serverId, messageId: m.id });
  res.json({ ok: true });
}));
var emojiSchema = import_zod7.z.string().min(1).max(16).regex(new RegExp("\\p{Extended_Pictographic}", "u"), "\u041D\u0443\u0436\u0435\u043D \u044D\u043C\u043E\u0434\u0437\u0438");
messagesRouter.put("/item/:msgId/reactions/:emoji", ah(async (req, res) => {
  const emoji = emojiSchema.parse(req.params.emoji);
  const { m, t } = await loadItem(req.userId, req.params.msgId);
  const kinds = await prisma.reaction.findMany({ where: { messageId: m.id }, distinct: ["emoji"], select: { emoji: true } });
  if (kinds.length >= 20 && !kinds.some((k) => k.emoji === emoji)) throw new HttpError(400, "\u0421\u043B\u0438\u0448\u043A\u043E\u043C \u043C\u043D\u043E\u0433\u043E \u0440\u0430\u0437\u043D\u044B\u0445 \u0440\u0435\u0430\u043A\u0446\u0438\u0439");
  await prisma.reaction.upsert({
    where: { messageId_userId_emoji: { messageId: m.id, userId: req.userId, emoji } },
    create: { messageId: m.id, userId: req.userId, emoji },
    update: {}
  });
  res.json(await broadcastUpdate(t, m.id));
}));
messagesRouter.delete("/item/:msgId/reactions/:emoji", ah(async (req, res) => {
  const { m, t } = await loadItem(req.userId, req.params.msgId);
  await prisma.reaction.deleteMany({ where: { messageId: m.id, userId: req.userId, emoji: req.params.emoji } });
  res.json(await broadcastUpdate(t, m.id));
}));
var setPin = (pinned) => ah(async (req, res) => {
  const { m, t } = await loadItem(req.userId, req.params.msgId);
  if (t.kind === "channel" && !canModerate(t)) throw new HttpError(403, "\u0417\u0430\u043A\u0440\u0435\u043F\u043B\u044F\u0442\u044C \u0441\u043E\u043E\u0431\u0449\u0435\u043D\u0438\u044F \u043C\u043E\u0433\u0443\u0442 \u0442\u043E\u043B\u044C\u043A\u043E \u043C\u043E\u0434\u0435\u0440\u0430\u0442\u043E\u0440\u044B");
  if (pinned) {
    const n = await prisma.message.count({ where: { ...whereTarget(t.kind, t.id), pinned: true } });
    if (n >= 50) throw new HttpError(400, "\u041C\u0430\u043A\u0441\u0438\u043C\u0443\u043C 50 \u0437\u0430\u043A\u0440\u0435\u043F\u043B\u0451\u043D\u043D\u044B\u0445 \u0441\u043E\u043E\u0431\u0449\u0435\u043D\u0438\u0439");
  }
  await prisma.message.update({ where: { id: m.id }, data: { pinned, pinnedAt: pinned ? /* @__PURE__ */ new Date() : null } });
  res.json(await broadcastUpdate(t, m.id));
});
messagesRouter.put("/item/:msgId/pin", setPin(true));
messagesRouter.delete("/item/:msgId/pin", setPin(false));
messagesRouter.get("/:kind/:id/pins", ah(async (req, res) => {
  const { kind, id } = idParams.parse(req.params);
  await resolveTarget(req.userId, kind, id);
  const rows = await prisma.message.findMany({ where: { ...whereTarget(kind, id), pinned: true }, orderBy: { pinnedAt: "desc" }, include });
  res.json(rows.map(view));
}));
messagesRouter.post("/:kind/:id/read", ah(async (req, res) => {
  const { kind, id } = idParams.parse(req.params);
  await resolveTarget(req.userId, kind, id);
  await markRead(req.userId, key(kind, id));
  res.json({ ok: true });
}));
messagesRouter.get("/:kind/:id", ah(async (req, res) => {
  const { kind, id } = idParams.parse(req.params);
  const q = import_zod7.z.object({ before: import_zod7.z.string().optional(), limit: import_zod7.z.coerce.number().int().min(1).max(100).default(50) }).parse(req.query);
  await resolveTarget(req.userId, kind, id);
  const rows = await prisma.message.findMany({
    where: whereTarget(kind, id),
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    take: q.limit + 1,
    ...q.before ? { cursor: { id: q.before }, skip: 1 } : {},
    include
  });
  res.json({ messages: rows.slice(0, q.limit).reverse().map(view), hasMore: rows.length > q.limit });
}));
messagesRouter.post("/:kind/:id", sendLimiter, ah(async (req, res) => {
  const { kind, id } = idParams.parse(req.params);
  const b = import_zod7.z.object({ content: import_zod7.z.string().trim().min(1).max(4e3), replyToId: import_zod7.z.string().optional() }).parse(req.body);
  const t = await resolveTarget(req.userId, kind, id);
  if (!canSend(t)) throw new HttpError(403, "\u0423 \u0432\u0430\u0441 \u043D\u0435\u0442 \u043F\u0440\u0430\u0432\u0430 \u043F\u0438\u0441\u0430\u0442\u044C \u0432 \u044D\u0442\u043E\u0442 \u043A\u0430\u043D\u0430\u043B");
  if (t.kind === "dm" && !t.isGroup) {
    const other = t.memberIds.find((x) => x !== req.userId);
    if (other && await prisma.block.findFirst({ where: { OR: [{ blockerId: req.userId, blockedId: other }, { blockerId: other, blockedId: req.userId }] } }))
      throw new HttpError(403, "\u041D\u0435\u0432\u043E\u0437\u043C\u043E\u0436\u043D\u043E \u043E\u0442\u043F\u0440\u0430\u0432\u0438\u0442\u044C \u0441\u043E\u043E\u0431\u0449\u0435\u043D\u0438\u0435 \u044D\u0442\u043E\u043C\u0443 \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044E");
  }
  if (b.replyToId) {
    const r = await prisma.message.findUnique({ where: { id: b.replyToId } });
    if (!r || (kind === "channel" ? r.channelId !== id : r.dmId !== id)) throw new HttpError(400, "\u0421\u043E\u043E\u0431\u0449\u0435\u043D\u0438\u0435 \u0434\u043B\u044F \u043E\u0442\u0432\u0435\u0442\u0430 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u043E");
  }
  const mentionIds = await resolveMentions(b.content, t, req.userId);
  const m = await prisma.message.create({
    data: {
      channelId: kind === "channel" ? id : null,
      dmId: kind === "dm" ? id : null,
      authorId: req.userId,
      content: b.content,
      replyToId: b.replyToId ?? null,
      mentions: { create: mentionIds.map((userId) => ({ userId })) }
    },
    include
  });
  if (kind === "dm") await prisma.dmChannel.update({ where: { id }, data: { lastMessageAt: m.createdAt } });
  await markRead(req.userId, key(kind, id));
  const v = view(m);
  emitToTarget(t, "message:new", { kind, id, serverId: t.serverId, message: v });
  for (const uid of mentionIds) emitToUser(uid, "mention", { kind, id, serverId: t.serverId, messageId: m.id });
  res.status(201).json(v);
}));

// src/routes/dms.ts
var import_express6 = require("express");
var import_zod8 = require("zod");
var dmsRouter = (0, import_express6.Router)();
dmsRouter.use(requireAuth);
var include2 = { members: { include: { user: true } }, messages: { orderBy: { createdAt: "desc" }, take: 1 } };
var dmView = (dm) => ({
  id: dm.id,
  isGroup: dm.isGroup,
  name: dm.name,
  ownerId: dm.ownerId,
  lastMessageAt: dm.lastMessageAt,
  members: dm.members.map((m) => publicUser(m.user)),
  lastMessage: dm.messages?.[0] ? { content: String(dm.messages[0].content).slice(0, 80), authorId: dm.messages[0].authorId } : null
});
var notify = (dm) => dm.members.forEach((m) => emitToUser(m.userId, "dms:update", {}));
dmsRouter.get("/", ah(async (req, res) => {
  const rows = await prisma.dmChannel.findMany({
    where: { members: { some: { userId: req.userId } } },
    orderBy: { lastMessageAt: "desc" },
    include: include2
  });
  res.json(rows.map(dmView));
}));
dmsRouter.post("/", ah(async (req, res) => {
  const b = import_zod8.z.object({ userIds: import_zod8.z.array(import_zod8.z.string()).min(1).max(9), name: import_zod8.z.string().trim().max(60).optional() }).parse(req.body);
  const ids = [...new Set(b.userIds)].filter((x) => x !== req.userId);
  if (!ids.length) throw new HttpError(400, "\u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0441\u043E\u0431\u0435\u0441\u0435\u0434\u043D\u0438\u043A\u0430");
  const users = await prisma.user.findMany({ where: { id: { in: ids } }, select: { id: true } });
  if (users.length !== ids.length) throw new HttpError(404, "\u041F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u044C \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D");
  const blocked = await prisma.block.findFirst({ where: { OR: [
    { blockerId: req.userId, blockedId: { in: ids } },
    { blockerId: { in: ids }, blockedId: req.userId }
  ] } });
  if (blocked) throw new HttpError(403, "\u041D\u0435\u0432\u043E\u0437\u043C\u043E\u0436\u043D\u043E \u043D\u0430\u0447\u0430\u0442\u044C \u0434\u0438\u0430\u043B\u043E\u0433 \u0441 \u044D\u0442\u0438\u043C \u043F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u0435\u043C");
  if (ids.length === 1) {
    const existing = await prisma.dmChannel.findFirst({
      where: { isGroup: false, AND: [{ members: { some: { userId: req.userId } } }, { members: { some: { userId: ids[0] } } }] },
      include: include2
    });
    if (existing) return res.json(dmView(existing));
  }
  const dm = await prisma.dmChannel.create({
    data: {
      isGroup: ids.length > 1,
      name: ids.length > 1 ? b.name ?? null : null,
      ownerId: ids.length > 1 ? req.userId : null,
      members: { create: [req.userId, ...ids].map((userId) => ({ userId })) }
    },
    include: include2
  });
  notify(dm);
  res.status(201).json(dmView(dm));
}));
dmsRouter.patch("/:id", ah(async (req, res) => {
  const { name: name2 } = import_zod8.z.object({ name: import_zod8.z.string().trim().min(1).max(60) }).parse(req.body);
  const dm = await prisma.dmChannel.findUnique({ where: { id: req.params.id }, include: include2 });
  if (!dm || !dm.isGroup || !dm.members.some((m) => m.userId === req.userId)) throw new HttpError(404, "\u0414\u0438\u0430\u043B\u043E\u0433 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D");
  const upd = await prisma.dmChannel.update({ where: { id: dm.id }, data: { name: name2 }, include: include2 });
  notify(upd);
  res.json(dmView(upd));
}));
dmsRouter.post("/:id/leave", ah(async (req, res) => {
  const dm = await prisma.dmChannel.findUnique({ where: { id: req.params.id }, include: include2 });
  if (!dm || !dm.isGroup || !dm.members.some((m) => m.userId === req.userId)) throw new HttpError(404, "\u0413\u0440\u0443\u043F\u043F\u0430 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u0430");
  await prisma.dmMember.delete({ where: { dmId_userId: { dmId: dm.id, userId: req.userId } } });
  if (dm.members.length <= 1) await prisma.dmChannel.delete({ where: { id: dm.id } });
  notify(dm);
  res.json({ ok: true });
}));

// src/index.ts
var app = (0, import_express7.default)();
app.set("trust proxy", 1);
app.use((0, import_helmet.default)({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use((0, import_cors.default)({ origin: corsOrigin }));
app.use(import_express7.default.json({ limit: "1mb" }));
app.use((0, import_express_rate_limit3.default)({ windowMs: 6e4, limit: 300, standardHeaders: true, legacyHeaders: false }));
app.get("/health", async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ ok: true, db: "up" });
  } catch {
    res.status(503).json({ ok: false, db: "down" });
  }
});
app.use("/api/auth", authRouter);
app.use("/api/users", usersRouter);
app.use("/api/friends", friendsRouter);
app.use("/api/servers", serversRouter);
app.use("/api/invites", invitesRouter);
app.use("/api/messages", messagesRouter);
app.use("/api/dms", dmsRouter);
app.use((_req, res) => res.status(404).json({ error: "\u041D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u043E" }));
app.use(errorHandler);
var server = import_http9.default.createServer(app);
initSocket(server);
server.listen(config.PORT, () => logger.info(`Dickcord backend: http://localhost:${config.PORT}`));
var shutdown = async () => {
  logger.info("Shutting down");
  server.close();
  await prisma.$disconnect();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
process.on("unhandledRejection", (err) => logger.error({ err }, "unhandledRejection"));
