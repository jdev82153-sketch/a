
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const session = require("express-session");
const connectPgSimple = require("connect-pg-simple");
const bcrypt = require("bcrypt");
const db = require("./config/db");

const app = express();

const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const SESSION_NAME = "marks.sid";

if (!process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET não foi configurada.");
}

const PgSession = connectPgSimple(session);

const allowedOrigins = (process.env.FRONTEND_URL || "")
  .split(",")
  .map((origin) => origin.trim().replace(/\/+$/, ""))
  .filter(Boolean);

app.disable("x-powered-by");
app.set("trust proxy", IS_PRODUCTION ? 1 : false);

app.use(helmet());

app.use(
  cors({
    origin(origin, callback) {
      if (!origin && !IS_PRODUCTION) {
        return callback(null, true);
      }

      if (
        !IS_PRODUCTION &&
        origin === "http://localhost:5500"
      ) {
        return callback(null, true);
      }

      if (origin && allowedOrigins.includes(origin.replace(/\/+$/, ""))) {
        return callback(null, true);
      }

      if (!origin && IS_PRODUCTION) {
        return callback(null, true);
      }

      return callback(new Error("Origem não autorizada pelo CORS."));
    },
    credentials: true,
  })
);

app.use(express.json({ limit: "20kb" }));

app.use(
  session({
    name: SESSION_NAME,
    secret: process.env.SESSION_SECRET,
    store: new PgSession({
      pool: db,
      tableName: "sessions",
      createTableIfMissing: true,
      pruneSessionInterval: 15 * 60,
    }),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: IS_PRODUCTION,
      sameSite: IS_PRODUCTION ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
    },
  })
);

async function initializeDatabase() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(50) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'user'
        CHECK (role IN ('user', 'admin')),
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await db.query(`
    CREATE INDEX IF NOT EXISTS idx_users_role
    ON users(role)
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      sid VARCHAR NOT NULL PRIMARY KEY,
      sess JSON NOT NULL,
      expire TIMESTAMP(6) NOT NULL
    )
  `);

  await db.query(`
    CREATE INDEX IF NOT EXISTS idx_sessions_expire
    ON sessions(expire)
  `);

  console.log("Banco de dados inicializado.");

  const username = process.env.ADMIN_USERNAME || "jaosafadex";
  const password = process.env.ADMIN_PASSWORD;

  if (!password) {
    console.warn(
      "ADMIN_PASSWORD não configurada. Administrador não foi criado."
    );
    return;
  }

  if (username.length < 3 || username.length > 50) {
    throw new Error(
      "ADMIN_USERNAME deve ter entre 3 e 50 caracteres."
    );
  }

  if (password.length < 12) {
    throw new Error(
      "ADMIN_PASSWORD precisa ter pelo menos 12 caracteres."
    );
  }

  const existing = await db.query(
    "SELECT id FROM users WHERE username = $1",
    [username]
  );

  if (existing.rowCount === 0) {
    const passwordHash = await bcrypt.hash(password, 12);

    await db.query(
      `INSERT INTO users (username, password_hash, role)
       VALUES ($1, $2, 'admin')`,
      [username, passwordHash]
    );

    console.log("Administrador inicial criado.");
  } else {
    await db.query(
      `UPDATE users
       SET role = 'admin',
           is_active = TRUE,
           updated_at = NOW()
       WHERE username = $1`,
      [username]
    );

    console.log("Conta administrativa verificada.");
  }
}

function requireAuth(req, res, next) {
  if (!req.session?.user) {
    return res.status(401).json({
      success: false,
      message: "Faça login para continuar.",
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (!req.session?.user || req.session.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Acesso exclusivo ao administrador.",
    });
  }

  next();
}

app.get("/", (req, res) => {
  res.json({
    success: true,
    name: "Agência Marks API",
    message: "API funcionando corretamente.",
    status: "online",
    version: "1.0.0",
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "online",
    timestamp: new Date().toISOString(),
  });
});

app.post("/api/auth/login", async (req, res, next) => {
  try {
    const { username, password } = req.body || {};

    if (
      typeof username !== "string" ||
      typeof password !== "string" ||
      !username.trim() ||
      username.length > 50 ||
      !password ||
      password.length > 1024
    ) {
      return res.status(400).json({
        success: false,
        message: "Informe usuário e senha válidos.",
      });
    }

    const result = await db.query(
      `SELECT id, username, password_hash, role, is_active
       FROM users
       WHERE username = $1`,
      [username.trim()]
    );

    const user = result.rows[0];

    if (
      !user ||
      !user.is_active ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return res.status(401).json({
        success: false,
        message: "Usuário ou senha incorretos.",
      });
    }

    req.session.regenerate((error) => {
      if (error) return next(error);

      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role,
      };

      req.session.save((saveError) => {
        if (saveError) return next(saveError);

        res.json({
          success: true,
          message: "Login realizado com sucesso.",
          user: req.session.user,
        });
      });
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/auth/me", (req, res) => {
  if (!req.session?.user) {
    return res.status(401).json({
      success: false,
      authenticated: false,
      message: "Nenhuma sessão ativa.",
    });
  }

  res.json({
    success: true,
    authenticated: true,
    user: req.session.user,
  });
});

app.post("/api/auth/logout", (req, res, next) => {
  if (!req.session) {
    return res.json({
      success: true,
      message: "Nenhuma sessão ativa.",
    });
  }

  req.session.destroy((error) => {
    if (error) return next(error);

    res.clearCookie(SESSION_NAME, {
      httpOnly: true,
      secure: IS_PRODUCTION,
      sameSite: IS_PRODUCTION ? "none" : "lax",
      path: "/",
    });

    res.json({
      success: true,
      message: "Logout realizado com sucesso.",
    });
  });
});

app.get("/api/admin", requireAuth, requireAdmin, (req, res) => {
  res.json({
    success: true,
    message: "Acesso administrativo autorizado.",
    user: req.session.user,
  });
});

app.get("/api", (req, res) => {
  res.json({
    success: true,
    name: "Agência Marks API",
    endpoints: [
      "GET /api/health",
      "POST /api/auth/login",
      "GET /api/auth/me",
      "POST /api/auth/logout",
      "GET /api/admin",
    ],
  });
});

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Rota não encontrada.",
    path: req.originalUrl,
  });
});

app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }

  console.error("Erro interno:", err.message);

  if (err.message === "Origem não autorizada pelo CORS.") {
    return res.status(403).json({
      success: false,
      message: "Origem não autorizada.",
    });
  }

  res.status(500).json({
    success: false,
    message: "Erro interno do servidor.",
  });
});

let server;

initializeDatabase()
  .then(() => {
    server = app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `Agência Marks API online na porta ${PORT}.`
      );
    });
  })
  .catch((error) => {
    console.error("Falha na inicialização:", error.message);
    process.exit(1);
  });

function shutdown(signal) {
  console.log(`${signal}: encerrando servidor.`);

  const finish = () => {
    db.end()
      .catch((error) => {
        console.error(
          "Erro ao encerrar PostgreSQL:",
          error.message
        );
      })
      .finally(() => process.exit(0));
  };

  if (server) {
    server.close(finish);
  } else {
    finish();
  }
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
