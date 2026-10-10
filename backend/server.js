
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000;
const API_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

app.use(cors({ origin: process.env.FRONTEND_URL || "*" }));
app.use(express.json({ limit: "20kb" }));

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    })
  : null;

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Muitas tentativas. Tente novamente em 15 minutos."
  }
});

let schemaPromise;

async function ensureSchema() {
  if (!pool) {
    throw new Error("DATABASE_URL não configurada.");
  }

  if (!schemaPromise) {
    schemaPromise = (async () => {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS companies (
          id BIGSERIAL PRIMARY KEY,
          name TEXT NOT NULL,
          key_hash TEXT NOT NULL,
          active BOOLEAN NOT NULL DEFAULT TRUE,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      await pool.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS companies_name_unique
        ON companies (LOWER(name))
      `);
    })().catch(error => {
      schemaPromise = null;
      throw error;
    });
  }

  return schemaPromise;
}

function createToken(payload, expiresIn = "8h") {
  if (!API_SECRET) {
    throw new Error("JWT_SECRET não configurada.");
  }

  return jwt.sign(payload, API_SECRET, { expiresIn });
}

// AUTENTICAÇÃO PELO TOKEN JWT
function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token || !API_SECRET) {
    return res.status(401).json({
      success: false,
      message: "Faça login para continuar."
    });
  }

  try {
    req.user = jwt.verify(token, API_SECRET);
    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: "Sessão inválida ou expirada. Entre novamente."
    });
  }
}

// PERMISSÃO EXCLUSIVA DO ADMINISTRADOR
function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Acesso exclusivo do administrador."
    });
  }

  next();
}

// ROTA INICIAL
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "API da Agência Marks está online."
  });
});

// STATUS DA API
app.get("/api/status", (req, res) => {
  res.json({
    success: true,
    service: "Agência Marks API",
    status: "online"
  });
});

// TESTE DO BANCO DE DADOS
app.get("/api/db-status", async (req, res) => {
  try {
    if (!pool) {
      throw new Error("DATABASE_URL não configurada.");
    }

    const result = await pool.query("SELECT NOW() AS server_time");

    res.json({
      success: true,
      message: "Banco conectado.",
      serverTime: result.rows[0].server_time
    });
  } catch (error) {
    console.error("Falha no teste do banco:", error.message);

    res.status(500).json({
      success: false,
      message: "Não foi possível conectar ao banco."
    });
  }
});

// LOGIN DO ADMINISTRADOR
app.post("/api/admin/login", loginLimiter, async (req, res) => {
  try {
    if (!ADMIN_USERNAME || !ADMIN_PASSWORD || !API_SECRET) {
      return res.status(503).json({
        success: false,
        message: "Configure ADMIN_USERNAME, ADMIN_PASSWORD e JWT_SECRET no Render."
      });
    }

    const username = String(req.body.username || "");
    const password = String(req.body.password || "");

    if (
      username !== ADMIN_USERNAME ||
      password !== ADMIN_PASSWORD
    ) {
      return res.status(401).json({
        success: false,
        message: "Nome de administrador ou senha incorretos."
      });
    }

    const token = createToken({
      role: "admin",
      username
    }, "8h");

    return res.json({
      success: true,
      token,
      username
    });
  } catch (error) {
    console.error("Erro no login administrativo:", error.message);

    return res.status(500).json({
      success: false,
      message: "Erro ao realizar login."
    });
  }
});

// CRIAR EMPRESA E GERAR CHAVE DE ACESSO
app.post(
  "/api/admin/companies",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      await ensureSchema();

      const name = String(req.body.name || "").trim();

      if (name.length < 2 || name.length > 100) {
        return res.status(400).json({
          success: false,
          message: "O nome da empresa deve ter entre 2 e 100 caracteres."
        });
      }

      const key = "MARKS-" + crypto.randomBytes(24).toString("hex");
      const keyHash = await bcrypt.hash(key, 12);

      const result = await pool.query(
        `INSERT INTO companies (name, key_hash)
         VALUES ($1, $2)
         RETURNING id, name, active, created_at`,
        [name, keyHash]
      );

      // A chave original só é enviada nesta resposta.
      return res.status(201).json({
        success: true,
        message: "Empresa criada. Copie a chave e guarde-a em local seguro.",
        company: result.rows[0],
        key
      });
    } catch (error) {
      if (error.code === "23505") {
        return res.status(409).json({
          success: false,
          message: "Já existe uma empresa com esse nome."
        });
      }

      console.error("Erro ao criar empresa:", error.message);

      return res.status(500).json({
        success: false,
        message: "Não foi possível criar a empresa."
      });
    }
  }
);

// LISTAR EMPRESAS SEM EXPOR AS CHAVES
app.get(
  "/api/admin/companies",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      await ensureSchema();

      const result = await pool.query(
        `SELECT id, name, active, created_at
         FROM companies
         ORDER BY created_at DESC`
      );

      return res.json({
        success: true,
        companies: result.rows
      });
    } catch (error) {
      console.error("Erro ao listar empresas:", error.message);

      return res.status(500).json({
        success: false,
        message: "Não foi possível listar as empresas."
      });
    }
  }
);

// LOGIN DA EMPRESA COM NOME E CHAVE
app.post("/api/company/login", loginLimiter, async (req, res) => {
  try {
    await ensureSchema();

    if (!API_SECRET) {
      return res.status(503).json({
        success: false,
        message: "API não configurada."
      });
    }

    const name = String(req.body.name || "").trim();
    const key = String(req.body.key || "").trim();

    if (!name || !key) {
      return res.status(400).json({
        success: false,
        message: "Informe o nome da empresa e a chave."
      });
    }

    const result = await pool.query(
      `SELECT id, name, key_hash
       FROM companies
       WHERE LOWER(name) = LOWER($1)
         AND active = TRUE`,
      [name]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        success: false,
        message: "Nome da empresa ou chave inválidos."
      });
    }

    const company = result.rows[0];
    const keyIsValid = await bcrypt.compare(key, company.key_hash);

    if (!keyIsValid) {
      return res.status(401).json({
        success: false,
        message: "Nome da empresa ou chave inválidos."
      });
    }

    const token = createToken({
      role: "company",
      companyId: String(company.id),
      companyName: company.name
    }, "12h");

    return res.json({
      success: true,
      token,
      company: {
        id: company.id,
        name: company.name
      }
    });
  } catch (error) {
    console.error("Erro no login da empresa:", error.message);

    return res.status(500).json({
      success: false,
      message: "Não foi possível realizar o login."
    });
  }
});

// VALIDAR SESSÃO E CONFERIR SE A EMPRESA ESTÁ ATIVA
app.get("/api/auth/me", authenticate, async (req, res) => {
  try {
    // O administrador também pode validar sua sessão.
    if (req.user.role === "admin") {
      return res.json({
        success: true,
        user: {
          role: "admin",
          username: req.user.username || null,
          companyId: null,
          companyName: null
        }
      });
    }

    // Rejeita tokens que não pertençam a uma empresa válida.
    if (req.user.role !== "company" || !req.user.companyId) {
      return res.status(403).json({
        success: false,
        message: "Acesso não autorizado."
      });
    }

    await ensureSchema();

    // Confere o estado atual da empresa diretamente no banco.
    const result = await pool.query(
      `SELECT id, name, active
       FROM companies
       WHERE id = $1`,
      [req.user.companyId]
    );

    if (!result.rows.length || !result.rows[0].active) {
      return res.status(403).json({
        success: false,
        message: "Sua conta está suspensa ou não está mais disponível. Entre em contato com o administrador."
      });
    }

    const company = result.rows[0];

    return res.json({
      success: true,
      user: {
        role: "company",
        username: null,
        companyId: String(company.id),
        companyName: company.name
      }
    });
  } catch (error) {
    console.error("Erro ao validar sessão:", error.message);

    return res.status(500).json({
      success: false,
      message: "Não foi possível validar sua sessão."
    });
  }
});

// INICIALIZAÇÃO DO SERVIDOR
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Agência Marks API rodando na porta ${PORT}`);
  console.log("PostgreSQL configurado:", Boolean(pool));
});

// ENCERRAMENTO GRACIOSO
process.on("SIGTERM", async () => {
  if (pool) {
    await pool.end().catch(() => {});
  }

  process.exit(0);
});
