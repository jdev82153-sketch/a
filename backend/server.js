
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
const KEY_ENCRYPTION_SECRET = process.env.KEY_ENCRYPTION_SECRET;

const SUSPENSION_MESSAGE =
  "Sua conta foi suspensa pelo ADM João. Entre em contato com o administrador para obter ajuda.";

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

// =====================================================
// CRIPTOGRAFIA DAS CHAVES
// =====================================================

function getEncryptionKey() {
  if (
    !KEY_ENCRYPTION_SECRET ||
    KEY_ENCRYPTION_SECRET.length < 32
  ) {
    const error = new Error(
      "Configure KEY_ENCRYPTION_SECRET no ambiente do servidor. Use um segredo aleatório com pelo menos 32 caracteres."
    );

    error.code = "KEY_ENCRYPTION_NOT_CONFIGURED";
    throw error;
  }

  return crypto
    .createHash("sha256")
    .update(KEY_ENCRYPTION_SECRET, "utf8")
    .digest();
}

function encryptKey(value) {
  const encryptionKey = getEncryptionKey();
  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    encryptionKey,
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final()
  ]);

  const authTag = cipher.getAuthTag();

  return [
    "v1",
    iv.toString("hex"),
    authTag.toString("hex"),
    encrypted.toString("hex")
  ].join(":");
}

function decryptKey(encryptedValue) {
  if (!encryptedValue) {
    return null;
  }

  try {
    const parts = encryptedValue.split(":");

    if (parts.length !== 4 || parts[0] !== "v1") {
      return null;
    }

    const [, ivHex, authTagHex, encryptedHex] = parts;

    if (
      !/^[0-9a-f]+$/i.test(ivHex) ||
      !/^[0-9a-f]+$/i.test(authTagHex) ||
      !/^[0-9a-f]*$/i.test(encryptedHex) ||
      ivHex.length !== 24 ||
      authTagHex.length !== 32
    ) {
      return null;
    }

    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      getEncryptionKey(),
      Buffer.from(ivHex, "hex")
    );

    decipher.setAuthTag(Buffer.from(authTagHex, "hex"));

    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(encryptedHex, "hex")),
      decipher.final()
    ]);

    return decrypted.toString("utf8");
  } catch {
    return null;
  }
}

function createAccessKey() {
  return "MARKS-" + crypto.randomBytes(24).toString("hex");
}

function handleServerError(res, error, genericMessage) {
  if (error.code === "KEY_ENCRYPTION_NOT_CONFIGURED") {
    return res.status(503).json({
      success: false,
      code: error.code,
      message: error.message
    });
  }

  console.error(genericMessage, error.message);

  return res.status(500).json({
    success: false,
    message: genericMessage
  });
}

// =====================================================
// BANCO DE DADOS
// =====================================================

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

      // Adiciona a coluna sem apagar os registros existentes.
      await pool.query(`
        ALTER TABLE companies
        ADD COLUMN IF NOT EXISTS key_encrypted TEXT
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

// =====================================================
// AUTENTICAÇÃO
// =====================================================

function createToken(payload, expiresIn = "8h") {
  if (!API_SECRET) {
    throw new Error("JWT_SECRET não configurada.");
  }

  return jwt.sign(payload, API_SECRET, { expiresIn });
}

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

function requireAdmin(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Acesso exclusivo do administrador."
    });
  }

  next();
}

// Middleware disponível para rotas empresariais futuras.
async function requireActiveCompany(req, res, next) {
  try {
    if (
      req.user?.role !== "company" ||
      !req.user.companyId
    ) {
      return res.status(403).json({
        success: false,
        message: "Acesso exclusivo de uma conta empresarial."
      });
    }

    await ensureSchema();

    const result = await pool.query(
      `SELECT id, name, active
       FROM companies
       WHERE id = $1`,
      [req.user.companyId]
    );

    if (!result.rows.length || !result.rows[0].active) {
      return res.status(403).json({
        success: false,
        message: SUSPENSION_MESSAGE,
        code: "COMPANY_SUSPENDED"
      });
    }

    req.company = result.rows[0];
    next();
  } catch (error) {
    console.error("Erro ao verificar empresa:", error.message);

    return res.status(500).json({
      success: false,
      message: "Não foi possível verificar a conta da empresa."
    });
  }
}

// =====================================================
// ROTAS PÚBLICAS E STATUS
// =====================================================

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "API da Agência Marks está online."
  });
});

app.get("/api/status", (req, res) => {
  res.json({
    success: true,
    service: "Agência Marks API",
    status: "online"
  });
});

app.get("/api/db-status", async (req, res) => {
  try {
    if (!pool) {
      throw new Error("DATABASE_URL não configurada.");
    }

    const result = await pool.query("SELECT NOW() AS server_time");

    return res.json({
      success: true,
      message: "Banco conectado.",
      serverTime: result.rows[0].server_time
    });
  } catch (error) {
    console.error("Falha no teste do banco:", error.message);

    return res.status(500).json({
      success: false,
      message: "Não foi possível conectar ao banco."
    });
  }
});

// =====================================================
// LOGIN DO ADMINISTRADOR
// =====================================================

app.post("/api/admin/login", loginLimiter, async (req, res) => {
  try {
    if (!ADMIN_USERNAME || !ADMIN_PASSWORD || !API_SECRET) {
      return res.status(503).json({
        success: false,
        message:
          "Configure ADMIN_USERNAME, ADMIN_PASSWORD e JWT_SECRET no Render."
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

    const token = createToken(
      {
        role: "admin",
        username
      },
      "8h"
    );

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

// =====================================================
// CADASTRAR EMPRESA
// =====================================================

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
          message:
            "O nome da empresa deve ter entre 2 e 100 caracteres."
        });
      }

      // A chave só é criada se puder ser protegida corretamente.
      const key = createAccessKey();
      const keyHash = await bcrypt.hash(key, 12);
      const keyEncrypted = encryptKey(key);

      const result = await pool.query(
        `INSERT INTO companies (name, key_hash, key_encrypted)
         VALUES ($1, $2, $3)
         RETURNING id, name, active, created_at`,
        [name, keyHash, keyEncrypted]
      );

      return res.status(201).json({
        success: true,
        message: "Empresa cadastrada com sucesso.",
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

      return handleServerError(
        res,
        error,
        "Não foi possível criar a empresa."
      );
    }
  }
);

// =====================================================
// LISTAR EMPRESAS COM CHAVES
// Somente administrador autenticado.
// =====================================================

app.get(
  "/api/admin/companies",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      await ensureSchema();

      const result = await pool.query(
        `SELECT id, name, active, created_at, key_encrypted
         FROM companies
         ORDER BY created_at DESC`
      );

      const companies = result.rows.map(company => {
        const key = decryptKey(company.key_encrypted);

        return {
          id: company.id,
          name: company.name,
          active: company.active,
          created_at: company.created_at,
          key,
          keyAvailable: Boolean(key)
        };
      });

      return res.json({
        success: true,
        companies
      });
    } catch (error) {
      return handleServerError(
        res,
        error,
        "Não foi possível listar as empresas."
      );
    }
  }
);

// =====================================================
// SUSPENDER OU REATIVAR EMPRESA
// PATCH /api/admin/companies/:id/status
// =====================================================

app.patch(
  "/api/admin/companies/:id/status",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      await ensureSchema();

      const id = String(req.params.id || "");

      if (!/^\d+$/.test(id)) {
        return res.status(400).json({
          success: false,
          message: "Identificador de empresa inválido."
        });
      }

      if (typeof req.body.active !== "boolean") {
        return res.status(400).json({
          success: false,
          message: "Informe o status da empresa."
        });
      }

      const result = await pool.query(
        `UPDATE companies
         SET active = $1
         WHERE id = $2
         RETURNING id, name, active, created_at`,
        [req.body.active, id]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message: "Empresa não encontrada."
        });
      }

      const company = result.rows[0];

      return res.json({
        success: true,
        message: company.active
          ? "Empresa reativada com sucesso."
          : "Empresa suspensa com sucesso.",
        company,
        suspensionMessage: company.active
          ? null
          : SUSPENSION_MESSAGE
      });
    } catch (error) {
      return handleServerError(
        res,
        error,
        "Não foi possível alterar o status da empresa."
      );
    }
  }
);

// =====================================================
// GERAR NOVA CHAVE E INVALIDAR A ANTERIOR
// POST /api/admin/companies/:id/rotate-key
// =====================================================

app.post(
  "/api/admin/companies/:id/rotate-key",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      await ensureSchema();

      const id = String(req.params.id || "");

      if (!/^\d+$/.test(id)) {
        return res.status(400).json({
          success: false,
          message: "Identificador de empresa inválido."
        });
      }

      const key = createAccessKey();
      const keyHash = await bcrypt.hash(key, 12);
      const keyEncrypted = encryptKey(key);

      const result = await pool.query(
        `UPDATE companies
         SET key_hash = $1,
             key_encrypted = $2
         WHERE id = $3
         RETURNING id, name, active, created_at`,
        [keyHash, keyEncrypted, id]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message: "Empresa não encontrada."
        });
      }

      return res.json({
        success: true,
        message:
          "Nova chave gerada. A chave anterior foi invalidada.",
        company: result.rows[0],
        key
      });
    } catch (error) {
      return handleServerError(
        res,
        error,
        "Não foi possível gerar uma nova chave."
      );
    }
  }
);

// =====================================================
// LOGIN DA EMPRESA
// =====================================================

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
      `SELECT id, name, key_hash, active
       FROM companies
       WHERE LOWER(name) = LOWER($1)`,
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

    if (!company.active) {
      return res.status(403).json({
        success: false,
        code: "COMPANY_SUSPENDED",
        message: SUSPENSION_MESSAGE
      });
    }

    const token = createToken(
      {
        role: "company",
        companyId: String(company.id),
        companyName: company.name
      },
      "12h"
    );

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

// =====================================================
// VALIDAR SESSÃO ATUAL
// GET /api/auth/me
// =====================================================

app.get("/api/auth/me", authenticate, async (req, res) => {
  try {
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

    if (
      req.user.role !== "company" ||
      !req.user.companyId
    ) {
      return res.status(403).json({
        success: false,
        message: "Acesso não autorizado."
      });
    }

    await ensureSchema();

    const result = await pool.query(
      `SELECT id, name, active
       FROM companies
       WHERE id = $1`,
      [req.user.companyId]
    );

    if (!result.rows.length || !result.rows[0].active) {
      return res.status(403).json({
        success: false,
        code: "COMPANY_SUSPENDED",
        message: SUSPENSION_MESSAGE
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

// =====================================================
// INICIALIZAÇÃO
// =====================================================

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Agência Marks API rodando na porta ${PORT}`);
  console.log("PostgreSQL configurado:", Boolean(pool));
});

process.on("SIGTERM", async () => {
  if (pool) {
    await pool.end().catch(() => {});
  }

  process.exit(0);
});
