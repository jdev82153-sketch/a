require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const { randomBytes, randomUUID } = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
    origin: process.env.FRONTEND_URL || "*"
}));

app.use(express.json({ limit: "20kb" }));

const databaseUrl = process.env.DATABASE_URL;
const jwtSecret = process.env.JWT_SECRET;

const pool = databaseUrl
    ? new Pool({
        connectionString: databaseUrl,
        ssl: { rejectUnauthorized: false },
        connectionTimeoutMillis: 10000
    })
    : null;

if (pool) {
    pool.on("error", (error) => {
        console.error("Erro inesperado no PostgreSQL:", error.message);
    });
}

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: "Muitas tentativas. Aguarde 15 minutos."
    }
});

// ========================================
// BANCO DE DADOS
// ========================================

async function createTables() {
    if (!pool) {
        throw new Error("DATABASE_URL não configurada.");
    }

    await pool.query(`
        CREATE TABLE IF NOT EXISTS companies (
            id BIGSERIAL PRIMARY KEY,
            name VARCHAR(150) NOT NULL UNIQUE,
            key_hash TEXT NOT NULL,
            active BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS company_automations (
            id BIGSERIAL PRIMARY KEY,
            company_id BIGINT NOT NULL
                REFERENCES companies(id) ON DELETE CASCADE,
            automation_key VARCHAR(100) NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(company_id, automation_key)
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id BIGSERIAL PRIMARY KEY,
            jti UUID NOT NULL UNIQUE,
            role VARCHAR(20) NOT NULL,
            company_id BIGINT
                REFERENCES companies(id) ON DELETE CASCADE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at TIMESTAMPTZ NOT NULL,
            revoked_at TIMESTAMPTZ
        );

        CREATE TABLE IF NOT EXISTS admin_logs (
            id BIGSERIAL PRIMARY KEY,
            admin_username VARCHAR(150) NOT NULL,
            action VARCHAR(100) NOT NULL,
            target_company_id BIGINT,
            details JSONB NOT NULL DEFAULT '{}',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_company
            ON sessions(company_id);

        CREATE INDEX IF NOT EXISTS idx_sessions_expiration
            ON sessions(expires_at);
    `);

    console.log("Estrutura do banco verificada.");
}

// ========================================
// MIDDLEWARES
// ========================================

function requireDatabase(req, res, next) {
    if (!pool) {
        return res.status(503).json({
            success: false,
            message: "Banco de dados não configurado."
        });
    }

    next();
}

function requireConfiguration(req, res, next) {
    if (!jwtSecret) {
        return res.status(503).json({
            success: false,
            message: "JWT_SECRET não configurado no servidor."
        });
    }

    next();
}

async function authenticate(req, res, next) {
    try {
        const authorization = req.headers.authorization || "";
        const token = authorization.startsWith("Bearer ")
            ? authorization.slice(7)
            : null;

        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Faça login para continuar."
            });
        }

        const decoded = jwt.verify(token, jwtSecret);

        const result = await pool.query(
            `SELECT jti, role, company_id
             FROM sessions
             WHERE jti = $1
               AND revoked_at IS NULL
               AND expires_at > NOW()`,
            [decoded.jti]
        );

        if (!result.rowCount) {
            return res.status(401).json({
                success: false,
                message: "Sessão expirada ou revogada."
            });
        }

        const session = result.rows[0];

        if (
            session.role !== decoded.role ||
            String(session.company_id ?? "") !==
                String(decoded.companyId ?? "")
        ) {
            return res.status(401).json({
                success: false,
                message: "Sessão inválida."
            });
        }

        req.auth = {
            jti: session.jti,
            role: session.role,
            companyId: session.company_id
        };

        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: "Token inválido ou expirado."
        });
    }
}

function requireAdmin(req, res, next) {
    if (req.auth.role !== "admin") {
        return res.status(403).json({
            success: false,
            message: "Acesso exclusivo do administrador."
        });
    }

    next();
}

function requireCompany(req, res, next) {
    if (req.auth.role !== "company") {
        return res.status(403).json({
            success: false,
            message: "Acesso exclusivo das empresas."
        });
    }

    next();
}

async function logAdminAction(action, companyId = null, details = {}) {
    await pool.query(
        `INSERT INTO admin_logs
         (admin_username, action, target_company_id, details)
         VALUES ($1, $2, $3, $4)`,
        [
            process.env.ADMIN_USERNAME,
            action,
            companyId,
            JSON.stringify(details)
        ]
    );
}

// ========================================
// ROTAS PÚBLICAS
// ========================================

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

app.get("/api/db-status", requireDatabase, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT NOW() AS server_time"
        );

        res.json({
            success: true,
            message: "Banco de dados conectado!",
            serverTime: result.rows[0].server_time
        });
    } catch (error) {
        console.error("Erro no PostgreSQL:", error.message);

        res.status(500).json({
            success: false,
            message: "Não foi possível conectar ao banco."
        });
    }
});

// ========================================
// LOGIN ADMINISTRATIVO
// ========================================

app.post(
    "/api/auth/admin/login",
    loginLimiter,
    requireDatabase,
    requireConfiguration,
    async (req, res) => {
        try {
            const { username, password } = req.body;

            if (
                typeof username !== "string" ||
                typeof password !== "string" ||
                !process.env.ADMIN_USERNAME ||
                !process.env.ADMIN_PASSWORD
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Preencha o usuário e a senha."
                });
            }

            if (
                username !== process.env.ADMIN_USERNAME ||
                password !== process.env.ADMIN_PASSWORD
            ) {
                return res.status(401).json({
                    success: false,
                    message: "Usuário ou senha incorretos."
                });
            }

            const jti = randomUUID();

            const expiresAt = new Date(
                Date.now() + 12 * 60 * 60 * 1000
            );

            await pool.query(
                `INSERT INTO sessions
                 (jti, role, expires_at)
                 VALUES ($1, 'admin', $2)`,
                [jti, expiresAt]
            );

            const token = jwt.sign(
                {
                    role: "admin",
                    jti
                },
                jwtSecret,
                { expiresIn: "12h" }
            );

            await logAdminAction("ADMIN_LOGIN");

            res.json({
                success: true,
                message: "Login administrativo realizado.",
                token,
                role: "admin",
                expiresAt
            });
        } catch (error) {
            console.error("Erro no login administrativo:", error.message);

            res.status(500).json({
                success: false,
                message: "Erro interno ao realizar login."
            });
        }
    }
);

// ========================================
// LOGIN DAS EMPRESAS
// ========================================

app.post(
    "/api/auth/company/login",
    loginLimiter,
    requireDatabase,
    requireConfiguration,
    async (req, res) => {
        try {
            const { name, key } = req.body;

            if (
                typeof name !== "string" ||
                typeof key !== "string" ||
                !name.trim() ||
                !key.trim()
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Informe o nome da empresa e a key."
                });
            }

            const result = await pool.query(
                `SELECT id, name, key_hash
                 FROM companies
                 WHERE LOWER(name) = LOWER($1)
                   AND active = TRUE`,
                [name.trim()]
            );

            if (
                !result.rowCount ||
                !(await bcrypt.compare(key, result.rows[0].key_hash))
            ) {
                return res.status(401).json({
                    success: false,
                    message: "Empresa ou key inválida."
                });
            }

            const company = result.rows[0];
            const jti = randomUUID();

            const expiresAt = new Date(
                Date.now() + 12 * 60 * 60 * 1000
            );

            await pool.query(
                `INSERT INTO sessions
                 (jti, role, company_id, expires_at)
                 VALUES ($1, 'company', $2, $3)`,
                [jti, company.id, expiresAt]
            );

            const token = jwt.sign(
                {
                    role: "company",
                    companyId: company.id,
                    jti
                },
                jwtSecret,
                { expiresIn: "12h" }
            );

            res.json({
                success: true,
                message: "Login realizado.",
                token,
                role: "company",
                company: {
                    id: company.id,
                    name: company.name
                },
                expiresAt
            });
        } catch (error) {
            console.error("Erro no login da empresa:", error.message);

            res.status(500).json({
                success: false,
                message: "Erro interno ao realizar login."
            });
        }
    }
);

// ========================================
// SAIR DA PLATAFORMA
// ========================================

app.post(
    "/api/auth/logout",
    requireDatabase,
    requireConfiguration,
    authenticate,
    async (req, res) => {
        await pool.query(
            `UPDATE sessions
             SET revoked_at = NOW()
             WHERE jti = $1`,
            [req.auth.jti]
        );

        res.json({
            success: true,
            message: "Sessão encerrada."
        });
    }
);

// ========================================
// PAINEL ADMINISTRATIVO
// ========================================

// Listar empresas
app.get(
    "/api/admin/companies",
    requireDatabase,
    requireConfiguration,
    authenticate,
    requireAdmin,
    async (req, res) => {
        try {
            const result = await pool.query(
                `SELECT
                    c.id,
                    c.name,
                    c.active,
                    c.created_at,
                    COALESCE(
                        json_agg(
                            json_build_object(
                                'key', a.automation_key,
                                'enabled', a.enabled
                            )
                        ) FILTER (WHERE a.id IS NOT NULL),
                        '[]'
                    ) AS automations
                 FROM companies c
                 LEFT JOIN company_automations a
                    ON a.company_id = c.id
                 GROUP BY c.id
                 ORDER BY c.created_at DESC`
            );

            res.json({
                success: true,
                companies: result.rows
            });
        } catch (error) {
            console.error("Erro ao listar empresas:", error.message);

            res.status(500).json({
                success: false,
                message: "Não foi possível listar as empresas."
            });
        }
    }
);

// Criar empresa e gerar key
app.post(
    "/api/admin/companies",
    requireDatabase,
    requireConfiguration,
    authenticate,
    requireAdmin,
    async (req, res) => {
        const client = await pool.connect();

        try {
            const { name, automations = [] } = req.body;

            if (
                typeof name !== "string" ||
                !name.trim() ||
                name.trim().length > 150
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Informe um nome válido para a empresa."
                });
            }

            if (
                !Array.isArray(automations) ||
                automations.length > 30 ||
                !automations.every(
                    item =>
                        typeof item === "string" &&
                        /^[a-zA-Z0-9_-]{1,100}$/.test(item)
                )
            ) {
                return res.status(400).json({
                    success: false,
                    message: "Lista de automações inválida."
                });
            }

            const accessKey =
                "MARKS-" + randomBytes(24).toString("base64url");

            const keyHash = await bcrypt.hash(accessKey, 12);

            await client.query("BEGIN");

            const result = await client.query(
                `INSERT INTO companies (name, key_hash)
                 VALUES ($1, $2)
                 RETURNING id, name, active, created_at`,
                [name.trim(), keyHash]
            );

            const company = result.rows[0];

            for (const automation of [...new Set(automations)]) {
                await client.query(
                    `INSERT INTO company_automations
                     (company_id, automation_key, enabled)
                     VALUES ($1, $2, TRUE)`,
                    [company.id, automation]
                );
            }

            await client.query("COMMIT");

            await logAdminAction(
                "COMPANY_CREATED",
                company.id,
                { name: company.name }
            );

            res.status(201).json({
                success: true,
                message: "Empresa criada. Guarde a key, pois ela não será exibida novamente.",
                company,
                key: accessKey
            });
        } catch (error) {
            await client.query("ROLLBACK");

            if (error.code === "23505") {
                return res.status(409).json({
                    success: false,
                    message: "Já existe uma empresa com esse nome."
                });
            }

            console.error("Erro ao criar empresa:", error.message);

            res.status(500).json({
                success: false,
                message: "Não foi possível criar a empresa."
            });
        } finally {
            client.release();
        }
    }
);

// Revogar acesso de uma empresa
app.patch(
    "/api/admin/companies/:id/revoke",
    requireDatabase,
    requireConfiguration,
    authenticate,
    requireAdmin,
    async (req, res) => {
        try {
            const companyId = req.params.id;

            if (!/^\d+$/.test(companyId)) {
                return res.status(400).json({
                    success: false,
                    message: "ID de empresa inválido."
                });
            }

            const result = await pool.query(
                `UPDATE companies
                 SET active = FALSE
                 WHERE id = $1
                 RETURNING id, name, active`,
                [companyId]
            );

            if (!result.rowCount) {
                return res.status(404).json({
                    success: false,
                    message: "Empresa não encontrada."
                });
            }

            await pool.query(
                `UPDATE sessions
                 SET revoked_at = NOW()
                 WHERE company_id = $1
                   AND revoked_at IS NULL`,
                [companyId]
            );

            await logAdminAction("COMPANY_REVOKED", companyId);

            res.json({
                success: true,
                message: "Acesso revogado e sessões encerradas.",
                company: result.rows[0]
            });
        } catch (error) {
            console.error("Erro ao revogar acesso:", error.message);

            res.status(500).json({
                success: false,
                message: "Não foi possível revogar o acesso."
            });
        }
    }
);

// Reativar empresa
app.patch(
    "/api/admin/companies/:id/activate",
    requireDatabase,
    requireConfiguration,
    authenticate,
    requireAdmin,
    async (req, res) => {
        try {
            const companyId = req.params.id;

            if (!/^\d+$/.test(companyId)) {
                return res.status(400).json({
                    success: false,
                    message: "ID de empresa inválido."
                });
            }

            const result = await pool.query(
                `UPDATE companies
                 SET active = TRUE
                 WHERE id = $1
                 RETURNING id, name, active`,
                [companyId]
            );

            if (!result.rowCount) {
                return res.status(404).json({
                    success: false,
                    message: "Empresa não encontrada."
                });
            }

            await logAdminAction("COMPANY_ACTIVATED", companyId);

            res.json({
                success: true,
                message: "Empresa reativada.",
                company: result.rows[0]
            });
        } catch (error) {
            console.error("Erro ao reativar empresa:", error.message);

            res.status(500).json({
                success: false,
                message: "Não foi possível reativar a empresa."
            });
        }
    }
);

// ========================================
// PAINEL DA EMPRESA
// ========================================

app.get(
    "/api/company/me",
    requireDatabase,
    requireConfiguration,
    authenticate,
    requireCompany,
    async (req, res) => {
        try {
            const result = await pool.query(
                `SELECT id, name, active, created_at
                 FROM companies
                 WHERE id = $1`,
                [req.auth.companyId]
          
