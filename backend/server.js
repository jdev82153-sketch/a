require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

// ========================================
// CONFIGURAÇÕES GERAIS
// ========================================

app.use(cors({
    origin: process.env.FRONTEND_URL || "*"
}));

app.use(express.json());

// ========================================
// CONEXÃO COM O POSTGRESQL
// ========================================

const databaseUrl = process.env.DATABASE_URL;

const pool = databaseUrl
    ? new Pool({
        connectionString: databaseUrl,
        ssl: {
            rejectUnauthorized: false
        },
        connectionTimeoutMillis: 10000
    })
    : null;

// Registrar erros inesperados na conexão
if (pool) {
    pool.on("error", (error) => {
        console.error("Erro inesperado no PostgreSQL:", {
            message: error.message,
            code: error.code
        });
    });
}

// ========================================
// ROTA PRINCIPAL
// ========================================

app.get("/", (req, res) => {
    res.json({
        success: true,
        message: "API da Agência Marks está online."
    });
});

// ========================================
// STATUS DA API
// ========================================

app.get("/api/status", (req, res) => {
    res.json({
        success: true,
        service: "Agência Marks API",
        status: "online"
    });
});

// ========================================
// TESTE DE CONEXÃO COM O BANCO
// ========================================

app.get("/api/db-status", async (req, res) => {
    if (!databaseUrl || !pool) {
        console.error(
            "DATABASE_URL não está configurada no ambiente."
        );

        return res.status(500).json({
            success: false,
            message: "Configuração do banco de dados ausente."
        });
    }

    try {
        const result = await pool.query(
            "SELECT NOW() AS server_time"
        );

        console.log("Conexão com PostgreSQL confirmada.");

        return res.status(200).json({
            success: true,
            message: "Banco de dados conectado!",
            serverTime: result.rows[0].server_time
        });

    } catch (error) {
        // Registrar informações úteis sem expor credenciais
        console.error("Erro ao conectar ao banco:", {
            message: error.message || "Mensagem indisponível",
            code: error.code || "SEM_CODIGO",
            detail: error.detail || null,
            severity: error.severity || null,
            routine: error.routine || null
        });

        return res.status(500).json({
            success: false,
            message: "Não foi possível conectar ao banco de dados.",
            errorCode: error.code || "ERRO_DE_CONEXAO"
        });
    }
});

// ========================================
// INICIALIZAÇÃO DO SERVIDOR
// ========================================

const server = app.listen(PORT, "0.0.0.0", () => {
    console.log(
        `Agência Marks API rodando na porta ${PORT}`
    );

    console.log(
        "DATABASE_URL configurada:",
        Boolean(databaseUrl)
    );
});

// ========================================
// ENCERRAMENTO SEGURO
// ========================================

process.on("SIGTERM", async () => {
    console.log("Encerrando a API da Agência Marks...");

    try {
        if (pool) {
            await pool.end();
        }
    } catch (error) {
        console.error(
            "Erro ao encerrar conexão com o banco:",
            error.message
        );
    }

    server.close(() => {
        process.exit(0);
    });
});
