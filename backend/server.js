require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
    origin: process.env.FRONTEND_URL || "*"
}));

app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL
        ? { rejectUnauthorized: false }
        : false
});

// Testar a conexão com o PostgreSQL
app.get("/api/db-status", async (req, res) => {
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
        console.error("Erro ao conectar ao banco:", error.message);

        res.status(500).json({
            success: false,
            message: "Não foi possível conectar ao banco de dados."
        });
    }
});

// Verificar se a API está online
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

const server = app.listen(PORT, "0.0.0.0", () => {
    console.log(`Agência Marks API rodando na porta ${PORT}`);
});

process.on("SIGTERM", async () => {
    await pool.end();
    server.close(() => process.exit(0));
});
