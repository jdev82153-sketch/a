
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const db = require("./config/db");

const app = express();

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";

// Configurações gerais
app.disable("x-powered-by");

app.use(helmet());

const allowedOrigins = process.env.FRONTEND_URL
  ? process.env.FRONTEND_URL.split(",").map((url) => url.trim())
  : true;

app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
  })
);

app.use(express.json({ limit: "20kb" }));

// Rota principal
app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    name: "Agência Marks API",
    message: "API funcionando corretamente.",
    status: "online",
    version: "1.0.0",
  });
});

// Status da API
app.get("/api/health", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Agência Marks API está funcionando.",
    status: "online",
    timestamp: new Date().toISOString(),
  });
});

// Teste da conexão com PostgreSQL
app.get("/api/db-health", async (req, res) => {
  try {
    const result = await db.query("SELECT NOW() AS database_time");

    res.status(200).json({
      success: true,
      message: "Conexão com PostgreSQL funcionando.",
      database: "online",
      timestamp: result.rows[0].database_time,
    });
  } catch (error) {
    console.error("Erro ao conectar ao PostgreSQL:", error.message);

    res.status(503).json({
      success: false,
      message: "Não foi possível conectar ao banco de dados.",
    });
  }
});

// Informações das rotas públicas
app.get("/api", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Bem-vindo à API da Agência Marks.",
    endpoints: {
      home: "/",
      health: "/api/health",
      database: "/api/db-health",
    },
  });
});

// Rota não encontrada
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Rota não encontrada.",
    path: req.originalUrl,
  });
});

// Tratamento centralizado de erros
app.use((err, req, res, next) => {
  console.error("Erro interno:", err.message);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    success: false,
    message: "Erro interno do servidor.",
  });
});

// Inicialização do servidor
const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Agência Marks API online na porta ${PORT} (${NODE_ENV}).`
  );
});

// Encerramento seguro
function shutdown(signal) {
  console.log(`${signal} recebido. Encerrando servidor...`);

  server.close(() => {
    db.end()
      .catch((error) => {
        console.error("Erro ao encerrar PostgreSQL:", error.message);
      })
      .finally(() => {
        process.exit(0);
      });
  });
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
