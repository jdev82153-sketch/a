
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");

const app = express();

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";

app.disable("x-powered-by");

app.use(helmet());

app.use(
  cors({
    origin: process.env.FRONTEND_URL
      ? process.env.FRONTEND_URL.split(",").map((url) => url.trim())
      : true,
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

// Verificação de saúde da API
app.get("/api/health", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Agência Marks API está funcionando.",
    status: "online",
    environment: NODE_ENV,
    timestamp: new Date().toISOString(),
  });
});

// Informações básicas da API
app.get("/api", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Bem-vindo à API da Agência Marks.",
    endpoints: {
      home: "/",
      health: "/api/health",
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

// Tratamento de erros
app.use((err, req, res, next) => {
  console.error("Erro na API:", err.message);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    success: false,
    message: "Erro interno do servidor.",
  });
});

// Inicialização
app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Agência Marks API online na porta ${PORT} (${NODE_ENV}).`
  );
});
