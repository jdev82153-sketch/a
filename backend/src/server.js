
require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;

app.disable("x-powered-by");

app.use(helmet());

app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:5500",
  credentials: true
}));

app.use(express.json({ limit: "20kb" }));

app.get("/api/health", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Agência Marks API está funcionando.",
    status: "online"
  });
});

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Rota não encontrada."
  });
});

app.use((err, req, res, next) => {
  console.error(err);

  res.status(500).json({
    success: false,
    message: "Erro interno do servidor."
  });
});

app.listen(PORT, () => {
  console.log(`Agência Marks API rodando na porta ${PORT}`);
});

