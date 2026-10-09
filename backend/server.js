require("dotenv").config();

const express = require("express");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
    origin: process.env.FRONTEND_URL || "*"
}));

app.use(express.json());

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

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Agência Marks API rodando na porta ${PORT}`);
});
