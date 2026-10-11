const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json({ limit: "1mb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

const JWT_SECRET = process.env.JWT_SECRET;
const ENCRYPTION_SECRET = process.env.KEY_ENCRYPTION_SECRET;
const WHATSAPP_VERIFY_TOKEN =
  process.env.WHATSAPP_VERIFY_TOKEN;

const META_VERSION =
  process.env.WHATSAPP_API_VERSION || "v23.0";

if (!JWT_SECRET) {
  console.error("ERRO: JWT_SECRET não configurado.");
}

if (!ENCRYPTION_SECRET) {
  console.error(
    "ERRO: KEY_ENCRYPTION_SECRET não configurado."
  );
}

function createToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: "7d"
  });
}

function authenticate(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Faça login para continuar."
    });
  }

  try {
    req.user = jwt.verify(
      header.slice(7),
      JWT_SECRET
    );

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Sessão expirada. Entre novamente."
    });
  }
}

function requireCompany(req, res, next) {
  authenticate(req, res, () => {
    if (
      req.user.role !== "company" ||
      !req.user.companyId
    ) {
      return res.status(403).json({
        success: false,
        message: "Acesso exclusivo para empresas."
      });
    }

    next();
  });
}

function requireAdmin(req, res, next) {
  authenticate(req, res, () => {
    if (req.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Acesso exclusivo ao administrador."
      });
    }

    next();
  });
}

function encryptToken(value) {
  if (!ENCRYPTION_SECRET) {
    throw new Error(
      "KEY_ENCRYPTION_SECRET não configurado."
    );
  }

  const key = crypto
    .createHash("sha256")
    .update(ENCRYPTION_SECRET)
    .digest();

  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    key,
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final()
  ]);

  const authTag = cipher.getAuthTag();

  return [
    iv.toString("hex"),
    authTag.toString("hex"),
    encrypted.toString("hex")
  ].join(":");
}

function decryptToken(value) {
  if (!ENCRYPTION_SECRET) {
    throw new Error(
      "KEY_ENCRYPTION_SECRET não configurado."
    );
  }

  const [ivHex, tagHex, encryptedHex] =
    value.split(":");

  const key = crypto
    .createHash("sha256")
    .update(ENCRYPTION_SECRET)
    .digest();

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(ivHex, "hex")
  );

  decipher.setAuthTag(
    Buffer.from(tagHex, "hex")
  );

  return Buffer.concat([
    decipher.update(
      Buffer.from(encryptedHex, "hex")
    ),
    decipher.final()
  ]).toString("utf8");
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS companies (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      company_key TEXT UNIQUE NOT NULL,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS automation_settings (
      company_id INTEGER PRIMARY KEY
        REFERENCES companies(id) ON DELETE CASCADE,
      settings JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS whatsapp_connections (
      company_id INTEGER PRIMARY KEY
        REFERENCES companies(id) ON DELETE CASCADE,
      phone_number_id TEXT NOT NULL,
      waba_id TEXT NOT NULL,
      encrypted_access_token TEXT NOT NULL,
      connected BOOLEAN DEFAULT TRUE,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS processed_whatsapp_messages (
      message_id TEXT PRIMARY KEY,
      processed_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  console.log("Banco de dados inicializado.");
}
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Pool } = require("pg");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json({ limit: "1mb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

const JWT_SECRET = process.env.JWT_SECRET;
const ENCRYPTION_SECRET = process.env.KEY_ENCRYPTION_SECRET;
const WHATSAPP_VERIFY_TOKEN =
  process.env.WHATSAPP_VERIFY_TOKEN;

const META_VERSION =
  process.env.WHATSAPP_API_VERSION || "v23.0";

if (!JWT_SECRET) {
  console.error("ERRO: JWT_SECRET não configurado.");
}

if (!ENCRYPTION_SECRET) {
  console.error(
    "ERRO: KEY_ENCRYPTION_SECRET não configurado."
  );
}

function createToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: "7d"
  });
}

function authenticate(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Faça login para continuar."
    });
  }

  try {
    req.user = jwt.verify(
      header.slice(7),
      JWT_SECRET
    );

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Sessão expirada. Entre novamente."
    });
  }
}

function requireCompany(req, res, next) {
  authenticate(req, res, () => {
    if (
      req.user.role !== "company" ||
      !req.user.companyId
    ) {
      return res.status(403).json({
        success: false,
        message: "Acesso exclusivo para empresas."
      });
    }

    next();
  });
}

function requireAdmin(req, res, next) {
  authenticate(req, res, () => {
    if (req.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Acesso exclusivo ao administrador."
      });
    }

    next();
  });
}

function encryptToken(value) {
  if (!ENCRYPTION_SECRET) {
    throw new Error(
      "KEY_ENCRYPTION_SECRET não configurado."
    );
  }

  const key = crypto
    .createHash("sha256")
    .update(ENCRYPTION_SECRET)
    .digest();

  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    key,
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final()
  ]);

  const authTag = cipher.getAuthTag();

  return [
    iv.toString("hex"),
    authTag.toString("hex"),
    encrypted.toString("hex")
  ].join(":");
}

function decryptToken(value) {
  if (!ENCRYPTION_SECRET) {
    throw new Error(
      "KEY_ENCRYPTION_SECRET não configurado."
    );
  }

  const [ivHex, tagHex, encryptedHex] =
    value.split(":");

  const key = crypto
    .createHash("sha256")
    .update(ENCRYPTION_SECRET)
    .digest();

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(ivHex, "hex")
  );

  decipher.setAuthTag(
    Buffer.from(tagHex, "hex")
  );

  return Buffer.concat([
    decipher.update(
      Buffer.from(encryptedHex, "hex")
    ),
    decipher.final()
  ]).toString("utf8");
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS companies (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      company_key TEXT UNIQUE NOT NULL,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS automation_settings (
      company_id INTEGER PRIMARY KEY
        REFERENCES companies(id) ON DELETE CASCADE,
      settings JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS whatsapp_connections (
      company_id INTEGER PRIMARY KEY
        REFERENCES companies(id) ON DELETE CASCADE,
      phone_number_id TEXT NOT NULL,
      waba_id TEXT NOT NULL,
      encrypted_access_token TEXT NOT NULL,
      connected BOOLEAN DEFAULT TRUE,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS processed_whatsapp_messages (
      message_id TEXT PRIMARY KEY,
      processed_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  console.log("Banco de dados inicializado.");
}
// ==========================================
// WHATSAPP CLOUD API — CONEXÃO E VALIDAÇÃO
// ==========================================

async function metaRequest(url, options = {}) {
  const response = await fetch(url, options);
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const error = new Error(
      data.error?.message || "Erro na comunicação com a Meta."
    );

    error.status = response.status;
    error.metaError = data.error;
    throw error;
  }

  return data;
}

async function validateWhatsAppCredentials(
  phoneNumberId,
  wabaId,
  accessToken
) {
  if (!phoneNumberId || !wabaId || !accessToken) {
    throw new Error(
      "Informe Phone Number ID, WABA ID e Access Token."
    );
  }

  const baseUrl =
    `https://graph.facebook.com/${META_VERSION}`;

  const phone = await metaRequest(
    `${baseUrl}/${encodeURIComponent(phoneNumberId)}?fields=id,display_phone_number,verified_name`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    }
  );

  const account = await metaRequest(
    `${baseUrl}/${encodeURIComponent(wabaId)}/phone_numbers?fields=id,display_phone_number,verified_name`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`
      }
    }
  );

  const belongsToAccount =
    Array.isArray(account.data) &&
    account.data.some(
      item => String(item.id) === String(phoneNumberId)
    );

  if (!belongsToAccount) {
    throw new Error(
      "O número informado não foi encontrado nessa conta do WhatsApp Business."
    );
  }

  return {
    phoneNumberId: phone.id,
    wabaId,
    displayPhoneNumber:
      phone.display_phone_number || "",
    verifiedName: phone.verified_name || ""
  };
}


// Conectar WhatsApp da empresa autenticada
app.post(
  "/api/automation/whatsapp/connect",
  requireCompany,
  async (req, res) => {
    try {
      const {
        phoneNumberId,
        wabaId,
        accessToken
      } = req.body;

      if (
        typeof phoneNumberId !== "string" ||
        typeof wabaId !== "string" ||
        typeof accessToken !== "string" ||
        !phoneNumberId.trim() ||
        !wabaId.trim() ||
        !accessToken.trim()
      ) {
        return res.status(400).json({
          success: false,
          message: "Preencha os três campos de conexão."
        });
      }

      const phoneId = phoneNumberId.trim();
      const businessAccountId = wabaId.trim();
      const token = accessToken.trim();

      const validation =
        await validateWhatsAppCredentials(
          phoneId,
          businessAccountId,
          token
        );

      const encryptedToken = encryptToken(token);

      await pool.query(
        `INSERT INTO whatsapp_connections
          (
            company_id,
            phone_number_id,
            waba_id,
            encrypted_access_token,
            connected,
            updated_at
          )
         VALUES ($1, $2, $3, $4, TRUE, NOW())
         ON CONFLICT (company_id)
         DO UPDATE SET
           phone_number_id = EXCLUDED.phone_number_id,
           waba_id = EXCLUDED.waba_id,
           encrypted_access_token =
             EXCLUDED.encrypted_access_token,
           connected = TRUE,
           updated_at = NOW()`,
        [
          req.user.companyId,
          phoneId,
          businessAccountId,
          encryptedToken
        ]
      );

      return res.json({
        success: true,
        message: "WhatsApp conectado e credenciais validadas.",
        connection: {
          connected: true,
          phoneNumberId: validation.phoneNumberId,
          wabaId: validation.wabaId,
          displayPhoneNumber:
            validation.displayPhoneNumber,
          verifiedName: validation.verifiedName
        }
      });
    } catch (error) {
      console.error(
        "Erro na conexão WhatsApp:",
        error.metaError?.message || error.message
      );

      return res.status(400).json({
        success: false,
        message:
          error.message ||
          "Não foi possível conectar o WhatsApp."
      });
    }
  }
);


// Consultar estado da conexão e validar o token novamente
app.get(
  "/api/automation/whatsapp/status",
  requireCompany,
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT phone_number_id, waba_id,
                encrypted_access_token, connected
         FROM whatsapp_connections
         WHERE company_id = $1`,
        [req.user.companyId]
      );

      if (
        result.rows.length === 0 ||
        !result.rows[0].connected
      ) {
        return res.json({
          success: true,
          connected: false,
          message: "WhatsApp ainda não conectado."
        });
      }

      const connection = result.rows[0];

      try {
        const token = decryptToken(
          connection.encrypted_access_token
        );

        const validation =
          await validateWhatsAppCredentials(
            connection.phone_number_id,
            connection.waba_id,
            token
          );

        return res.json({
          success: true,
          connected: true,
          connection: {
            phoneNumberId: validation.phoneNumberId,
            wabaId: validation.wabaId,
            displayPhoneNumber:
              validation.displayPhoneNumber,
            verifiedName: validation.verifiedName
          }
        });
      } catch (validationError) {
        console.error(
          "Falha ao validar conexão WhatsApp:",
          validationError.message
        );

        return res.json({
          success: true,
          connected: false,
          message:
            "As credenciais precisam ser verificadas. Confira o token e as permissões da Meta."
        });
      }
    } catch (error) {
      console.error(
        "Erro ao consultar WhatsApp:",
        error.message
      );

      return res.status(500).json({
        success: false,
        message: "Erro ao consultar a conexão."
      });
    }
  }
);


// Desconectar WhatsApp
app.delete(
  "/api/automation/whatsapp/connect",
  requireCompany,
  async (req, res) => {
    try {
      await pool.query(
        `DELETE FROM whatsapp_connections
         WHERE company_id = $1`,
        [req.user.companyId]
      );

      return res.json({
        success: true,
        connected: false,
        message: "WhatsApp desconectado."
      });
    } catch (error) {
      console.error(
        "Erro ao desconectar WhatsApp:",
        error.message
      );

      return res.status(500).json({
        success: false,
        message: "Não foi possível desconectar."
      });
    }
  }
);


// ==========================================
// ENVIO DE MENSAGENS PELO WHATSAPP
// ==========================================

async function sendWhatsAppMessage(
  phoneNumberId,
  accessToken,
  recipient,
  message
) {
  const url =
    `https://graph.facebook.com/${META_VERSION}/${encodeURIComponent(phoneNumberId)}/messages`;

  return metaRequest(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      messaging_product: "whatsapp",
      recipient_type: "individual",
      to: recipient,
      type: "text",
      text: {
        preview_url: false,
        body: message
      }
    })
  });
}


// ==========================================
// WEBHOOK — VERIFICAÇÃO DA META
// ==========================================

app.get(
  "/api/webhooks/whatsapp",
  (req, res) => {
    const mode = req.query["hub.mode"];
    const token = req.query["hub.verify_token"];
    const challenge = req.query["hub.challenge"];

    if (
      mode === "subscribe" &&
      WHATSAPP_VERIFY_TOKEN &&
      token === WHATSAPP_VERIFY_TOKEN
    ) {
      return res.status(200).send(challenge);
    }

    return res.sendStatus(403);
  }
);


// ==========================================
// WEBHOOK — RECEBER MENSAGENS
// ==========================================

app.post(
  "/api/webhooks/whatsapp",
  async (req, res) => {
    // Responder rapidamente à Meta.
    res.sendStatus(200);

    try {
      const body = req.body;

      if (
        body.object !== "whatsapp_business_account" ||
        !Array.isArray(body.entry)
      ) {
        return;
      }

      for (const entry of body.entry) {
        if (!Array.isArray(entry.changes)) continue;

        for (const change of entry.changes) {
          if (change.field !== "messages") continue;

          const value = change.value || {};
          const messages = value.messages || [];
          const metadata = value.metadata || {};

          for (const message of messages) {
            if (
              !message.id ||
              message.type !== "text" ||
              !message.text?.body ||
              !message.from
            ) {
              continue;
            }

            // Impede processar novamente mensagens já registradas.
            const inserted = await pool.query(
              `INSERT INTO processed_whatsapp_messages
                (message_id)
               VALUES ($1)
               ON CONFLICT DO NOTHING
               RETURNING message_id`,
              [message.id]
            );

            if (inserted.rows.length === 0) {
              continue;
            }

            const phoneNumberId =
              metadata.phone_number_id;

            if (!phoneNumberId) continue;

            const connectionResult = await pool.query(
              `SELECT company_id,
                      encrypted_access_token
               FROM whatsapp_connections
               WHERE phone_number_id = $1
                 AND connected = TRUE`,
              [phoneNumberId]
            );

            if (connectionResult.rows.length === 0) {
              continue;
            }

            const connection =
              connectionResult.rows[0];

            const settingsResult = await pool.query(
              `SELECT settings
               FROM automation_settings
               WHERE company_id = $1`,
              [connection.company_id]
            );

            const settings =
              settingsResult.rows[0]?.settings || {};

            if (
              settings.automationEnabled !== true ||
              settings.autoReply !== true
            ) {
              continue;
            }

            const incomingText =
              message.text.body.trim();

            if (!incomingText) continue;

            const openAIKey =
              process.env.OPENAI_API_KEY;

            if (!openAIKey) {
              console.error(
                "OPENAI_API_KEY não configurada."
              );
              continue;
            }

            const aiResponse = await fetch(
              "https://api.openai.com/v1/chat/completions",
              {
                method: "POST",
                headers: {
                  Authorization: `Bearer ${openAIKey}`,
                  "Content-Type": "application/json"
                },
                body: JSON.stringify({
                  model:
                    process.env.OPENAI_MODEL ||
                    "gpt-4o-mini",
                  messages: [
                    {
                      role: "system",
                      content:
                        typeof settings.systemPrompt === "string" &&
                        settings.systemPrompt.trim()
                          ? settings.systemPrompt
                          : "Você é um atendente virtual educado e profissional. Responda em português brasileiro, com mensagens breves. Não invente preços, disponibilidade, endereços ou condições. Quando não souber, diga que um atendente humano poderá ajudar."
                    },
                    {
                      role: "user",
                      content: incomingText
                    }
                  ],
                  temperature: 0.5
                })
              }
            );

            const aiData =
              await aiResponse.json().catch(() => ({}));

            if (!aiResponse.ok) {
              console.error(
                "Erro ao gerar resposta da IA:",
                aiData.error?.message ||
                  aiResponse.status
              );
              continue;
            }

            const reply =
              aiData.choices?.[0]?.message?.content?.trim();

            if (!reply) continue;

            const accessToken = decryptToken(
              connection.encrypted_access_token
            );

            await sendWhatsAppMessage(
              phoneNumberId,
              accessToken,
              message.from,
              reply
            );
          }
        }
      }
    } catch (error) {
      console.error(
        "Erro ao processar webhook WhatsApp:",
        error.message
      );
    }
  }
);


// ==========================================
// STATUS DO BANCO E ROTA INICIAL
// ==========================================

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Agência Marks API online."
  });
});

app.get("/api/db-status", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    return res.json({
      success: true,
      database: "online"
    });
  } catch (error) {
    console.error("Erro no banco:", error.message);

    return res.status(500).json({
      success: false,
      database: "offline"
    });
  }
});


// ==========================================
// INICIAR SERVIDOR
// ==========================================

async function startServer() {
  try {
    await initializeDatabase();

    app.listen(PORT, () => {
      console.log(
        `Agência Marks API rodando na porta ${PORT}.`
      );
    });
  } catch (error) {
    console.error(
      "Não foi possível iniciar o servidor:",
      error
    );

    process.exit(1);
  }
}

startServer();
