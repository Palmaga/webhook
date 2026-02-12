import express, { Request, Response } from "express";
import crypto from "crypto";

const PORT = process.env.PORT || 3000;
const app = express();
app.use(express.json());

// --- GESTIÓN DE LA LLAVE ---
const getPrivateKey = () => {
  try {
    const rawKey = process.env.PRIVATE_KEY;
    if (!rawKey) throw new Error("La variable PRIVATE_KEY está vacía");

    // Limpieza profunda: Si pegaste desde Linux, convertimos saltos de línea literales
    const formattedKey = rawKey.replace(/\\n/g, '\n');

    return crypto.createPrivateKey({
      key: formattedKey,
      format: 'pem',
      passphrase: process.env.PASSPHRASE // Asegúrate de que esta variable exista
    });
  } catch (err: any) {
    console.error("❌ ERROR CRÍTICO AL CARGAR LA LLAVE PRIVADA:");
    console.error(err.message);
    // En lugar de dejar que explote con código 1, lanzamos un error controlado
    return null;
  }
};

const PRIVATE_KEY_OBJECT = getPrivateKey();

// --- ENDPOINT ---
app.post("/data", async (req: Request, res: Response) => {
  if (!PRIVATE_KEY_OBJECT) {
    return res.status(500).json({ error: "Servidor no configurado: Llave privada inválida" });
  }

  try {
    const { decryptedBody, aesKeyBuffer, initialVectorBuffer } = decryptRequest(
      req.body,
      PRIVATE_KEY_OBJECT
    );

    // Respuesta de ejemplo para Meta
    const screenData = {
      screen: "SUCCESS",
      data: { message: "Listo" }
    };

    const encryptedResponse = encryptResponse(screenData, aesKeyBuffer, initialVectorBuffer);
    res.status(200).send(encryptedResponse);
  } catch (error: any) {
    console.error("Error en procesamiento:", error.message);
    res.status(400).send("Error de descifrado");
  }
});

// --- FUNCIONES CORE ---
function decryptRequest(body: any, privateKey: crypto.KeyObject) {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

  const decryptedAesKey = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(encrypted_aes_key, "base64")
  );

  const flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");
  const initialVectorBuffer = Buffer.from(initial_vector, "base64");

  const TAG_LENGTH = 16;
  const encryptedBody = flowDataBuffer.subarray(0, -TAG_LENGTH);
  const authTag = flowDataBuffer.subarray(-TAG_LENGTH);

  const decipher = crypto.createDecipheriv("aes-128-gcm", decryptedAesKey, initialVectorBuffer);
  decipher.setAuthTag(authTag);

  const decryptedJSONString = Buffer.concat([
    decipher.update(encryptedBody),
    decipher.final(),
  ]).toString("utf-8");

  return {
    decryptedBody: JSON.parse(decryptedJSONString),
    aesKeyBuffer: decryptedAesKey,
    initialVectorBuffer,
  };
}

function encryptResponse(response: any, aesKeyBuffer: Buffer, initialVectorBuffer: Buffer) {
  const flipped_iv = Buffer.from(initialVectorBuffer.map((byte) => ~byte));
  const cipher = crypto.createCipheriv("aes-128-gcm", aesKeyBuffer, flipped_iv);

  return Buffer.concat([
    cipher.update(JSON.stringify(response), "utf-8"),
    cipher.final(),
    cipher.getAuthTag(),
  ]).toString("base64");
}

app.listen(PORT, () => {
  console.log(`🚀 Servidor en puerto ${PORT}`);
});
