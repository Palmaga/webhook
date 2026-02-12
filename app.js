import express, { Request, Response } from "express";
import crypto from "crypto";

const PORT = process.env.PORT || 3000;
const app = express();

app.use(express.json());

/**
 * CONFIGURACIÓN DE SEGURIDAD
 * Asegúrate de configurar estas variables en tu entorno (.env)
 */
const PRIVATE_KEY = process.env.PRIVATE_KEY?.replace(/\\n/g, '\n') as string;
const PASSPHRASE = process.env.PASSPHRASE || "Palma"; 

app.post("/data", async (req: Request, res: Response) => {
  try {
    // 1. Desencriptar la petición usando la llave con contraseña
    const { decryptedBody, aesKeyBuffer, initialVectorBuffer } = decryptRequest(
      req.body,
      PRIVATE_KEY,
      PASSPHRASE
    );

    console.log("Datos del Flow recibidos:", decryptedBody);

    // 2. Lógica de respuesta (Ejemplo de éxito)
    const screenData = {
      screen: "SUCCESS_SCREEN",
      data: {
        status: "proceso_completado",
      },
    };

    // 3. Encriptar respuesta para Meta
    const encryptedResponse = encryptResponse(screenData, aesKeyBuffer, initialVectorBuffer);
    res.status(200).send(encryptedResponse);

  } catch (error: any) {
    console.error("Error en el Flow:", error.message);
    res.status(400).send("Error de descifrado o formato de llave incorrecto");
  }
});

const decryptRequest = (body: any, privatePem: string, passphrase: string) => {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

  // IMPORTANTE: Se agrega 'passphrase' para manejar la ENCRYPTED PRIVATE KEY
  const decryptedAesKey = crypto.privateDecrypt(
    {
      key: crypto.createPrivateKey({
        key: privatePem,
        format: 'pem',
        passphrase: passphrase,
      }),
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
};

const encryptResponse = (response: any, aesKeyBuffer: Buffer, initialVectorBuffer: Buffer) => {
  const flipped_iv = Buffer.from(initialVectorBuffer.map((byte) => ~byte));
  const cipher = crypto.createCipheriv("aes-128-gcm", aesKeyBuffer, flipped_iv);

  return Buffer.concat([
    cipher.update(JSON.stringify(response), "utf-8"),
    cipher.final(),
    cipher.getAuthTag(),
  ]).toString("base64");
};

app.listen(PORT, () => {
  console.log(`🚀 Servidor listo en puerto ${PORT}`);
});
