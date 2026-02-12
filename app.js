import express, { Request, Response } from "express";
import crypto from "crypto";

const PORT = process.env.PORT || 3000;
const app = express();

app.use(express.json());

/**
 * FUNCIÓN PARA FORMATEAR LA LLAVE
 * Esta función toma lo que pegaste y asegura que tenga los encabezados
 * y el formato que Node.js espera.
 */
const formatPrivateKey = (key: string): string => {
  // 1. Quitamos espacios o saltos de línea accidentales al inicio/final
  let cleanKey = key.trim();
  
  // 2. Si la llave no tiene los encabezados, no funcionará. 
  // Pero si los tiene y están en una sola línea, necesitamos asegurar que 
  // Node.js la reconozca. El método más seguro es este:
  if (!cleanKey.startsWith('-----BEGIN')) {
     throw new Error("La llave no tiene el formato PEM correcto.");
  }

  return cleanKey.replace(/\\n/g, '\n');
};

const PRIVATE_KEY = formatPrivateKey(process.env.PRIVATE_KEY as string);
const PASSPHRASE = process.env.PASSPHRASE || "Palma";

app.post("/data", async (req: Request, res: Response) => {
  try {
    const { decryptedBody, aesKeyBuffer, initialVectorBuffer } = decryptRequest(
      req.body,
      PRIVATE_KEY,
      PASSPHRASE
    );

    // Tu lógica de negocio aquí
    const screenData = {
      screen: "SUCCESS_SCREEN",
      data: { status: "ok" },
    };

    const encryptedResponse = encryptResponse(screenData, aesKeyBuffer, initialVectorBuffer);
    res.status(200).send(encryptedResponse);

  } catch (error: any) {
    console.error("Error crítico:", error.message);
    res.status(400).send("Error en el formato de la llave o descifrado.");
  }
});

const decryptRequest = (body: any, privatePem: string, passphrase: string) => {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

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
  console.log(`🚀 Endpoint validado y corriendo en puerto ${PORT}`);
});
