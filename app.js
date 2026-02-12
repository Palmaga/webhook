import express, { Request, Response } from "express";
import crypto from "crypto";

const PORT = process.env.PORT || 3000;
const app = express();
app.use(express.json());

// 1. COLOCA TU CLAVE AQUÍ ABAJO
// Copia y pega TAL CUAL sale en tu terminal de Linux
const PRIVATE_KEY_STRING = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIOSMqpgOTAKgCAggA
MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECGXonuaPlXAwBIIEyB3NpmZPFaE1
/YXaXQe11cuvMX47lAVvP7vU/w2k1eNpVjWBfcIS0cLbG+7V1U16GKMt4+fDETTY
KgJfaLKS6ARspvX96+g/shcqT0UOeFn/vBFpgCIWToOlGpLESBNXCquOqG0zmipa
cWJF1ST18Y2xx976EAY8J83o4Q1XQZlrknirbrt0b87SoCoweEN0uwxWhy1KGyIB
qCLDwzHBJrtT8GBBmUnHpJfB0sxkrvUxizEZKufmT56WVyAwW09LYSf7p95qBrEZ
relzcx1jn7alV9eYxn2kkpDTbZNPcNWxvvGoulEEkIK4WE9pwxAbe7Od+TpzId7a
/CTRtT1sKCsHxJSZzrH3Lff1iQqVxyuI0yikwGwsrZgXlJXYnW+ZjfZ2v3ZbdRl8
+NeOm7FqWn0IgnLUd+MMk7f64b5ZfibKJ9skD7CYWjHhRIsLQhrv120P9AXfOUpL
MvdpRLw3JEnEqxHZGOvzhqkUBHIoMLs3cTzzPEJh6xvibexR6nMH5UKKTCae7mQp
Xc1Wt+VYtd6I+83QHdNjT6gWJMyLCnFLjr/x4w0yFv2Q7mTWIvsUp2g6StRiZYFL
nb9iERD1GpJMuSvo97VTiBBjWci/IbHhKNkoXc0/yQFB/SNHO4LiCxGxHV8xgapk
xPbCmpNgms+GU+o6vouu7Rh4ra6r7IREw+hNafRha/0VVKUSixCZt8nRr2Nl9J0p
2VZdW94gJi6g84d1hHnzkUwv1xxvjT6BODj0ZELozyh+xGDbpjSgK8iZD+SOVrkI
yiTKKNHVG43YGH9Blq/n5JH2RlNIZalxI9w7DheZ7ueJY1MB4rX/T4GpdmXlo1Bo
MbEHO8Xw6hCqnVj0/0a+7UkSuorcMryyk0UbnXHqOezjnxPDtFJEmUSnAN2FA5k6
HIggKA9SN/zFvB1CgH8ypYnXkWrKivExvHmcnHG3EVRpcgRj9BYlLbaxaskaDP9E
8mD3jFXY7iIKTW1XTb5XU78eTcsb4mP3usU87/SV7xO5CHiU2fi4MemBn0at+3rM
/HWBcFmmxhheVB86xwlhCtYIBXJClp9NKZ25XKTpQShEXyi4iVaoCIuzvc9YwPBv
HCWZLZN7vs0d47BRY0rrUJ2DHGHecXzyvXDi5B2ij/V5Jd0cQkYV9bK+ShGD1NUN
LPv1yHdIUh2+dg9KfZNupFkrPibjPknquvUTfQcS0YwDWjYuyBwJVONrqRPabIqN
erzT9jX7hGjP4PM7aCfJhXRQxythn5H+lDpsP0Xz164X4J+w3kOfhnCdRHCfICkm
eGYpsJ+eE2r0kBhkK9loOp7sEz86EcSM5hnxpUTPKCWMplu4u//hLDL+iaU+PQ7q
Gv1tcWoOy4rCP8JFgIMEQbu90DUQTbpwSrvKhqFnMo/QNaoKN1YTzQ9TjCDKLDjm
/JfpZ8jUDkf3ISuR+AP5iKCCErfwA+jF0TW4Jl9VdPqVwMM0tfzTezzq4c28LdZ/
2ieq0gDLmYNYS+aV+UBBFNrViNLS+SzRSCvqDDc8cfctC4Id+SkD3igZqC3kRxGs
Bw8Ks7GjBY4vHtyLkco6SVJfB0hGekfeNaGX962sMroS9OVl7AAfMr0nqe7e5oZE
dxM8BPgvtJJBLRqm7u6aQA==
-----END ENCRYPTED PRIVATE KEY-----`;

// 2. COLOCA TU CONTRASEÑA AQUÍ
const PASSPHRASE = "Palma";

/**
 * Función para inicializar la llave de forma segura
 */
const getPrivateKey = () => {
  try {
    return crypto.createPrivateKey({
      key: PRIVATE_KEY_STRING,
      format: 'pem',
      passphrase: PASSPHRASE,
    });
  } catch (err: any) {
    console.error("❌ ERROR CARGANDO LA LLAVE: Revisa el formato o la contraseña.");
    console.error("Detalle:", err.message);
    return null;
  }
};

const PRIVATE_KEY_OBJECT = getPrivateKey();

app.post("/data", async (req: Request, res: Response) => {
  if (!PRIVATE_KEY_OBJECT) {
    return res.status(500).send("Error: Llave privada no configurada.");
  }

  try {
    const { decryptedBody, aesKeyBuffer, initialVectorBuffer } = decryptRequest(
      req.body,
      PRIVATE_KEY_OBJECT
    );

    // Ejemplo de respuesta que espera Meta
    const screenData = {
      screen: "SUCCESS",
      data: { status: "completado" }
    };

    res.status(200).send(encryptResponse(screenData, aesKeyBuffer, initialVectorBuffer));
  } catch (error: any) {
    console.error("Error en el Flow:", error.message);
    res.status(400).send("Error de descifrado");
  }
});

// --- Lógica de Cifrado (No cambiar) ---

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

  return { decryptedBody: JSON.parse(decryptedJSONString), aesKeyBuffer: decryptedAesKey, initialVectorBuffer };
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
  console.log(`🚀 Servidor activo en puerto ${PORT}`);
});
