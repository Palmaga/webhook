const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

const PORT = process.env.PORT || 3000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;

// COPIA Y PEGA TU CLAVE COMPLETA ENTRE LAS COMILLAS INVERTIDAS
const PRIVATE_KEY = `-----BEGIN ENCRYPTED PRIVATE KEY-----
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
-----END ENCRYPTED PRIVATE KEY-----
`;

// --- UTILIDADES DE CRIPTOGRAFÍA ---

function decryptRequest(body, privateKey) {
    const { encrypted_flow_data, encrypted_aes_key, initial_vector } = body;

    const decryptedAesKey = crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        Buffer.from(encrypted_aes_key, 'base64')
    );

    const flowDataBuffer = Buffer.from(encrypted_flow_data, 'base64');
    const iv = Buffer.from(initial_vector, 'base64');
    const tag = flowDataBuffer.slice(-16);
    const encryptedData = flowDataBuffer.slice(0, -16);

    const decipher = crypto.createDecipheriv('aes-128-gcm', decryptedAesKey, iv);
    decipher.setAuthTag(tag);

    let decrypted = decipher.update(encryptedData, 'binary', 'utf8');
    decrypted += decipher.final('utf8');

    return { decrypted: JSON.parse(decrypted), aesKey: decryptedAesKey };
}

function encryptResponse(responseJson, aesKey, ivString) {
    const iv = Buffer.from(ivString, 'base64');
    const cipher = crypto.createCipheriv('aes-128-gcm', aesKey, iv);
    
    let encrypted = cipher.update(JSON.stringify(responseJson), 'utf8', 'base64');
    encrypted += cipher.final('base64');
    
    const tag = cipher.getAuthTag().toString('base64');
    return Buffer.from(encrypted + tag, 'base64').toString('base64');
}

// --- RUTAS DEL SERVIDOR ---

app.get('/', (req, res) => {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
        const response = Buffer.from(challenge).toString('base64');
        return res.status(200).send(response);
    }
    res.status(403).end();
});

app.post('/', (req, res) => {
    try {
        const { decrypted, aesKey } = decryptRequest(req.body, PRIVATE_KEY);
        console.log("Datos recibidos:", decrypted);

        const responseJSON = {
            version: "3.0",
            screen: "SUCCESS",
            data: {
                extension_message_response: {
                    params: {
                        status: "success",
                        message: `Referencia ${decrypted.referencia} procesada.`
                    }
                }
            }
        };

        const encryptedB64Response = encryptResponse(responseJSON, aesKey, req.body.initial_vector);
        res.set('Content-Type', 'text/plain');
        res.status(200).send(encryptedB64Response);

    } catch (error) {
        console.error("Detalle del error:", error);
        res.status(500).send(`Error de descifrado: ${error.message}`);
    }
});

app.listen(PORT, () => console.log(`Servidor de prueba en puerto ${PORT}`));
