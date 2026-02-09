const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

const PORT = process.env.PORT || 3000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
const PRIVATE_KEY = process.env.PRIVATE_KEY; // Incluir encabezados -----BEGIN PRIVATE KEY-----

// --- UTILIDADES DE CRIPTOGRAFÍA ---

function decryptRequest(body, privateKey) {
    const { encrypted_flow_data, encrypted_aes_key, initial_vector } = body;

    // 1. Descifrar la clave AES con RSA
    const decryptedAesKey = crypto.privateDecrypt(
        {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        Buffer.from(encrypted_aes_key, 'base64')
    );

    // 2. Descifrar datos con AES-128-GCM
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
    // Meta espera los datos cifrados seguidos del tag de autenticación
    return Buffer.from(encrypted + tag, 'base64').toString('base64');
}

// --- RUTAS DEL SERVIDOR ---

// Validación del Webhook (Configuración inicial)
app.get('/', (req, res) => {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
        console.log('WEBHOOK VERIFICADO');
        const response = Buffer.from(challenge).toString('base64');
        return res.status(200).send(response);
    }
    res.status(403).end();
});

// Procesamiento de datos del Flow (Pantalla DETAILS)
app.post('/', (req, res) => {
    try {
        const { decrypted, aesKey } = decryptRequest(req.body, PRIVATE_KEY);
        console.log("Datos del pago recibidos:", decrypted);

        // Respuesta para cerrar la pantalla 'DETAILS' con éxito
        const responseJSON = {
            version: "3.0",
            screen: "SUCCESS",
            data: {
                extension_message_response: {
                    params: {
                        status: "success",
                        message: `Reporte de ${decrypted.monto} Bs recibido.`
                    }
                }
            }
        };

        // Cifrar la respuesta de vuelta para Meta
        const encryptedB64Response = encryptResponse(responseJSON, aesKey, req.body.initial_vector);
        
        res.set('Content-Type', 'text/plain');
        res.status(200).send(encryptedB64Response);

    } catch (error) {
        console.error("Error procesando el Flow:", error.message);
        res.status(500).send("Error interno en el servidor de Flows");
    }
});

app.listen(PORT, () => console.log(`Servidor Flows ejecutándose en puerto ${PORT}`));
