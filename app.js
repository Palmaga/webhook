import express from "express";
import crypto from "crypto";

const PORT = process.env.PORT || 3000;
const app = express();
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || "mi_token_123";
const PRIVATE_KEY = process.env.PRIVATE_KEY as string;

app.use(express.json({
    verify: (req: any, res, buf) => {
        req.rawBody = buf;
    }
}));

// ✅ 1. VERIFICACIÓN DEL WEBHOOK - OBLIGATORIO
app.get('/', (req, res) => {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
        console.log('✅ Webhook verificado');
        return res.status(200).send(String(challenge));
    }
    res.status(403).end();
});

// ✅ 2. DECRYPT - CORREGIDO A AES-128-CBC
const decryptRequest = (body: any, privatePem: string) => {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

    // Decrypt AES key
    const decryptedAesKey = crypto.privateDecrypt(
        {
            key: crypto.createPrivateKey(privatePem),
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256",
        },
        Buffer.from(encrypted_aes_key, "base64"),
    );

    // Decrypt Flow data - AES-128-CBC (NO GCM)
    const iv = Buffer.from(initial_vector, "base64");
    const encryptedData = Buffer.from(encrypted_flow_data, "base64");

    const decipher = crypto.createDecipheriv("aes-128-cbc", decryptedAesKey, iv);
    decipher.setAutoPadding(true);

    const decrypted = Buffer.concat([
        decipher.update(encryptedData),
        decipher.final()
    ]);

    return {
        decryptedBody: JSON.parse(decrypted.toString("utf-8")),
        aesKeyBuffer: decryptedAesKey,
        initialVectorBuffer: iv,
    };
};

// ✅ 3. ENCRYPT - CORREGIDO A AES-128-CBC SIN FLIP
const encryptResponse = (
    response: any,
    aesKeyBuffer: Buffer,
    initialVectorBuffer: Buffer,
) => {
    // Usar el MISMO IV, sin flip
    const cipher = crypto.createCipheriv("aes-128-cbc", aesKeyBuffer, initialVectorBuffer);
    cipher.setAutoPadding(true);

    return Buffer.concat([
        cipher.update(JSON.stringify(response), "utf-8"),
        cipher.final()
    ]).toString("base64");
};

// ✅ 4. ENDPOINT PRINCIPAL - POST / (NO /data)
app.post('/', async ({ body }, res) => {
    try {
        // Health Check
        if (body.health_check) {
            return res.json({ status: 'healthy' });
        }

        // Error Notification
        if (body.error && body.flow_id) {
            console.log('Error notification:', body.error);
            return res.status(200).end();
        }

        // Flow Data Exchange
        if (!body.encrypted_flow_data || !body.encrypted_aes_key || !body.initial_vector) {
            return res.status(200).end();
        }

        const { decryptedBody, aesKeyBuffer, initialVectorBuffer } = decryptRequest(
            body,
            PRIVATE_KEY,
        );

        console.log('📡 Flow recibido:', JSON.stringify(decryptedBody, null, 2));

        const { screen, data, version, action, flow_token } = decryptedBody;

        // ✅ 5. RESPUESTA CON TODOS LOS CAMPOS REQUERIDOS
        let responseData: any = {
            version: "3.0",              // ✅ REQUERIDO
            flow_token: flow_token,      // ✅ REQUERIDO
        };

        // CASO 1: INIT - Abrir Flow
        if (action === 'INIT' || (action === 'data_exchange' && !screen)) {
            responseData.screen = screen || 'WELCOME';
            // NO incluir data
        }
        // CASO 2: data_exchange - Enviar formulario
        else if (action === 'data_exchange' && screen) {
            responseData.screen = decryptedBody.next_screen || 'CONFIRMATION';
            responseData.data = {
                ...data,
                status: 'success',
                processed_at: new Date().toISOString()
            };
        }
        // CASO 3: BACK - Botón atrás
        else if (action === 'BACK') {
            responseData.screen = decryptedBody.previous_screen || 'PREVIOUS_SCREEN';
            // NO incluir data
        }
        // CASO 4: component_change - Cambio de componente
        else if (decryptedBody.component_id) {
            responseData.screen = screen;
            responseData.data = {
                ...data,
                [decryptedBody.component_id]: decryptedBody.component_value
            };
        }
        // Default
        else {
            responseData.screen = screen || 'RESPONSE';
            if (data) {
                responseData.data = data;
            }
        }

        // Encrypt y enviar
        const encryptedResponse = encryptResponse(
            responseData,
            aesKeyBuffer,
            initialVectorBuffer
        );

        console.log('✅ Respondiendo con Base64');
        res.set('Content-Type', 'text/plain');
        res.status(200).send(encryptedResponse);

    } catch (error) {
        console.error('❌ Error:', error);
        res.status(200).end();
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`
╔════════════════════════════════════════════╗
║    🚀 FLOW WEBHOOK - PRODUCCIÓN           ║
╠════════════════════════════════════════════╣
║  📍 Endpoint: POST /                      ║
║  📍 Puerto: ${PORT}                           ║
║  🔐 Cipher: AES-128-CBC (CORRECTO)        ║
║  ✅ IV Flip: NO (CORRECTO)               ║
╚════════════════════════════════════════════╝
    `);
});
