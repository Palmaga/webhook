const express = require('express');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const app = express();
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || 'webhook_token_123';

// ✅ USA LLAVE PRIVADA NORMAL, NO ENCRIPTADA
const PRIVATE_KEY = process.env.PRIVATE_KEY; // PEM sin encriptar

if (!PRIVATE_KEY) {
    console.error('❌ ERROR: PRIVATE_KEY es obligatoria');
    process.exit(1);
}

app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf;
    }
}));

// ✅ VERIFICACIÓN OBLIGATORIA
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

// ✅ DECRYPT - AES-128-CBC (CORRECTO)
function decryptRequest(body, privatePem) {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

    // Desencriptar AES key con RSA
    const decryptedAesKey = crypto.privateDecrypt(
        {
            key: privatePem,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
        },
        Buffer.from(encrypted_aes_key, 'base64')
    );

    // Desencriptar flow data con AES-128-CBC
    const iv = Buffer.from(initial_vector, 'base64');
    const encryptedData = Buffer.from(encrypted_flow_data, 'base64');

    const decipher = crypto.createDecipheriv('aes-128-cbc', decryptedAesKey, iv);
    decipher.setAutoPadding(true);

    const decrypted = Buffer.concat([
        decipher.update(encryptedData),
        decipher.final()
    ]);

    return {
        decryptedBody: JSON.parse(decrypted.toString('utf-8')),
        aesKeyBuffer: decryptedAesKey,
        initialVectorBuffer: iv
    };
}

// ✅ ENCRYPT - AES-128-CBC (CORRECTO)
function encryptResponse(response, aesKeyBuffer, initialVectorBuffer) {
    // USAR EL MISMO IV, SIN FLIP
    const cipher = crypto.createCipheriv('aes-128-cbc', aesKeyBuffer, initialVectorBuffer);
    cipher.setAutoPadding(true);

    return Buffer.concat([
        cipher.update(JSON.stringify(response), 'utf-8'),
        cipher.final()
    ]).toString('base64');
}

// ✅ ENDPOINT PRINCIPAL - POST /
app.post('/', (req, res) => {
    try {
        const body = req.body;

        // Health Check
        if (body.health_check) {
            return res.json({ status: 'healthy' });
        }

        // Error Notification
        if (body.error && body.flow_id) {
            console.log('Error notification:', body.error);
            return res.status(200).end();
        }

        // Validar Flow
        if (!body.encrypted_flow_data || !body.encrypted_aes_key || !body.initial_vector) {
            return res.status(200).end();
        }

        const { decryptedBody, aesKeyBuffer, initialVectorBuffer } = decryptRequest(
            body,
            PRIVATE_KEY
        );

        console.log('📡 Flow recibido:', JSON.stringify(decryptedBody, null, 2));

        // ✅ CONSTRUIR RESPUESTA - SIEMPRE INCLUIR version Y flow_token
        let responseData = {
            version: '3.0',
            flow_token: decryptedBody.flow_token
        };

        // CASO 1: INIT - Abrir Flow
        if (decryptedBody.action === 'INIT' || 
            (decryptedBody.action === 'data_exchange' && !decryptedBody.screen)) {
            responseData.screen = decryptedBody.screen || 'WELCOME';
        }
        // CASO 2: data_exchange - Enviar formulario
        else if (decryptedBody.action === 'data_exchange' && decryptedBody.screen) {
            responseData.screen = decryptedBody.next_screen || 'CONFIRMATION';
            responseData.data = {
                ...decryptedBody.data,
                status: 'success',
                processed_at: new Date().toISOString()
            };
        }
        // CASO 3: BACK - Botón atrás
        else if (decryptedBody.action === 'BACK') {
            responseData.screen = decryptedBody.previous_screen || 'PREVIOUS_SCREEN';
        }
        // CASO 4: component_change - Cambio de componente
        else if (decryptedBody.component_id) {
            responseData.screen = decryptedBody.screen;
            responseData.data = {
                ...decryptedBody.data,
                [decryptedBody.component_id]: decryptedBody.component_value
            };
        }
        // Default
        else {
            responseData.screen = decryptedBody.screen || 'RESPONSE';
            if (decryptedBody.data) {
                responseData.data = decryptedBody.data;
            }
        }

        // ⚠️ "SUCCESS" ES PALABRA RESERVADA - NO USAR
        if (responseData.screen === 'SUCCESS') {
            responseData.screen = 'CONFIRMATION';
        }

        // Encriptar y enviar
        const encryptedResponse = encryptResponse(
            responseData,
            aesKeyBuffer,
            initialVectorBuffer
        );

        res.set('Content-Type', 'text/plain');
        res.status(200).send(encryptedResponse);

    } catch (error) {
        console.error('❌ Error:', error.message);
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
║  🔐 Algoritmo: AES-128-CBC ✅            ║
║  🔑 Llave: PRIVATE KEY (no encriptada)   ║
║  ✅ Verificación: GET /                  ║
╚════════════════════════════════════════════╝
    `);
});
