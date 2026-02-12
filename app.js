const express = require('express');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const app = express();
const VERIFY_TOKEN = process.env.VERIFY_TOKEN;
const PRIVATE_KEY = process.env.PRIVATE_KEY;

if (!PRIVATE_KEY) {
    console.error('❌ ERROR: PRIVATE_KEY es obligatoria');
    process.exit(1);
}

app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf;
    }
}));

// ✅ VERIFICACIÓN
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

// ✅ DECRYPT - AES-128-CBC
function decryptRequest(body, privatePem) {
    const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

    const decryptedAesKey = crypto.privateDecrypt(
        {
            key: privatePem,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
        },
        Buffer.from(encrypted_aes_key, 'base64')
    );

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

// ✅ ENCRYPT - SIEMPRE BASE64
function encryptResponse(response, aesKeyBuffer, initialVectorBuffer) {
    const cipher = crypto.createCipheriv('aes-128-cbc', aesKeyBuffer, initialVectorBuffer);
    cipher.setAutoPadding(true);

    return Buffer.concat([
        cipher.update(JSON.stringify(response), 'utf-8'),
        cipher.final()
    ]).toString('base64');
}

// ✅ ENDPOINT PRINCIPAL - SIEMPRE BASE64
app.post('/', (req, res) => {
    try {
        const body = req.body;

        // ============================================
        // CASO 6: HEALTH CHECK
        // ============================================
        if (body.health_check) {
            const healthResponse = {
                status: 'healthy',
                timestamp: new Date().toISOString()
            };
            // ✅ SIEMPRE Base64
            const encrypted = Buffer.from(JSON.stringify(healthResponse)).toString('base64');
            res.set('Content-Type', 'text/plain');
            return res.status(200).send(encrypted);
        }

        // ============================================
        // CASO 5: ERROR NOTIFICATION
        // ============================================
        if (body.error && body.flow_id) {
            console.log('Error notification:', body.error);
            // ✅ SOLO 200 OK, sin body
            return res.status(200).end();
        }

        // ============================================
        // VALIDAR FLOW
        // ============================================
        if (!body.encrypted_flow_data || !body.encrypted_aes_key || !body.initial_vector) {
            return res.status(200).end();
        }

        // Desencriptar
        const { decryptedBody, aesKeyBuffer, initialVectorBuffer } = decryptRequest(
            body,
            PRIVATE_KEY
        );

        console.log('📡 Flow:', JSON.stringify(decryptedBody, null, 2));

        // ============================================
        // CONSTRUIR RESPUESTA
        // ============================================
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

        // ⚠️ "SUCCESS" es reservado
        if (responseData.screen === 'SUCCESS') {
            responseData.screen = 'CONFIRMATION';
        }

        // ✅ ENCRIPTAR Y ENVIAR BASE64
        const encryptedResponse = encryptResponse(
            responseData,
            aesKeyBuffer,
            initialVectorBuffer
        );

        console.log('✅ Respondiendo con Base64');
        res.set('Content-Type', 'text/plain');
        res.status(200).send(encryptedResponse);

    } catch (error) {
        console.error('❌ Error:', error.message);
        
        // ============================================
        // ⚠️ IMPORTANTE: SIEMPRE RESPONDER CON BASE64
        // ============================================
        const errorResponse = {
            version: '3.0',
            screen: 'ERROR',
            flow_token: req.body?.flow_token || 'error',
            data: {
                error: error.message,
                timestamp: new Date().toISOString()
            }
        };
        
        // Intentamos encriptar si tenemos los datos, sino Base64 fijo
        try {
            if (req.body?.encrypted_aes_key && req.body?.initial_vector) {
                const { aesKeyBuffer, initialVectorBuffer } = decryptRequest(
                    req.body,
                    PRIVATE_KEY
                );
                const encryptedError = encryptResponse(errorResponse, aesKeyBuffer, initialVectorBuffer);
                res.set('Content-Type', 'text/plain');
                return res.status(200).send(encryptedError);
            }
        } catch (e) {
            // Si no podemos encriptar, Base64 de un JSON simple
            const fallbackBase64 = Buffer.from(JSON.stringify({
                version: '3.0',
                screen: 'ERROR',
                flow_token: 'error',
                data: { error: 'Internal error' }
            })).toString('base64');
            
            res.set('Content-Type', 'text/plain');
            return res.status(200).send(fallbackBase64);
        }
        
        res.status(200).end();
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`
╔══════════════════════════════════════════════════════════╗
║    🚀 FLOW WEBHOOK - SIEMPRE BASE64                     ║
╠══════════════════════════════════════════════════════════╣
║  📍 Endpoint: POST /                                    ║
║  📍 Puerto: ${PORT}                                          ║
║  🔐 Algoritmo: AES-128-CBC                              ║
╠══════════════════════════════════════════════════════════╣
║  ✅ ÉXITO:   Content-Type: text/plain + BASE64         ║
║  ✅ ERROR:   Content-Type: text/plain + BASE64         ║
║  ✅ HEALTH:  Content-Type: text/plain + BASE64         ║
║  ❌ NUNCA:   JSON, HTML, texto plano                   ║
╚══════════════════════════════════════════════════════════╝
    `);
});
