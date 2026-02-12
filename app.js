const express = require('express');
const crypto = require('crypto');

const app = express();

app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf;
    }
}));

const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;
const privateKey = process.env.PRIVATE_KEY;

if (!privateKey) {
    console.error('❌ ERROR: PRIVATE_KEY es OBLIGATORIA');
    process.exit(1);
}

// Formatear llave privada
const formattedPrivateKey = privateKey.replace(/\\n/g, '\n');

// ✅ 1. VERIFICACIÓN - RAÍZ
app.get('/', (req, res) => {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    if (mode === 'subscribe' && token === verifyToken) {
        console.log('✅ Webhook verificado');
        return res.status(200).send(String(challenge));
    }
    res.status(403).end();
});

// 🔐 2. DESENCRIPTAR
function decryptFlowData(encryptedFlowData, encryptedAesKey, initialVector) {
    const aesKey = crypto.privateDecrypt(
        {
            key: formattedPrivateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
        },
        Buffer.from(encryptedAesKey, 'base64')
    );

    const iv = Buffer.from(initialVector, 'base64');
    const encryptedData = Buffer.from(encryptedFlowData, 'base64');

    const decipher = crypto.createDecipheriv('aes-128-cbc', aesKey, iv);
    decipher.setAutoPadding(true);

    const decrypted = Buffer.concat([
        decipher.update(encryptedData),
        decipher.final()
    ]);

    return {
        aesKey,
        iv,
        data: JSON.parse(decrypted.toString('utf8'))
    };
}

// 🔐 3. ENCRIPTAR RESPUESTA Y CONVERTIR A BASE64
function encryptFlowResponse(responseData, aesKey, iv) {
    const cipher = crypto.createCipheriv('aes-128-cbc', aesKey, iv);
    cipher.setAutoPadding(true);

    const encrypted = Buffer.concat([
        cipher.update(JSON.stringify(responseData), 'utf8'),
        cipher.final()
    ]);

    // ✅ CONVERTIR A BASE64 - ESTO ES LO QUE META ESPERA
    const base64Response = encrypted.toString('base64');
    
    console.log('🔐 Respuesta en Base64:', base64Response.substring(0, 50) + '...');
    
    return base64Response;
}

// 📥 4. RECIBIR FLOWS - RESPONDER SIEMPRE CON BASE64
app.post('/', (req, res) => {
    try {
        const body = req.body;

        // VALIDAR QUE SEA UN FLOW
        if (!body.encrypted_flow_data || !body.encrypted_aes_key || !body.initial_vector) {
            return res.status(200).end();
        }

        console.log('\n📡 Flow recibido:', new Date().toISOString());

        // Desencriptar
        const { aesKey, iv, data: flowData } = decryptFlowData(
            body.encrypted_flow_data,
            body.encrypted_aes_key,
            body.initial_vector
        );

        console.log('📊 Datos desencriptados:', JSON.stringify(flowData, null, 2));

        // ============================================
        // CONSTRUIR RESPUESTA
        // ============================================
        let responseData = {
            version: '3.0',
            flow_token: flowData.flow_token // ✅ SIEMPRE INCLUIR
        };

        // CASO: INIT - Abrir Flow
        if (flowData.action === 'INIT' || flowData.action === 'data_exchange' && !flowData.screen) {
            console.log('🎯 Acción: INIT');
            responseData.screen = flowData.screen || 'WELCOME';
            // ❌ NO INCLUIR DATA
        }

        // CASO: data_exchange - Enviar formulario
        else if (flowData.action === 'data_exchange' && flowData.screen) {
            console.log('🎯 Acción: data_exchange');
            responseData.screen = flowData.next_screen || 'CONFIRMATION';
            responseData.data = {
                ...flowData.data,
                status: 'success',
                timestamp: new Date().toISOString()
            };
        }

        // CASO: BACK - Botón atrás
        else if (flowData.action === 'BACK') {
            console.log('🎯 Acción: BACK');
            responseData.screen = flowData.previous_screen || 'PREVIOUS_SCREEN';
            // ❌ NO INCLUIR DATA
        }

        // CASO: component_change - Cambio de valor
        else if (flowData.component_id) {
            console.log('🎯 Acción: component_change');
            responseData.screen = flowData.screen;
            responseData.data = {
                ...flowData.data,
                [flowData.component_id]: flowData.component_value
            };
        }

        // CASO: Default
        else {
            console.log('🎯 Acción: Default');
            responseData.screen = flowData.screen || 'RESPONSE';
            if (flowData.data) {
                responseData.data = flowData.data;
            }
        }

        // ✅ PASO CRÍTICO: Encriptar y convertir a Base64
        const encryptedBase64 = encryptFlowResponse(responseData, aesKey, iv);

        // ✅ ENVIAR SOLO EL STRING BASE64 - NADA DE JSON, NADA DE HTML
        console.log('✅ Enviando respuesta Base64');
        
        res.set('Content-Type', 'text/plain');
        res.status(200).send(encryptedBase64); // 👈 SOLO EL BASE64 STRING

    } catch (error) {
        console.error('❌ Error:', error.message);
        // En caso de error, responder con 200 vacío
        res.status(200).end();
    }
});

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'healthy' });
});

// 🚀 Iniciar servidor
app.listen(port, '0.0.0.0', () => {
    console.log(`
╔══════════════════════════════════════════════════════════╗
║    🚀 FLOW WEBHOOK - PRODUCCIÓN                         ║
╠══════════════════════════════════════════════════════════╣
║  📍 Endpoint: POST /                                    ║
║  📍 Puerto: ${port}                                          ║
║  🔐 RSA: ✅ Cargada                                     ║
╠══════════════════════════════════════════════════════════╣
║  ✅ Respuesta: SIEMPRE Base64 puro                     ║
║  ✅ Content-Type: text/plain                           ║
║  ❌ NUNCA: JSON, HTML, XML                             ║
╚══════════════════════════════════════════════════════════╝
    `);
});
