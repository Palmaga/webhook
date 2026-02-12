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

// ✅ VERIFICACIÓN - EXACTAMENTE COMO META ESPERA
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

// 🔐 LIMPIAR DATOS DEL EJEMPLO DE META (ELIMINAR < > y \/)
function cleanMetaExample(data) {
    if (!data) return data;
    let cleaned = data;
    // Eliminar < > del ejemplo
    if (cleaned.startsWith('<') && cleaned.endsWith('>')) {
        cleaned = cleaned.slice(1, -1);
    }
    // Eliminar . al final si existe
    if (cleaned.endsWith('.')) {
        cleaned = cleaned.slice(0, -1);
    }
    // Reemplazar \/ por /
    cleaned = cleaned.replace(/\\\//g, '/');
    return cleaned;
}

// 🔐 DESENCRIPTAR - MANEJA EL EJEMPLO DE META
function decryptFlowData(encryptedFlowData, encryptedAesKey, initialVector) {
    // Limpiar datos del ejemplo de Meta
    const cleanKey = cleanMetaExample(encryptedAesKey);
    const cleanIv = cleanMetaExample(initialVector);
    const cleanData = cleanMetaExample(encryptedFlowData);

    // Desencriptar AES key
    const aesKey = crypto.privateDecrypt(
        {
            key: formattedPrivateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: 'sha256',
        },
        Buffer.from(cleanKey, 'base64')
    );

    // Desencriptar flow data
    const iv = Buffer.from(cleanIv, 'base64');
    const encryptedData = Buffer.from(cleanData, 'base64');

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

// 🔐 ENCRIPTAR RESPUESTA - EXACTAMENTE COMO EL EJEMPLO
function encryptFlowResponse(responseData, aesKey, iv) {
    const cipher = crypto.createCipheriv('aes-128-cbc', aesKey, iv);
    cipher.setAutoPadding(true);

    const encrypted = Buffer.concat([
        cipher.update(JSON.stringify(responseData), 'utf8'),
        cipher.final()
    ]);

    return encrypted.toString('base64');
}

// 📥 ENDPOINT PRINCIPAL - IGUAL AL EJEMPLO DE META
app.post('/', (req, res) => {
    console.log('\n' + '='.repeat(60));
    console.log('📡 FLOW REQUEST RECIBIDO');
    console.log('='.repeat(60));
    
    try {
        const body = req.body;

        // ============================================
        // CASO 6: HEALTH CHECK
        // ============================================
        if (body.health_check) {
            console.log('🏥 Health Check Request');
            return res.status(200).json({ 
                status: 'healthy',
                timestamp: new Date().toISOString()
            });
        }

        // ============================================
        // CASO 5: ERROR NOTIFICATION
        // ============================================
        if (body.error && body.flow_id) {
            console.log('⚠️ Error Notification Request');
            console.log(`   Flow ID: ${body.flow_id}`);
            console.log(`   Error: ${body.error.message}`);
            return res.status(200).end();
        }

        // ============================================
        // CASOS 1-4: DATA EXCHANGE REQUEST (FLOW)
        // ============================================
        if (!body.encrypted_flow_data || !body.encrypted_aes_key || !body.initial_vector) {
            return res.status(200).end();
        }

        console.log('🔐 Data Exchange Request - Flow Encriptado');
        console.log('📦 encrypted_flow_data:', body.encrypted_flow_data.substring(0, 30) + '...');
        console.log('🔑 encrypted_aes_key:', body.encrypted_aes_key.substring(0, 30) + '...');
        console.log('🎲 initial_vector:', body.initial_vector.substring(0, 30) + '...');

        // Desencriptar
        const { aesKey, iv, data: flowData } = decryptFlowData(
            body.encrypted_flow_data,
            body.encrypted_aes_key,
            body.initial_vector
        );

        console.log('\n📊 FLOW DATA DESENCRIPTADA:');
        console.log(JSON.stringify(flowData, null, 2));

        // ============================================
        // CONSTRUIR RESPUESTA SEGÚN DOCUMENTACIÓN
        // ============================================
        let responseData = {
            version: '3.0',
            flow_token: flowData.flow_token // SIEMPRE REQUERIDO
        };

        // CASO 1: Usuario abre el Flow (INIT)
        if (flowData.action === 'INIT' || (flowData.action === 'data_exchange' && !flowData.screen)) {
            console.log('🎯 CASO 1: Usuario abre el Flow');
            responseData.screen = flowData.screen || 'WELCOME';
            // NO incluir data
        }

        // CASO 2: Usuario envía formulario
        else if (flowData.action === 'data_exchange' && flowData.screen) {
            console.log('🎯 CASO 2: Usuario envía formulario');
            responseData.screen = flowData.next_screen || 'CONFIRMATION';
            responseData.data = {
                ...flowData.data,
                status: 'success',
                processed_at: new Date().toISOString()
            };
        }

        // CASO 3: Usuario presiona back
        else if (flowData.action === 'BACK') {
            console.log('🎯 CASO 3: Usuario presiona back');
            responseData.screen = flowData.previous_screen || 'PREVIOUS_SCREEN';
            // NO incluir data
        }

        // CASO 4: Usuario cambia componente
        else if (flowData.component_id) {
            console.log('🎯 CASO 4: Usuario cambia componente');
            responseData.screen = flowData.screen;
            responseData.data = {
                ...flowData.data,
                [flowData.component_id]: flowData.component_value,
                validated: true
            };
        }

        // Default
        else {
            console.log('🎯 CASO: Default');
            responseData.screen = flowData.screen || 'RESPONSE';
            if (flowData.data) {
                responseData.data = flowData.data;
            }
        }

        console.log('\n📤 RESPUESTA PREPARADA:');
        console.log(JSON.stringify(responseData, null, 2));

        // Encriptar respuesta
        const encryptedResponse = encryptFlowResponse(responseData, aesKey, iv);
        
        console.log('\n✅ RESPONDIENDO CON BASE64:');
        console.log('📦 Longitud:', encryptedResponse.length);
        console.log('📦 Base64:', encryptedResponse.substring(0, 50) + '...');

        // ⚠️ EXACTAMENTE COMO EL EJEMPLO DE META:
        // HTTP/2 200
        // content-type: text/plain
        // [BASE64_STRING]
        
        res.set('Content-Type', 'text/plain');
        res.status(200).send(encryptedResponse);

    } catch (error) {
        console.error('❌ Error:', error.message);
        res.status(200).end();
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy',
        timestamp: new Date().toISOString()
    });
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
║  📋 CASOS IMPLEMENTADOS:                                ║
║  ✅ CASO 1: Usuario abre Flow (INIT)                   ║
║  ✅ CASO 2: Usuario envía formulario (data_exchange)   ║
║  ✅ CASO 3: Usuario presiona back (BACK)               ║
║  ✅ CASO 4: Usuario cambia componente                  ║
║  ✅ CASO 5: Error Notification                         ║
║  ✅ CASO 6: Health Check                               ║
╠══════════════════════════════════════════════════════════╣
║  ⚠️  RESPUESTA: SIEMPRE text/plain + BASE64            ║
║  ⚠️  IGUAL AL EJEMPLO DE META                          ║
╚══════════════════════════════════════════════════════════╝
    `);
});
