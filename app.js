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

// ✅ 1. VERIFICACIÓN - SOLO EN LA RAÍZ (PORQUE META USA /)
app.get('/', (req, res) => {
    const mode = req.query['hub.mode'];
    const token = req.query['hub.verify_token'];
    const challenge = req.query['hub.challenge'];

    console.log('🔐 Verificación en /');
    
    if (mode === 'subscribe' && token === verifyToken) {
        console.log('✅ Webhook verificado');
        return res.status(200).send(String(challenge));
    }
    res.status(403).end();
});

// 🔐 2. DESENCRIPTAR FLOW DATA
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

// 🔐 3. ENCRIPTAR RESPUESTA
function encryptFlowResponse(responseData, aesKey, iv) {
    const cipher = crypto.createCipheriv('aes-128-cbc', aesKey, iv);
    cipher.setAutoPadding(true);

    const encrypted = Buffer.concat([
        cipher.update(JSON.stringify(responseData), 'utf8'),
        cipher.final()
    ]);

    return encrypted.toString('base64');
}

// 📥 4. RECIBIR FLOWS - SOLO EN LA RAÍZ (PORQUE META USA /)
app.post('/', (req, res) => {
    try {
        const body = req.body;

        // SOLO FLOWS ENCRIPTADOS
        if (!body.encrypted_flow_data || !body.encrypted_aes_key || !body.initial_vector) {
            return res.status(200).end();
        }

        console.log('\n📡 Flow recibido en /:', new Date().toISOString());

        // Desencriptar
        const { aesKey, iv, data: flowData } = decryptFlowData(
            body.encrypted_flow_data,
            body.encrypted_aes_key,
            body.initial_vector
        );

        console.log('📊 Datos:', JSON.stringify(flowData, null, 2));

        // RESPUESTA SEGÚN EL CASO
        let responseData = {
            version: '3.0',
            flow_token: flowData.flow_token
        };

        // CASO 1: Usuario abre Flow (INIT)
        if (flowData.action === 'INIT' || (!flowData.screen && flowData.action === 'data_exchange')) {
            console.log('🎯 Caso: Abrir Flow');
            responseData.screen = flowData.screen || 'WELCOME';
        }

        // CASO 2: Usuario envía formulario
        else if (flowData.action === 'data_exchange' && flowData.screen) {
            console.log('🎯 Caso: Enviar formulario');
            responseData.screen = flowData.next_screen || 'CONFIRMATION';
            responseData.data = {
                ...flowData.data,
                status: 'success',
                processed_at: new Date().toISOString()
            };
        }

        // CASO 3: Usuario presiona back
        else if (flowData.action === 'BACK') {
            console.log('🎯 Caso: Botón back');
            responseData.screen = flowData.previous_screen || 'PREVIOUS_SCREEN';
        }

        // CASO 4: Cambio de componente
        else if (flowData.component_id) {
            console.log('🎯 Caso: Cambio componente');
            responseData.screen = flowData.screen;
            responseData.data = {
                ...flowData.data,
                [flowData.component_id]: flowData.component_value
            };
        }

        // Default
        else {
            console.log('🎯 Caso: Default');
            responseData.screen = flowData.screen || 'RESPONSE';
            if (flowData.data) {
                responseData.data = flowData.data;
            }
        }

        // Encriptar y enviar
        const encryptedResponse = encryptFlowResponse(responseData, aesKey, iv);
        
        console.log('✅ Respondiendo con Flow encriptado');
        res.set('Content-Type', 'text/plain');
        res.status(200).send(encryptedResponse);

    } catch (error) {
        console.error('❌ Error:', error.message);
        res.status(200).end();
    }
});

// 📊 Health check
app.get('/health', (req, res) => {
    res.json({ status: 'healthy' });
});

// 🚀 Iniciar servidor
app.listen(port, '0.0.0.0', () => {
    console.log(`
╔════════════════════════════════════════════╗
║    🚀 FLOW WEBHOOK - PRODUCCIÓN           ║
╠════════════════════════════════════════════╣
║  📍 Endpoint: POST /  (RAÍZ)             ║
║  📍 Puerto: ${port}                              ║
║  📍 Token: ${verifyToken}                       ║
║  🔐 RSA: ✅ Cargada                       ║
╚════════════════════════════════════════════╝
    `);
});
