// Import Express.js
const express = require('express');
const crypto = require('crypto');

const app = express();

// Middleware para parsear JSON con rawBody para firma
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;
const appSecret = process.env.APP_SECRET;
const privateKey = process.env.PRIVATE_KEY; // Tu llave privada para desencriptar

// Verificación de firma
function verifySignature(req, res, next) {
  if (!appSecret) return next();
  
  const signature = req.headers['x-hub-signature-256'];
  if (!signature) {
    return res.status(401).send('No signature found');
  }

  const elements = signature.split('=');
  const signatureHash = elements[1];
  const expectedHash = crypto
    .createHmac('sha256', appSecret)
    .update(req.rawBody)
    .digest('hex');

  if (signatureHash !== expectedHash) {
    return res.status(401).send('Invalid signature');
  }
  next();
}

// 🔐 Función para desencriptar datos del Flow
function decryptFlowData(encryptedFlowData, encryptedAesKey, initialVector) {
  try {
    console.log('🔐 Iniciando desencriptación de Flow...');
    
    // 1. Desencriptar AES key con RSA (usando tu llave privada)
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(encryptedAesKey, 'base64')
    );
    
    console.log('  ✅ AES Key desencriptada');
    
    // 2. Desencriptar flow data con AES
    const iv = Buffer.from(initialVector, 'base64');
    const encryptedData = Buffer.from(encryptedFlowData, 'base64');
    
    const decipher = crypto.createDecipheriv('aes-128-cbc', aesKey, iv);
    const decrypted = Buffer.concat([
      decipher.update(encryptedData),
      decipher.final()
    ]);
    
    console.log('  ✅ Flow data desencriptada');
    
    // 3. Parsear JSON
    return JSON.parse(decrypted.toString());
    
  } catch (error) {
    console.error('❌ Error desencriptando Flow:', error);
    throw error;
  }
}

// ✅ VERIFICACIÓN - CON BASE64
app.get(['/', '/webhook'], (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

  console.log('\n' + '='.repeat(60));
  console.log('🔐 VERIFICACIÓN DE WEBHOOK');
  console.log('='.repeat(60));
  console.log('  📍 Mode:', mode);
  console.log('  📍 Challenge (original):', challenge);
  console.log('  📍 Token:', token);

  if (mode === 'subscribe' && token === verifyToken) {
    const challengeBase64 = Buffer.from(String(challenge)).toString('base64');
    
    console.log('  ✅ VERIFICACIÓN EXITOSA');
    console.log('  🔑 Challenge Base64:', challengeBase64);
    console.log('='.repeat(60));
    
    res.set('Content-Type', 'text/plain');
    res.status(200).send(challengeBase64);
  } else {
    console.log('  ❌ VERIFICACIÓN FALLIDA');
    console.log('='.repeat(60));
    res.status(403).end();
  }
});

// 📥 RECEPCIÓN de mensajes Flow encriptados
app.post(['/', '/webhook'], verifySignature, (req, res) => {
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  
  console.log('\n' + '📱'.repeat(15));
  console.log(`📡 FLOW WEBHOOK RECIBIDO ${timestamp}`);
  console.log('📱'.repeat(15));
  
  try {
    const body = req.body;
    
    // ✅ VERIFICAR SI ES UN FLOW ENCRIPTADO
    if (body.encrypted_flow_data && body.encrypted_aes_key && body.initial_vector) {
      console.log('\n🔐 MENSAJE FLOW ENCRIPTADO DETECTADO');
      console.log('  📦 encrypted_flow_data:', body.encrypted_flow_data.substring(0, 50) + '...');
      console.log('  🔑 encrypted_aes_key:', body.encrypted_aes_key.substring(0, 50) + '...');
      console.log('  🎲 initial_vector:', body.initial_vector.substring(0, 50) + '...');
      
      // Desencriptar los datos del Flow
      if (privateKey) {
        try {
          const decryptedData = decryptFlowData(
            body.encrypted_flow_data,
            body.encrypted_aes_key,
            body.initial_vector
          );
          
          console.log('\n📊 DATOS DEL FLOW DESENCRIPTADOS:');
          console.log(JSON.stringify(decryptedData, null, 2));
          
          // Aquí procesas los datos desencriptados
          processFlowData(decryptedData);
          
        } catch (decryptError) {
          console.error('❌ Error desencriptando:', decryptError);
        }
      } else {
        console.log('\n⚠️  PRIVATE_KEY no configurada - No se puede desencriptar');
        console.log('   Configura PRIVATE_KEY en .env con tu llave privada RSA');
      }
      
    } 
    // ✅ VERIFICAR SI ES UN WEBHOOK NORMAL DE WHATSAPP
    else if (body.entry) {
      console.log('\n📨 MENSAJE WHATSAPP NORMAL DETECTADO');
      console.log(JSON.stringify(body, null, 2));
      
      // Procesar mensajes normales de WhatsApp
      body.entry.forEach(entry => {
        if (entry.changes) {
          entry.changes.forEach(change => {
            if (change.value && change.value.messages) {
              change.value.messages.forEach(message => {
                if (message.type === 'interactive' && message.interactive) {
                  console.log('  🎯 Mensaje interactivo:', message.interactive);
                }
              });
            }
          });
        }
      });
    }
    else {
      console.log('\n📦 OTRO TIPO DE PAYLOAD:');
      console.log(JSON.stringify(body, null, 2));
    }
    
    // ✅ SIEMPRE responder 200 OK
    res.status(200).json({
      status: 'success',
      message: 'Webhook received'
    });
    
  } catch (error) {
    console.error('❌ Error procesando webhook:', error);
    // Siempre responder 200 aunque haya error
    res.status(200).json({
      status: 'error',
      message: 'Error processing webhook'
    });
  }
});

// Función para procesar datos del Flow
function processFlowData(flowData) {
  console.log('\n🔄 PROCESANDO DATOS DEL FLOW:');
  
  // Estructura típica de flowData:
  // {
  //   version: "3.0",
  //   screen: "SCREEN_NAME",
  //   data: {
  //     flow_token: "TOKEN",
  //     ... otros campos del formulario
  //   }
  // }
  
  if (flowData.screen) {
    console.log(`  📱 Screen: ${flowData.screen}`);
  }
  
  if (flowData.data) {
    console.log('  📋 Datos del formulario:');
    Object.entries(flowData.data).forEach(([key, value]) => {
      console.log(`    • ${key}: ${value}`);
    });
  }
  
  // Aquí agregas tu lógica de negocio
  // - Guardar en base de datos
  // - Procesar respuestas
  // - Enviar confirmación
  // etc.
}

// 🏠 Página de estado
app.get('/status', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Webhook Meta Flow</title>
        <style>
          body { font-family: Arial, sans-serif; padding: 30px; background: #f5f5f5; }
          .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          .success { color: green; }
          .warning { color: orange; }
          .error { color: red; }
          code { background: #f0f0f0; padding: 2px 5px; border-radius: 3px; }
          pre { background: #333; color: #fff; padding: 15px; border-radius: 5px; overflow-x: auto; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🚀 Webhook Server para Meta Flow</h1>
          <p class="${privateKey ? 'success' : 'warning'}">
            ${privateKey ? '✅' : '⚠️'} Servidor funcionando 
            ${privateKey ? 'con' : 'sin'} soporte para Flow encriptado
          </p>
          <p>📅 ${new Date().toLocaleString()}</p>
          <hr>
          
          <h3>⚙️ Configuración:</h3>
          <ul>
            <li>VERIFY_TOKEN: ${verifyToken ? '✅ Configurado' : '❌ No configurado'}</li>
            <li>APP_SECRET: ${appSecret ? '✅ Configurado' : '⚠️ Opcional'}</li>
            <li>PRIVATE_KEY: ${privateKey ? '✅ Configurada' : '❌ No configurada'}</li>
          </ul>
          
          <h3>📌 Endpoints activos:</h3>
          <ul>
            <li><code>GET /webhook</code> - Verificación (responde con Base64)</li>
            <li><code>POST /webhook</code> - Recepción de mensajes (soporta Flow encriptado)</li>
            <li><code>GET /status</code> - Esta página</li>
          </ul>
          
          <h3>🔐 Estructura de Flow Encriptado:</h3>
          <pre>
{
  "encrypted_flow_data": "&lt;BASE64_ENCRYPTED_DATA&gt;",
  "encrypted_aes_key": "&lt;BASE64_ENCRYPTED_AES_KEY&gt;",
  "initial_vector": "&lt;BASE64_IV&gt;"
}
          </pre>
          
          <h3>🧪 Prueba de verificación:</h3>
          <pre>
curl "http://localhost:${port}/webhook?hub.mode=subscribe&hub.challenge=123456789&hub.verify_token=${verifyToken || 'TU_TOKEN'}"
          </pre>
        </div>
      </body>
    </html>
  `);
});

// Iniciar servidor
app.listen(port, () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║        🚀 SERVIDOR WEBHOOK PARA META FLOW               ║
╠══════════════════════════════════════════════════════════╣
║  📍 Puerto:        ${port}                                  ║
║  📍 Rutas:         GET/POST /webhook                     ║
║  🔐 Verificación:  BASE64 ENCODED                       ║
╠══════════════════════════════════════════════════════════╣
║  🎯 Verify Token:  ${verifyToken ? '✅' : '❌'}                                   ║
║  🔑 App Secret:    ${appSecret ? '✅' : '⚠️ Opcional'}                            ║
║  🔐 Private Key:   ${privateKey ? '✅' : '❌'}                                   ║
╚══════════════════════════════════════════════════════════╝
  `);
  
  if (!privateKey) {
    console.log('\n⚠️  IMPORTANTE: PRIVATE_KEY no configurada');
    console.log('   Para recibir Flows encriptados necesitas:');
    console.log('   1. Generar un par de llaves RSA');
    console.log('   2. Configurar la llave pública en Meta');
    console.log('   3. Configurar PRIVATE_KEY en .env\n');
  }
});
