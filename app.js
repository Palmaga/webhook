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
let privateKey = process.env.PRIVATE_KEY;

// 🔧 Formatear llave privada correctamente
if (privateKey) {
  // Reemplazar \\n con saltos de línea reales
  privateKey = privateKey.replace(/\\n/g, '\n');
}

// ✅ VERIFICACIÓN DEL WEBHOOK
app.get(['/', '/webhook'], (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

  if (mode === 'subscribe' && token === verifyToken) {
    console.log('✅ WEBHOOK VERIFICADO');
    res.set('Content-Type', 'text/plain');
    res.status(200).send(String(challenge));
  } else {
    res.status(403).end();
  }
});

// 🔐 Función para desencriptar datos del Flow
function decryptFlowData(encryptedFlowData, encryptedAesKey, initialVector) {
  try {
    console.log('🔐 Desencriptando Flow...');
    
    // 1. Desencriptar AES key con RSA (OAEP SHA-256)
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(encryptedAesKey, 'base64')
    );
    
    console.log('  ✅ AES Key desencriptada');
    
    // 2. Desencriptar flow data con AES-128-CBC
    const iv = Buffer.from(initialVector, 'base64');
    const encryptedData = Buffer.from(encryptedFlowData, 'base64');
    
    const decipher = crypto.createDecipheriv('aes-128-cbc', aesKey, iv);
    decipher.setAutoPadding(true);
    
    const decrypted = Buffer.concat([
      decipher.update(encryptedData),
      decipher.final()
    ]);
    
    const decryptedString = decrypted.toString('utf8');
    console.log('  ✅ Flow data desencriptada:', decryptedString);
    
    return JSON.parse(decryptedString);
    
  } catch (error) {
    console.error('❌ Error desencriptando:', error);
    throw error;
  }
}

// 🔐 Función para ENCRIPTAR respuesta del Flow
function encryptFlowResponse(responseData, encryptedAesKey, initialVector) {
  try {
    console.log('🔐 Encriptando respuesta...');
    
    // 1. Desencriptar AES key con RSA (misma llave)
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(encryptedAesKey, 'base64')
    );
    
    // 2. Convertir respuesta a JSON string
    const responseString = JSON.stringify(responseData);
    console.log('  📤 Respuesta original:', responseString);
    
    // 3. Encriptar con AES-128-CBC usando el mismo IV
    const iv = Buffer.from(initialVector, 'base64');
    const cipher = crypto.createCipheriv('aes-128-cbc', aesKey, iv);
    cipher.setAutoPadding(true);
    
    const encrypted = Buffer.concat([
      cipher.update(responseString, 'utf8'),
      cipher.final()
    ]);
    
    // 4. Convertir a Base64
    const encryptedBase64 = encrypted.toString('base64');
    console.log('  🔐 Respuesta encriptada (Base64):', encryptedBase64.substring(0, 50) + '...');
    
    return encryptedBase64;
    
  } catch (error) {
    console.error('❌ Error encriptando respuesta:', error);
    throw error;
  }
}

// 📥 RECEPCIÓN DE FLOWS
app.post(['/', '/webhook'], (req, res) => {
  console.log('\n' + '📱'.repeat(20));
  console.log('📡 FLOW RECIBIDO');
  console.log('📱'.repeat(20));
  
  try {
    const body = req.body;
    
    // Verificar si es un Flow encriptado
    if (body.encrypted_flow_data && body.encrypted_aes_key && body.initial_vector) {
      
      console.log('\n📦 Datos encriptados recibidos:');
      console.log('  encrypted_flow_data:', body.encrypted_flow_data.substring(0, 30) + '...');
      console.log('  encrypted_aes_key:', body.encrypted_aes_key.substring(0, 30) + '...');
      console.log('  initial_vector:', body.initial_vector.substring(0, 30) + '...');
      
      // Verificar que tenemos la llave privada
      if (!privateKey) {
        console.error('❌ PRIVATE_KEY no configurada');
        return res.status(500).json({ error: 'Private key not configured' });
      }
      
      // 1️⃣ DESENCRIPTAR DATOS
      const decryptedData = decryptFlowData(
        body.encrypted_flow_data,
        body.encrypted_aes_key,
        body.initial_vector
      );
      
      console.log('\n📊 DATOS DESENCRIPTADOS:');
      console.log(JSON.stringify(decryptedData, null, 2));
      
      // 2️⃣ PROCESAR SEGÚN EL TIPO DE FLOW
      let flowResponse;
      
      if (decryptedData.screen === 'INITIAL') {
        // Flow de inicio - respuesta inicial
        flowResponse = {
          version: decryptedData.version || '3.0',
          screen: decryptedData.screen,
          data: {
            ...decryptedData.data,
            response_type: 'initial',
            timestamp: new Date().toISOString()
          }
        };
      } else {
        // Flow con datos del formulario
        flowResponse = {
          version: decryptedData.version || '3.0',
          screen: decryptedData.screen,
          data: {
            ...decryptedData.data,
            status: 'success',
            confirmed: true,
            processed_at: new Date().toISOString()
          }
        };
      }
      
      console.log('\n📤 RESPUESTA A ENVIAR:');
      console.log(JSON.stringify(flowResponse, null, 2));
      
      // 3️⃣ ENCRIPTAR RESPUESTA
      const encryptedResponse = encryptFlowResponse(
        flowResponse,
        body.encrypted_aes_key,
        body.initial_vector
      );
      
      // 4️⃣ ENVIAR RESPUESTA ENCRIPTADA
      console.log('\n✅ Enviando respuesta encriptada...');
      res.set('Content-Type', 'text/plain');
      res.status(200).send(encryptedResponse);
      
    } else if (body.entry) {
      // Mensaje normal de WhatsApp
      console.log('📨 Mensaje WhatsApp normal');
      console.log(JSON.stringify(body, null, 2));
      res.status(200).end();
    } else {
      console.log('📦 Otro tipo de payload');
      console.log(JSON.stringify(body, null, 2));
      res.status(200).end();
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(200).json({ error: 'Internal server error' });
  }
});

// 📊 Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    encryption: privateKey ? 'configured' : 'not configured'
  });
});

// 🏠 Página principal
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Meta Flow Webhook</title>
        <style>
          body { font-family: Arial; padding: 40px; background: #f5f5f5; }
          .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          .success { color: #10b981; }
          .warning { color: #f59e0b; }
          code { background: #f3f4f6; padding: 2px 5px; border-radius: 3px; }
          pre { background: #1f2937; color: #fff; padding: 15px; border-radius: 5px; overflow-x: auto; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🚀 Meta Flow Webhook</h1>
          <p class="success">✅ Servidor funcionando correctamente</p>
          
          <h3>🔐 Estado de encriptación:</h3>
          <p class="${privateKey ? 'success' : 'warning'}">
            ${privateKey ? '✅ PRIVATE_KEY configurada' : '⚠️ PRIVATE_KEY no configurada'}
          </p>
          
          <h3>📋 Endpoints:</h3>
          <ul>
            <li><code>GET /webhook</code> - Verificación</li>
            <li><code>POST /webhook</code> - Webhook (soporta Flows encriptados)</li>
            <li><code>GET /health</code> - Health check</li>
          </ul>
          
          <h3>🔧 Configuración de PRIVATE_KEY:</h3>
          <pre>
# Generar llave privada RSA
openssl genrsa -out private.key 2048

# Ver la llave (cópiala completa)
cat private.key

# En tu plataforma, configura PRIVATE_KEY con el contenido completo
          </pre>
        </div>
      </body>
    </html>
  `);
});

// Iniciar servidor
app.listen(port, '0.0.0.0', () => {
  console.log('\n' + '🚀'.repeat(20));
  console.log('   SERVIDOR WEBHOOK META FLOW');
  console.log('🚀'.repeat(20) + '\n');
  console.log(`📌 Puerto: ${port}`);
  console.log(`📌 Verify Token: ${verifyToken || 'No configurado'}`);
  console.log(`📌 Encriptación: ${privateKey ? '✅ Activa' : '❌ Inactiva'}`);
  console.log('\n📌 Endpoints:');
  console.log(`   GET  /webhook - Verificación`);
  console.log(`   POST /webhook - Webhook`);
  console.log(`   GET  /health - Health check`);
  console.log(`   GET  / - Página principal\n`);
});
