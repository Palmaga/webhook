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
const privateKey = process.env.PRIVATE_KEY; // Tu llave privada RSA

// 🔐 Función para desencriptar datos del Flow
function decryptFlowData(encryptedFlowData, encryptedAesKey, initialVector) {
  try {
    console.log('🔐 Desencriptando Flow...');
    
    // Desencriptar AES key con RSA
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(encryptedAesKey, 'base64')
    );
    
    // Desencriptar flow data con AES
    const iv = Buffer.from(initialVector, 'base64');
    const encryptedData = Buffer.from(encryptedFlowData, 'base64');
    
    const decipher = crypto.createDecipheriv('aes-128-cbc', aesKey, iv);
    const decrypted = Buffer.concat([
      decipher.update(encryptedData),
      decipher.final()
    ]);
    
    return JSON.parse(decrypted.toString());
    
  } catch (error) {
    console.error('❌ Error desencriptando:', error);
    throw error;
  }
}

// 🔐 Función para ENCRIPTAR respuesta del Flow
function encryptFlowResponse(responseData, encryptedAesKey, initialVector) {
  try {
    console.log('🔐 Encriptando respuesta del Flow...');
    
    // 1. Desencriptar AES key con RSA (misma llave que recibimos)
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
    console.log('  📤 Respuesta plana:', responseString);
    
    // 3. Encriptar con AES usando el mismo IV
    const iv = Buffer.from(initialVector, 'base64');
    const cipher = crypto.createCipheriv('aes-128-cbc', aesKey, iv);
    
    const encrypted = Buffer.concat([
      cipher.update(responseString, 'utf8'),
      cipher.final()
    ]);
    
    // 4. Convertir a Base64
    const encryptedBase64 = encrypted.toString('base64');
    console.log('  🔐 Respuesta encriptada:', encryptedBase64.substring(0, 50) + '...');
    
    return encryptedBase64;
    
  } catch (error) {
    console.error('❌ Error encriptando respuesta:', error);
    throw error;
  }
}

// ✅ VERIFICACIÓN DEL WEBHOOK
app.get(['/', '/webhook'], (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

  if (mode === 'subscribe' && token === verifyToken) {
    const challengeBase64 = Buffer.from(String(challenge)).toString('base64');
    res.set('Content-Type', 'text/plain');
    res.status(200).send(challengeBase64);
  } else {
    res.status(403).end();
  }
});

// 📥 RECEPCIÓN Y RESPUESTA DE FLOWS ENCRIPTADOS
app.post(['/', '/webhook'], verifySignature, (req, res) => {
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  
  console.log('\n' + '='.repeat(60));
  console.log(`📡 FLOW WEBHOOK RECIBIDO ${timestamp}`);
  console.log('='.repeat(60));
  
  try {
    const body = req.body;
    
    // ✅ DETECTAR FLOW ENCRIPTADO
    if (body.encrypted_flow_data && body.encrypted_aes_key && body.initial_vector) {
      console.log('🔐 FLOW ENCRIPTADO DETECTADO');
      console.log('  📦 encrypted_flow_data:', body.encrypted_flow_data.substring(0, 30) + '...');
      console.log('  🔑 encrypted_aes_key:', body.encrypted_aes_key.substring(0, 30) + '...');
      console.log('  🎲 initial_vector:', body.initial_vector.substring(0, 30) + '...');
      
      if (!privateKey) {
        console.error('❌ PRIVATE_KEY no configurada');
        return res.status(500).send('Private key not configured');
      }
      
      // 1️⃣ DESENCRIPTAR DATOS RECIBIDOS
      const decryptedData = decryptFlowData(
        body.encrypted_flow_data,
        body.encrypted_aes_key,
        body.initial_vector
      );
      
      console.log('\n📊 DATOS DESENCRIPTADOS:');
      console.log(JSON.stringify(decryptedData, null, 2));
      
      // 2️⃣ PROCESAR LOS DATOS Y GENERAR RESPUESTA
      // Esta es la estructura que Meta espera como respuesta
      const flowResponse = {
        version: decryptedData.version || '3.0',
        screen: decryptedData.screen,
        data: {
          ...decryptedData.data,
          // Puedes agregar campos adicionales aquí
          confirmed: true,
          timestamp: new Date().toISOString()
        }
      };
      
      console.log('\n📤 RESPUESTA A ENVIAR:');
      console.log(JSON.stringify(flowResponse, null, 2));
      
      // 3️⃣ ENCRIPTAR LA RESPUESTA
      const encryptedResponse = encryptFlowResponse(
        flowResponse,
        body.encrypted_aes_key,
        body.initial_vector
      );
      
      // 4️⃣ ENVIAR RESPUESTA ENCRIPTADA (IGUAL QUE EL EJEMPLO DE META)
      console.log('\n✅ ENVIANDO RESPUESTA ENCRIPTADA...');
      res.set('Content-Type', 'text/plain');
      res.status(200).send(encryptedResponse);
      
      console.log('='.repeat(60));
      
    } else {
      // WEBHOOK NORMAL DE WHATSAPP
      console.log('📨 MENSAJE WHATSAPP NORMAL');
      console.log(JSON.stringify(body, null, 2));
      res.status(200).end();
    }
    
  } catch (error) {
    console.error('❌ Error:', error);
    res.status(500).send('Error processing webhook');
  }
});

// 🏠 Página de estado
app.get('/status', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Webhook Meta Flow</title>
        <style>
          body { font-family: Arial, sans-serif; padding: 30px; background: #f5f5f5; }
          .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
          .success { color: green; }
          .warning { color: orange; }
          code { background: #f0f0f0; padding: 2px 5px; border-radius: 3px; }
          pre { background: #333; color: #fff; padding: 15px; border-radius: 5px; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🚀 Webhook Server para Meta Flow</h1>
          <p class="${privateKey ? 'success' : 'warning'}">
            ${privateKey ? '✅' : '⚠️'} Servidor configurado ${privateKey ? 'CON' : 'SIN'} encriptación
          </p>
          
          <h3>📋 Último Flow Procesado:</h3>
          <pre id="lastFlow">Esperando primer Flow...</pre>
          
          <h3>🔐 Estructura de Flow Encriptado:</h3>
          <pre>
{
  "encrypted_flow_data": "&lt;BASE64&gt;",
  "encrypted_aes_key": "&lt;BASE64&gt;",
  "initial_vector": "&lt;BASE64&gt;"
}
          </pre>
          
          <h3>📤 Respuesta que envía el servidor:</h3>
          <pre>
{STRING_BASE64_ENCRIPTADO}  ← IGUAL QUE EL EJEMPLO DE META
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
║     🚀 SERVIDOR WEBHOOK PARA META FLOW                  ║
╠══════════════════════════════════════════════════════════╣
║  📍 Puerto:        ${port}                                  ║
║  🔐 Estado:        ${privateKey ? '✅ Encriptación activa' : '❌ Sin encriptación'}   ║
║  📤 Respuesta:     BASE64 Encriptado (AES-128-CBC)      ║
╠══════════════════════════════════════════════════════════╣
║  🎯 Verify Token:  ${verifyToken ? '✅' : '❌'}                                   ║
║  🔑 App Secret:    ${appSecret ? '✅' : '⚠️'}                                   ║
║  🔐 Private Key:   ${privateKey ? '✅' : '❌'}                                   ║
╚══════════════════════════════════════════════════════════╝
  `);
  
  if (!privateKey) {
    console.log('\n⚠️  IMPORTANTE: PRIVATE_KEY no configurada');
    console.log('   Para Flows encriptados necesitas:');
    console.log('   1. Generar par RSA: openssl genrsa -out private.key 2048');
    console.log('   2. Extraer pública: openssl rsa -in private.key -pubout -out public.key');
    console.log('   3. Subir public.key a Meta Developers\n');
  }
});
