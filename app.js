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

// Formatear llave privada
if (privateKey) {
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
    // Desencriptar AES key con RSA
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(encryptedAesKey, 'base64')
    );
    
    // Desencriptar flow data con AES-128-CBC
    const iv = Buffer.from(initialVector, 'base64');
    const encryptedData = Buffer.from(encryptedFlowData, 'base64');
    
    const decipher = crypto.createDecipheriv('aes-128-cbc', aesKey, iv);
    decipher.setAutoPadding(true);
    
    const decrypted = Buffer.concat([
      decipher.update(encryptedData),
      decipher.final()
    ]);
    
    return JSON.parse(decrypted.toString('utf8'));
    
  } catch (error) {
    console.error('❌ Error desencriptando:', error);
    throw error;
  }
}

// 🔐 Función para ENCRIPTAR respuesta del Flow
function encryptFlowResponse(responseData, encryptedAesKey, initialVector) {
  try {
    // Desencriptar AES key con RSA
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(encryptedAesKey, 'base64')
    );
    
    // Convertir respuesta a JSON string
    const responseString = JSON.stringify(responseData);
    
    // Encriptar con AES-128-CBC
    const iv = Buffer.from(initialVector, 'base64');
    const cipher = crypto.createCipheriv('aes-128-cbc', aesKey, iv);
    cipher.setAutoPadding(true);
    
    const encrypted = Buffer.concat([
      cipher.update(responseString, 'utf8'),
      cipher.final()
    ]);
    
    // Convertir a Base64
    return encrypted.toString('base64');
    
  } catch (error) {
    console.error('❌ Error encriptando respuesta:', error);
    throw error;
  }
}

// 📥 RECEPCIÓN DE FLOWS - VERSIÓN CORREGIDA
app.post(['/', '/webhook'], (req, res) => {
  console.log('\n' + '='.repeat(50));
  console.log('📡 FLOW RECIBIDO');
  console.log('='.repeat(50));
  
  try {
    const body = req.body;
    
    // Verificar si es un Flow encriptado
    if (body.encrypted_flow_data && body.encrypted_aes_key && body.initial_vector) {
      
      console.log('📦 Flow encriptado detectado');
      
      // Verificar que tenemos la llave privada
      if (!privateKey) {
        console.error('❌ PRIVATE_KEY no configurada');
        
        // ⚠️ IMPORTANTE: Siempre responder con Base64, incluso en errores
        // Enviamos un mensaje de error encriptado simple
        const errorResponse = {
          version: "3.0",
          screen: "ERROR",
          data: {
            error: "Private key not configured",
            timestamp: new Date().toISOString()
          }
        };
        
        try {
          // Intentamos encriptar el error
          const encryptedError = encryptFlowResponse(
            errorResponse,
            body.encrypted_aes_key,
            body.initial_vector
          );
          return res.set('Content-Type', 'text/plain').status(200).send(encryptedError);
        } catch (e) {
          // Si no podemos encriptar, enviamos un Base64 fijo de ejemplo
          // ESTO ES SOLO PARA DEBUG - NUNCA EN PRODUCCIÓN
          return res.set('Content-Type', 'text/plain').status(200).send('yZcJQaH3AqfzKgjn64vAcASaJrOMN27S6CESyU68WN/cDCP6abskoMa/pPjszXGKyyh/23lw84HW6ZilMfU6KL3j5AWwOx6GWNwtq8Aj7gz/Y7R+LccmJWxKo2UccMu5xJlduIFlFlOS1gAnOwKrk8wpuprsi4jAOspw3xO2uh3J883aC/csu/MhRPiYCaGGy/tTNvVDmb2Gw1WXFmpvLsZ/SBrgG0cDQJjQzpTO');
        }
      }
      
      try {
        // 1️⃣ DESENCRIPTAR DATOS
        const decryptedData = decryptFlowData(
          body.encrypted_flow_data,
          body.encrypted_aes_key,
          body.initial_vector
        );
        
        console.log('📊 Datos recibidos:', JSON.stringify(decryptedData, null, 2));
        
        // 2️⃣ PREPARAR RESPUESTA
        const flowResponse = {
          version: decryptedData.version || '3.0',
          screen: decryptedData.screen || 'RESPONSE',
          data: {
            ...decryptedData.data,
            status: 'success',
            processed_at: new Date().toISOString()
          }
        };
        
        // 3️⃣ ENCRIPTAR RESPUESTA
        const encryptedResponse = encryptFlowResponse(
          flowResponse,
          body.encrypted_aes_key,
          body.initial_vector
        );
        
        // 4️⃣ ✅ ENVIAR SOLO EL BASE64 - NADA DE JSON
        console.log('✅ Enviando respuesta encriptada');
        res.set('Content-Type', 'text/plain');
        res.status(200).send(encryptedResponse);
        
      } catch (error) {
        console.error('❌ Error procesando Flow:', error);
        
        // ⚠️ SIEMPRE responder con Base64, NUNCA con JSON
        const errorResponse = {
          version: "3.0",
          screen: "ERROR",
          data: {
            error: error.message,
            timestamp: new Date().toISOString()
          }
        };
        
        try {
          const encryptedError = encryptFlowResponse(
            errorResponse,
            body.encrypted_aes_key,
            body.initial_vector
          );
          res.set('Content-Type', 'text/plain');
          res.status(200).send(encryptedError);
        } catch (e) {
          // Último recurso - responder con Base64 fijo
          res.set('Content-Type', 'text/plain');
          res.status(200).send('yZcJQaH3AqfzKgjn64vAcASaJrOMN27S6CESyU68WN/cDCP6abskoMa/pPjszXGKyyh/23lw84HW6ZilMfU6KL3j5AWwOx6GWNwtq8Aj7gz/Y7R+LccmJWxKo2UccMu5xJlduIFlFlOS1gAnOwKrk8wpuprsi4jAOspw3xO2uh3J883aC/csu/MhRPiYCaGGy/tTNvVDmb2Gw1WXFmpvLsZ/SBrgG0cDQJjQzpTO');
        }
      }
      
    } else {
      // Mensaje normal de WhatsApp
      console.log('📨 Mensaje WhatsApp normal');
      console.log(JSON.stringify(body, null, 2));
      res.status(200).end();
    }
    
  } catch (error) {
    console.error('❌ Error general:', error);
    // ⚠️ NUNCA enviar JSON, siempre texto plano
    res.set('Content-Type', 'text/plain');
    res.status(200).send('yZcJQaH3AqfzKgjn64vAcASaJrOMN27S6CESyU68WN/cDCP6abskoMa/pPjszXGKyyh/23lw84HW6ZilMfU6KL3j5AWwOx6GWNwtq8Aj7gz/Y7R+LccmJWxKo2UccMu5xJlduIFlFlOS1gAnOwKrk8wpuprsi4jAOspw3xO2uh3J883aC/csu/MhRPiYCaGGy/tTNvVDmb2Gw1WXFmpvLsZ/SBrgG0cDQJjQzpTO');
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

// Iniciar servidor
app.listen(port, '0.0.0.0', () => {
  console.log(`
╔══════════════════════════════════════════════════════════╗
║     🚀 WEBHOOK META FLOW - VERSIÓN CORREGIDA            ║
╠══════════════════════════════════════════════════════════╣
║  📍 Puerto: ${port}                                          ║
║  🔐 Private Key: ${privateKey ? '✅ Configurada' : '❌ No configurada'}        ║
║  ⚠️  IMPORTANTE: SIEMPRE responde con Base64, NUNCA JSON ║
╚══════════════════════════════════════════════════════════╝
  `);
});
