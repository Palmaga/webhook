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
let privateKey = process.env.PRIVATE_KEY;

// Formatear llave privada correctamente
if (privateKey) {
  privateKey = privateKey.replace(/\\n/g, '\n');
}

// ✅ VERIFICACIÓN DEL WEBHOOK - SIN BASE64, TEXTO PLANO SIMPLE
app.get(['/', '/webhook'], (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

  console.log('🔐 Verificación recibida:', { mode, challenge, token });
  
  if (mode === 'subscribe' && token === verifyToken) {
    console.log('✅ VERIFICACIÓN EXITOSA');
    // IMPORTANTE: Para verificación NO necesitas Base64
    // Solo el challenge como texto plano
    return res.status(200).send(String(challenge));
  } else {
    console.log('❌ VERIFICACIÓN FALLIDA');
    return res.status(403).end();
  }
});

// 🔐 Función para desencriptar y encriptar Flow
function processFlow(encryptedFlowData, encryptedAesKey, initialVector) {
  console.log('\n🔐 Procesando Flow...');
  
  // 1. Desencriptar AES key con RSA (OBLIGATORIO)
  console.log('  📍 Desencriptando AES key...');
  const aesKey = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    Buffer.from(encryptedAesKey, 'base64')
  );
  console.log('  ✅ AES key desencriptado:', aesKey.toString('hex').substring(0, 20) + '...');
  
  // 2. Desencriptar los datos del Flow
  console.log('  📍 Desencriptando flow data...');
  const iv = Buffer.from(initialVector, 'base64');
  const encryptedData = Buffer.from(encryptedFlowData, 'base64');
  
  const decipher = crypto.createDecipheriv('aes-128-cbc', aesKey, iv);
  decipher.setAutoPadding(true);
  
  const decrypted = Buffer.concat([
    decipher.update(encryptedData),
    decipher.final()
  ]);
  
  const flowData = JSON.parse(decrypted.toString('utf8'));
  console.log('  ✅ Flow data desencriptado:', JSON.stringify(flowData, null, 2));
  
  // 3. Preparar respuesta (usa los mismos screen/version que recibiste)
  const responseData = {
    version: flowData.version || '3.0',
    screen: flowData.screen || 'RESPONSE',
    data: {
      ...flowData.data,
      status: 'success',
      processed_at: new Date().toISOString()
    }
  };
  
  console.log('  📍 Respuesta preparada:', JSON.stringify(responseData, null, 2));
  
  // 4. Encriptar la respuesta CON EL MISMO AES KEY
  console.log('  📍 Encriptando respuesta...');
  const cipher = crypto.createCipheriv('aes-128-cbc', aesKey, iv);
  cipher.setAutoPadding(true);
  
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(responseData), 'utf8'),
    cipher.final()
  ]);
  
  const encryptedBase64 = encrypted.toString('base64');
  console.log('  ✅ Respuesta encriptada (Base64):', encryptedBase64.substring(0, 50) + '...');
  
  return encryptedBase64;
}

// 📥 RECEPCIÓN DE FLOWS - VERSIÓN CORREGIDA Y FUNCIONAL
app.post(['/', '/webhook'], (req, res) => {
  console.log('\n' + '='.repeat(60));
  console.log('📡 FLOW RECIBIDO');
  console.log('='.repeat(60));
  
  try {
    const body = req.body;
    
    // Verificar si es un Flow encriptado
    if (body.encrypted_flow_data && body.encrypted_aes_key && body.initial_vector) {
      
      console.log('📦 Tipo: Flow Encriptado');
      console.log('  📍 encrypted_flow_data:', body.encrypted_flow_data.substring(0, 30) + '...');
      console.log('  📍 encrypted_aes_key:', body.encrypted_aes_key.substring(0, 30) + '...');
      console.log('  📍 initial_vector:', body.initial_vector.substring(0, 30) + '...');
      
      // Verificar PRIVATE_KEY
      if (!privateKey) {
        console.error('❌ ERROR: PRIVATE_KEY no configurada');
        
        // ⚠️ En desarrollo, puedes usar esta respuesta de prueba
        // PERO EN PRODUCCIÓN DEBES TENER LA LLAVE PRIVADA
        console.log('⚠️ Usando respuesta de prueba (solo desarrollo)');
        const testResponse = "yZcJQaH3AqfzKgjn64vAcASaJrOMN27S6CESyU68WN/cDCP6abskoMa/pPjszXGKyyh/23lw84HW6ZilMfU6KL3j5AWwOx6GWNwtq8Aj7gz/Y7R+LccmJWxKo2UccMu5xJlduIFlFlOS1gAnOwKrk8wpuprsi4jAOspw3xO2uh3J883aC/csu/MhRPiYCaGGy/tTNvVDmb2Gw1WXFmpvLsZ/SBrgG0cDQJjQzpTO";
        
        res.set('Content-Type', 'text/plain');
        return res.status(200).send(testResponse);
      }
      
      try {
        // PROCESAR FLOW REAL
        const encryptedResponse = processFlow(
          body.encrypted_flow_data,
          body.encrypted_aes_key,
          body.initial_vector
        );
        
        console.log('\n✅ Enviando respuesta encriptada real');
        res.set('Content-Type', 'text/plain');
        res.status(200).send(encryptedResponse);
        
      } catch (error) {
        console.error('❌ Error procesando Flow:', error.message);
        
        // Enviar respuesta de error encriptada
        try {
          const errorResponse = {
            version: "3.0",
            screen: "ERROR",
            data: {
              error: error.message,
              timestamp: new Date().toISOString()
            }
          };
          
          // Desencriptar AES key para encriptar el error
          const aesKey = crypto.privateDecrypt(
            {
              key: privateKey,
              padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
              oaepHash: 'sha256',
            },
            Buffer.from(body.encrypted_aes_key, 'base64')
          );
          
          const iv = Buffer.from(body.initial_vector, 'base64');
          const cipher = crypto.createCipheriv('aes-128-cbc', aesKey, iv);
          cipher.setAutoPadding(true);
          
          const encrypted = Buffer.concat([
            cipher.update(JSON.stringify(errorResponse), 'utf8'),
            cipher.final()
          ]);
          
          res.set('Content-Type', 'text/plain');
          res.status(200).send(encrypted.toString('base64'));
          
        } catch (e) {
          console.error('❌ No se pudo encriptar error:', e.message);
          res.set('Content-Type', 'text/plain');
          res.status(200).send('Error procesando Flow');
        }
      }
      
    } else {
      // Mensaje normal de WhatsApp
      console.log('📨 Tipo: Mensaje WhatsApp normal');
      console.log(JSON.stringify(body, null, 2));
      res.status(200).end();
    }
    
  } catch (error) {
    console.error('❌ Error general:', error);
    res.set('Content-Type', 'text/plain');
    res.status(200).send('Error en webhook');
  }
});

// 📊 Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    encryption: privateKey ? '✅ Configurada' : '❌ No configurada',
    mode: privateKey ? 'produccion' : 'desarrollo (respuestas fijas)'
  });
});

// 🏠 Página principal
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Meta Flow Webhook</title>
        <style>
          body { font-family: Arial; padding: 40px; background: #1a1a1a; color: #fff; }
          .container { max-width: 800px; margin: 0 auto; background: #2d2d2d; padding: 30px; border-radius: 10px; }
          .success { color: #4caf50; }
          .error { color: #f44336; }
          .warning { color: #ff9800; }
          code { background: #3d3d3d; padding: 2px 5px; border-radius: 3px; color: #ffd700; }
          pre { background: #1a1a1a; padding: 15px; border-radius: 5px; color: #fff; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🚀 Meta Flow Webhook</h1>
          <p class="${privateKey ? 'success' : 'warning'}">
            ${privateKey ? '✅ MODO PRODUCCIÓN' : '⚠️ MODO DESARROLLO'}
          </p>
          
          <h3>🔐 Estado Encriptación:</h3>
          <ul>
            <li>PRIVATE_KEY: ${privateKey ? '✅ Configurada' : '❌ No configurada'}</li>
            <li>Respuestas: ${privateKey ? 'Encriptadas reales' : 'Base64 fijo (pruebas)'}</li>
          </ul>
          
          <h3>⚠️ IMPORTANTE:</h3>
          <p style="color: #ff9800;">
            ${!privateKey ? 
              'Estás usando respuestas BASE64 FIJAS. Meta no puede descifrarlas. Configura PRIVATE_KEY para producción.' : 
              'Todo correcto. Las respuestas son encriptadas específicamente para cada Flow.'}
          </p>
          
          <h3>🔧 Configurar PRIVATE_KEY:</h3>
          <pre>
# 1. Generar llave RSA
openssl genrsa -out private.key 2048

# 2. Ver llave (copia TODO el contenido)
cat private.key

# 3. Configurar en plataforma:
PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----"
          </pre>
        </div>
      </body>
    </html>
  `);
});

// Iniciar servidor
app.listen(port, '0.0.0.0', () => {
  console.log('\n' + '🔥'.repeat(30));
  console.log('   WEBHOOK META FLOW');
  console.log('🔥'.repeat(30) + '\n');
  console.log(`📍 Puerto: ${port}`);
  console.log(`📍 Verify Token: ${verifyToken || 'No configurado'}`);
  console.log(`📍 Private Key: ${privateKey ? '✅ CONFIGURADA' : '❌ NO CONFIGURADA'}`);
  
  if (!privateKey) {
    console.log('\n⚠️  ADVERTENCIA: Modo DESARROLLO');
    console.log('   Usando respuestas BASE64 FIJAS');
    console.log('   Meta NO podrá descifrar estas respuestas');
    console.log('\n🔧 Para producción:');
    console.log('   1. Genera llave RSA: openssl genrsa -out private.key 2048');
    console.log('   2. Configura PRIVATE_KEY en tu plataforma');
    console.log('   3. Sube la llave pública a Meta Developers\n');
  } else {
    console.log('\n✅ MODO PRODUCCIÓN');
    console.log('   Las respuestas son encriptadas específicamente para cada Flow\n');
  }
});
