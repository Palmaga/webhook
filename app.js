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

// ✅ VERIFICACIÓN - CON BASE64 (LO QUE META ESPERA)
app.get(['/', '/webhook'], (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

  console.log('\n' + '='.repeat(50));
  console.log('🔐 VERIFICACIÓN DE WEBHOOK');
  console.log('='.repeat(50));
  console.log('  📍 Mode:', mode);
  console.log('  📍 Challenge (original):', challenge);
  console.log('  📍 Token recibido:', token);
  console.log('  📍 Token esperado:', verifyToken);
  console.log('-'.repeat(50));

  if (mode === 'subscribe' && token === verifyToken) {
    // 🔐 CONVERTIR A BASE64 - Meta espera el challenge en Base64
    const challengeBase64 = Buffer.from(String(challenge)).toString('base64');
    
    console.log('  ✅ VERIFICACIÓN EXITOSA');
    console.log('  🔑 Challenge en Base64:', challengeBase64);
    console.log('='.repeat(50));
    
    // Enviar SOLO el Base64, nada más
    res.set('Content-Type', 'text/plain');
    res.status(200).send(challengeBase64);
  } else {
    console.log('  ❌ VERIFICACIÓN FALLIDA');
    console.log('  ⚠️  El token no coincide');
    console.log('='.repeat(50));
    res.status(403).end();
  }
});

// 📥 RECEPCIÓN de mensajes (POST)
app.post(['/', '/webhook'], verifySignature, (req, res) => {
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  console.log(`\n📡 Webhook POST recibido ${timestamp}`);
  console.log('📦 Payload:', JSON.stringify(req.body, null, 2));
  
  // Procesar mensajes Flow aquí...
  if (req.body.entry) {
    req.body.entry.forEach(entry => {
      if (entry.changes) {
        entry.changes.forEach(change => {
          if (change.value && change.value.messages) {
            change.value.messages.forEach(message => {
              if (message.type === 'interactive' && message.interactive) {
                console.log('🎯 Mensaje Flow detectado:', message.interactive);
              }
            });
          }
        });
      }
    });
  }
  
  // Siempre responder 200 OK
  res.status(200).end();
});

// 🏠 Página de estado
app.get('/status', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Webhook Meta Flow</title>
        <style>
          body { font-family: Arial, sans-serif; padding: 30px; background: #f5f5f5; }
          .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
          .success { color: green; }
          .warning { color: orange; }
          code { background: #f0f0f0; padding: 2px 5px; border-radius: 3px; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🚀 Webhook Server para Meta Flow</h1>
          <p class="success">✅ Servidor funcionando correctamente con codificación Base64</p>
          <p>📅 ${new Date().toLocaleString()}</p>
          <hr>
          <h3>⚙️ Configuración:</h3>
          <ul>
            <li>VERIFY_TOKEN: ${verifyToken ? '✅ Configurado' : '❌ No configurado'}</li>
            <li>APP_SECRET: ${appSecret ? '✅ Configurado' : '⚠️ Opcional'}</li>
          </ul>
          <h3>📌 Endpoints activos:</h3>
          <ul>
            <li><code>GET /</code> o <code>/webhook</code> - Verificación (responde con Base64)</li>
            <li><code>POST /</code> o <code>/webhook</code> - Recepción de mensajes</li>
            <li><code>GET /status</code> - Esta página</li>
          </ul>
          <h3>🧪 Prueba de verificación:</h3>
          <p>Usa este comando para probar localmente:</p>
          <pre style="background: #333; color: #fff; padding: 10px; border-radius: 5px;">
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
╔════════════════════════════════════════════════════╗
║     🚀 SERVIDOR WEBHOOK PARA META FLOW            ║
╠════════════════════════════════════════════════════╣
║  📍 Puerto:      ${port}                              ║
║  📍 Rutas:       GET/POST /, /webhook              ║
║  🔐 Verificación: BASE64 ENCODED                   ║
╠════════════════════════════════════════════════════╣
║  🎯 Verify Token: ${verifyToken ? '✅' : '❌'}                               ║
║  🔑 App Secret:   ${appSecret ? '✅' : '⚠️ Opcional'}                        ║
╚════════════════════════════════════════════════════╝
  `);
  
  // Ejemplo de challenge en Base64 para pruebas
  const testChallenge = "123456789";
  const testBase64 = Buffer.from(testChallenge).toString('base64');
  console.log('\n📝 Ejemplo de codificación Base64:');
  console.log(`   Challenge: ${testChallenge} → Base64: ${testBase64}\n`);
});
