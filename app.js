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

// ✅ VERIFICACIÓN - Versión CORREGIDA
app.get(['/', '/webhook'], (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

  console.log('\n🔐 Verificación de webhook recibida:');
  console.log('  └─ mode:', mode);
  console.log('  └─ challenge:', challenge);
  console.log('  └─ token recibido:', token);
  console.log('  └─ token esperado:', verifyToken);

  if (mode === 'subscribe' && token === verifyToken) {
    console.log('  └─ ✅ VERIFICACIÓN EXITOSA');
    
    // ⚠️ CRÍTICO: Enviar SOLO el challenge como string, sin JSON.stringify
    res.set('Content-Type', 'text/plain');
    res.status(200).send(String(challenge));
  } else {
    console.log('  └─ ❌ VERIFICACIÓN FALLIDA - Token inválido');
    res.status(403).end();
  }
});

// 📥 RECEPCIÓN de mensajes (POST)
app.post(['/', '/webhook'], verifySignature, (req, res) => {
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  console.log(`\n📡 Webhook recibido ${timestamp}`);
  console.log('📦 Payload:', JSON.stringify(req.body, null, 2));
  
  // Siempre responder 200 OK
  res.status(200).end();
});

// 🏠 Página de estado
app.get('/status', (req, res) => {
  res.send(`
    <html>
      <head><title>Webhook Meta Flow</title></head>
      <body style="font-family: Arial; padding: 20px;">
        <h1>🚀 Webhook Server para Meta Flow</h1>
        <p>✅ Servidor funcionando correctamente</p>
        <p>📅 ${new Date().toLocaleString()}</p>
        <hr>
        <h3>Configuración:</h3>
        <ul>
          <li>VERIFY_TOKEN: ${verifyToken ? '✅ Configurado' : '❌ No configurado'}</li>
          <li>APP_SECRET: ${appSecret ? '✅ Configurado' : '⚠️ Opcional'}</li>
        </ul>
        <h3>Endpoints activos:</h3>
        <ul>
          <li>GET / o /webhook - Verificación de webhook</li>
          <li>POST / o /webhook - Recepción de mensajes</li>
        </ul>
      </body>
    </html>
  `);
});

// Iniciar servidor
app.listen(port, () => {
  console.log(`
╔════════════════════════════════════════╗
║   🚀 Servidor Webhook para Meta Flow   ║
╠════════════════════════════════════════╣
║  Puerto:     ${port}                         ║
║  Rutas:      GET/POST /, /webhook       ║
║  VerifyToken: ${verifyToken ? '✅' : '❌'}                          ║
║  AppSecret:  ${appSecret ? '✅' : '⚠️'}                          ║
╚════════════════════════════════════════╝
  `);
});
