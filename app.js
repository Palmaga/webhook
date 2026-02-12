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

// ✅ VERIFICACIÓN - Acepta tanto / como /webhook
app.get(['/', '/webhook'], (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

  if (mode === 'subscribe' && token === verifyToken) {
    console.log('✅ WEBHOOK VERIFICADO CORRECTAMENTE');
    res.status(200).send(challenge);
  } else {
    console.log('❌ Error de verificación - Token inválido');
    res.status(403).end();
  }
});

// 📥 RECEPCIÓN - Acepta tanto / como /webhook
app.post(['/', '/webhook'], verifySignature, (req, res) => {
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  console.log(`\n📡 Webhook recibido ${timestamp}`);
  console.log('📦 Payload:', JSON.stringify(req.body, null, 2));
  
  // SIEMPRE responder 200 OK
  res.status(200).end();
});

// 🏠 Página de inicio
app.get('/status', (req, res) => {
  res.send('🚀 Webhook server para Meta Flow está funcionando!');
});

// Iniciar servidor
app.listen(port, () => {
  console.log(`
╔════════════════════════════════════════╗
║   🚀 Servidor Webhook para Meta Flow   ║
╠════════════════════════════════════════╣
║  Puerto: ${port}                               ║
║  Rutas:  GET/POST /, /webhook          ║
║  Estado: ✅ Activo                     ║
╚════════════════════════════════════════╝
  `);
});
