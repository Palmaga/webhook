const express = require('express');
const app = express();

app.use(express.json());

const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;

// Route for GET requests (Verificación del Webhook)
app.get('/', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === verifyToken) {
    console.log('WEBHOOK VERIFIED');
    // IMPORTANTE: Meta Flows requiere el challenge en Base64
    const base64Challenge = Buffer.from(challenge).toString('base64');
    res.status(200).send(base64Challenge);
  } else {
    res.status(403).end();
  }
});

// Route for POST requests (Interacción del Flow)
app.post('/', (req, res) => {
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  console.log(`\nWebhook received ${timestamp}\n`);
  console.log(JSON.stringify(req.body, null, 2));

  // Para validar la conexión inicial sin errores:
  // Meta espera una respuesta Base64. "SUCCESS" es un estándar común.
  const responsePayload = Buffer.from({
    "status":"SUCCESS"
  }).toString('base64');
  res.status(200).send(responsePayload);
});

app.listen(port, () => {
  console.log(`\nListening on port ${port}\n`);
});
