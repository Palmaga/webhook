// Import Express.js
const express = require('express');
const crypto = require('crypto'); // Para verificar firmas

// Create an Express app
const app = express();

// Middleware para parsear JSON bodies (raw para verificar firmas)
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf; // Guardar raw body para verificar firma
  }
}));

// Set port and verify_token
const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;
const appSecret = process.env.APP_SECRET; // Necesario para verificar firmas

// Función para verificar firma de Meta
function verifySignature(req, res, next) {
  if (!appSecret) {
    console.log('APP_SECRET no configurado, saltando verificación de firma');
    return next();
  }

  const signature = req.headers['x-hub-signature-256'];
  if (!signature) {
    console.log('No se encontró firma en el webhook');
    return res.status(401).send('No signature found');
  }

  const elements = signature.split('=');
  const signatureHash = elements[1];
  const expectedHash = crypto
    .createHmac('sha256', appSecret)
    .update(req.rawBody)
    .digest('hex');

  if (signatureHash !== expectedHash) {
    console.log('Firma inválida');
    return res.status(401).send('Invalid signature');
  }

  console.log('Firma verificada correctamente');
  next();
}

// Función para procesar mensajes Flow
function processFlowMessage(entry) {
  const changes = entry.changes || [];
  
  changes.forEach(change => {
    const value = change.value;
    
    // Verificar si es un mensaje de WhatsApp
    if (value.messages && value.messages.length > 0) {
      const message = value.messages[0];
      const contact = value.contacts ? value.contacts[0] : null;
      
      // Verificar si es un mensaje interactivo de tipo Flow
      if (message.type === 'interactive' && message.interactive) {
        const interactive = message.interactive;
        
        // Determinar el tipo de interacción Flow
        if (interactive.type === 'flow') {
          console.log('📱 Mensaje Flow detectado!');
          console.log('De:', contact?.wa_id || message.from);
          console.log('Flow data:', JSON.stringify(interactive.flow, null, 2));
          
          // Aquí puedes procesar los datos específicos del Flow
          handleFlowResponse(message.from, interactive.flow);
          
        } else if (interactive.type === 'nfm_reply') {
          console.log('🔄 Respuesta de Flow (nfm_reply) detectada!');
          console.log('De:', contact?.wa_id || message.from);
          console.log('NFM Reply:', JSON.stringify(interactive.nfm_reply, null, 2));
          
          // Procesar respuesta del Flow
          handleNfmReply(message.from, interactive.nfm_reply);
        }
      }
      
      // Otros tipos de mensajes
      else {
        console.log('📨 Otro tipo de mensaje:', message.type);
        console.log(JSON.stringify(message, null, 2));
      }
    }
    
    // Verificar estados
    if (value.statuses) {
      value.statuses.forEach(status => {
        console.log('📊 Estado de mensaje:', status.status);
        console.log('ID:', status.id);
        if (status.pricing) {
          console.log('Pricing:', status.pricing);
        }
        if (status.conversation) {
          console.log('Conversación:', status.conversation.id);
        }
      });
    }
  });
}

// Función para manejar respuestas de Flow
function handleFlowResponse(from, flowData) {
  // Aquí implementas tu lógica para procesar la respuesta del Flow
  console.log(`Procesando respuesta Flow de ${from}`);
  console.log('Flow ID:', flowData.id);
  console.log('Flow screen:', flowData.screen);
  console.log('Flow data:', JSON.stringify(flowData.data, null, 2));
  
  // Ejemplo: Guardar en base de datos, procesar respuestas, etc.
}

// Función para manejar NFM Reply
function handleNfmReply(from, nfmReply) {
  // Procesar respuestas de Flows de tipo nfm_reply
  console.log(`Procesando NFM Reply de ${from}`);
  console.log('Response JSON:', nfmReply.response_json);
  
  try {
    // Parsear la respuesta JSON
    const responseData = JSON.parse(nfmReply.response_json);
    console.log('Datos parseados:', responseData);
    
    // Aquí puedes acceder a los campos específicos del Flow
    // Por ejemplo: responseData.flow_name, responseData.screen_01, etc.
    
  } catch (error) {
    console.error('Error parseando response_json:', error);
  }
}

// Route for GET requests (verificación del webhook)
app.get('/webhook', (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

  if (mode === 'subscribe' && token === verifyToken) {
    console.log('✅ WEBHOOK VERIFICADO CORRECTAMENTE');
    res.status(200).send(challenge);
  } else {
    console.log('❌ Error de verificación - Token inválido');
    res.status(403).end();
  }
});

// Route for POST requests (recibir webhooks)
app.post('/webhook', verifySignature, (req, res) => {
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  console.log(`\n📡 Webhook recibido ${timestamp}\n`);
  
  try {
    const body = req.body;
    console.log('📦 Payload completo:');
    console.log(JSON.stringify(body, null, 2));
    
    // Procesar cada entrada del webhook
    if (body.entry) {
      body.entry.forEach(entry => {
        console.log(`\n📋 Procesando entry ID: ${entry.id}`);
        processFlowMessage(entry);
      });
    }
    
    // Siempre responder con 200 OK para Meta
    res.status(200).end();
    
  } catch (error) {
    console.error('❌ Error procesando webhook:', error);
    // Aún así responder 200 para no reintentar
    res.status(200).end();
  }
});

// Ruta para pruebas locales
app.get('/', (req, res) => {
  res.send('🚀 Webhook server para Meta Flow está funcionando!');
});

// Iniciar el servidor
app.listen(port, () => {
  console.log(`
╔════════════════════════════════════════╗
║   🚀 Servidor Webhook para Meta Flow   ║
╠════════════════════════════════════════╣
║  Puerto: ${port.padEnd(30)} ║
║  Estado: ✅ Activo                     ║
║  Verificación: ${verifyToken ? '✅ Configurada' : '⚠️  No configurada'}     ║
║  App Secret: ${appSecret ? '✅ Configurado' : '⚠️  No configurado'}       ║
╚════════════════════════════════════════╝
  `);
  
  console.log('📱 Endpoints disponibles:');
  console.log(`   GET  /webhook - Verificación`);
  console.log(`   POST /webhook - Recibir mensajes (incluyendo Flow)`);
  console.log(`   GET  / - Página de estado\n`);
});

// Manejo de errores no capturados
process.on('uncaughtException', (error) => {
  console.error('❌ Error no capturado:', error);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Promesa rechazada no manejada:', reason);
});
