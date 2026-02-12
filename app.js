// Import Express.js
const express = require('express');
const crypto = require('crypto');

const app = express();

// Middleware para parsear JSON
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// 📌 CONFIGURACIÓN CON VALORES POR DEFECTO PARA EVITAR ERRORES AL DESPLEGAR
const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN || 'webhook_verify_token_123';
const appSecret = process.env.APP_SECRET || '';
const privateKey = process.env.PRIVATE_KEY || '';

// ⚠️ NO USAR CRYPTO SI NO HAY LLAVES - Evita errores al desplegar
const hasEncryption = privateKey && privateKey.includes('BEGIN PRIVATE KEY');

// ✅ VERIFICACIÓN DEL WEBHOOK - SIN BASE64 para máxima compatibilidad
app.get(['/', '/webhook'], (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

  console.log('🔐 Verificando webhook...');
  
  if (mode === 'subscribe' && token === verifyToken) {
    console.log('✅ VERIFICACIÓN EXITOSA');
    // IMPORTANTE: Enviar SOLO el challenge como string
    return res.status(200).send(String(challenge));
  } else {
    console.log('❌ VERIFICACIÓN FALLIDA - Token incorrecto');
    return res.status(403).send('Token inválido');
  }
});

// 📥 RECEPCIÓN DE WEBHOOKS
app.post(['/', '/webhook'], (req, res) => {
  const timestamp = new Date().toISOString();
  
  console.log('\n' + '='.repeat(60));
  console.log(`📡 Webhook recibido: ${timestamp}`);
  console.log('='.repeat(60));
  
  try {
    const body = req.body;
    console.log('📦 Payload:', JSON.stringify(body, null, 2));
    
    // 📱 DETECTAR TIPO DE MENSAJE
    if (body.entry) {
      // Mensaje normal de WhatsApp
      console.log('✅ Mensaje WhatsApp recibido');
      processWhatsAppMessage(body);
      return res.status(200).end();
      
    } else if (body.encrypted_flow_data) {
      // Flow de WhatsApp
      console.log('🎯 Flow de WhatsApp detectado');
      
      if (hasEncryption) {
        console.log('🔐 Encriptación configurada - Procesando Flow...');
        // Aquí va tu lógica de desencriptación cuando tengas las llaves
      } else {
        console.log('⚠️ Modo desarrollo: Respondiendo con challenge de prueba');
        // Respuesta de prueba para desarrollo
        const testResponse = "yZcJQaH3AqfzKgjn64vAcASaJrOMN27S6CESyU68WN/cDCP6abskoMa/pPjszXGKyyh/23lw84HW6ZilMfU6KL3j5AWwOx6GWNwtq8Aj7gz/Y7R+LccmJWxKo2UccMu5xJlduIFlFlOS1gAnOwKrk8wpuprsi4jAOspw3xO2uh3J883aC/csu/MhRPiYCaGGy/tTNvVDmb2Gw1WXFmpvLsZ/SBrgG0cDQJjQzpTO";
        return res.set('Content-Type', 'text/plain').status(200).send(testResponse);
      }
      
    } else {
      // Otro tipo de mensaje
      console.log('📦 Otro tipo de payload');
    }
    
    // SIEMPRE responder 200 OK
    res.status(200).end();
    
  } catch (error) {
    console.error('❌ Error procesando webhook:', error);
    // Siempre 200 aunque haya error
    res.status(200).end();
  }
});

// Función para procesar mensajes de WhatsApp
function processWhatsAppMessage(body) {
  try {
    body.entry?.forEach(entry => {
      entry.changes?.forEach(change => {
        if (change.value?.messages) {
          change.value.messages.forEach(message => {
            console.log(`  📨 De: ${message.from}`);
            console.log(`  📝 Tipo: ${message.type}`);
            
            if (message.type === 'text') {
              console.log(`  💬 Texto: ${message.text?.body}`);
            } else if (message.type === 'interactive') {
              console.log(`  🎯 Interactivo:`, message.interactive);
            }
          });
        }
        
        if (change.value?.statuses) {
          change.value.statuses.forEach(status => {
            console.log(`  📊 Estado: ${status.status}`);
          });
        }
      });
    });
  } catch (error) {
    console.error('Error procesando mensaje:', error);
  }
}

// 📊 Página de estado
app.get('/status', (req, res) => {
  const status = {
    server: 'running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    config: {
      port: port,
      verifyToken: verifyToken ? '✅ configurado' : '⚠️ usando default',
      appSecret: appSecret ? '✅ configurado' : '⚠️ opcional',
      encryption: hasEncryption ? '✅ activa' : '⚠️ inactiva (modo desarrollo)'
    }
  };
  
  res.json(status);
});

// 🏠 Página principal
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Webhook Meta Flow</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
          body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            padding: 30px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            margin: 0;
            min-height: 100vh;
          }
          .container { 
            max-width: 800px; 
            margin: 0 auto; 
            background: rgba(255,255,255,0.95);
            color: #333;
            padding: 40px; 
            border-radius: 20px; 
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
          }
          h1 { margin-top: 0; color: #667eea; }
          .success { color: #10b981; font-weight: bold; }
          .warning { color: #f59e0b; }
          code { 
            background: #f3f4f6; 
            padding: 2px 6px; 
            border-radius: 4px;
            font-size: 14px;
          }
          pre { 
            background: #1f2937; 
            color: #e5e7eb; 
            padding: 15px; 
            border-radius: 10px;
            overflow-x: auto;
          }
          .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            margin-left: 10px;
          }
          .badge-success { background: #10b981; color: white; }
          .badge-warning { background: #f59e0b; color: white; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🚀 Webhook Meta Flow</h1>
          <p>
            ✅ Servidor funcionando correctamente
            <span class="badge badge-success">v1.0.0</span>
          </p>
          
          <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">
          
          <h3>📋 Configuración actual:</h3>
          <ul style="list-style: none; padding: 0;">
            <li style="margin: 10px 0;">
              🔌 Puerto: <code>${port}</code>
            </li>
            <li style="margin: 10px 0;">
              🔐 Verify Token: <code>${verifyToken.substring(0, 10)}...</code>
              ${verifyToken !== 'webhook_verify_token_123' ? 
                '<span class="badge badge-success">personalizado</span>' : 
                '<span class="badge badge-warning">default</span>'}
            </li>
            <li style="margin: 10px 0;">
              🔑 Encriptación: 
              ${hasEncryption ? 
                '<span class="badge badge-success">activa</span>' : 
                '<span class="badge badge-warning">modo desarrollo</span>'}
            </li>
          </ul>
          
          <h3>📌 Endpoints disponibles:</h3>
          <ul style="list-style: none; padding: 0;">
            <li style="margin: 10px 0;">
              <code>GET /webhook</code> - Verificación del webhook
            </li>
            <li style="margin: 10px 0;">
              <code>POST /webhook</code> - Recibir mensajes
            </li>
            <li style="margin: 10px 0;">
              <code>GET /status</code> - Estado del servidor (JSON)
            </li>
            <li style="margin: 10px 0;">
              <code>GET /</code> - Esta página
            </li>
          </ul>
          
          <h3>🧪 Prueba de verificación:</h3>
          <pre>curl "${req.protocol}://${req.get('host')}/webhook?hub.mode=subscribe&hub.challenge=123456&hub.verify_token=${verifyToken}"</pre>
          
          <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">
          
          <p style="color: #6b7280; font-size: 14px; text-align: center;">
            ⚡ Listo para recibir webhooks de Meta WhatsApp Business API
          </p>
        </div>
      </body>
    </html>
  `);
});

// 📋 Health check para plataformas de despliegue
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// 🚀 Iniciar servidor
const server = app.listen(port, '0.0.0.0', () => {
  console.log('\n' + '⭐'.repeat(30));
  console.log('   🚀 WEBHOOK META FLOW DESPLEGADO');
  console.log('⭐'.repeat(30));
  console.log(`\n📌 Servidor:`);
  console.log(`   • Puerto: ${port}`);
  console.log(`   • Modo: ${process.env.NODE_ENV || 'development'}`);
  console.log(`   • Verify Token: ${verifyToken}`);
  console.log(`   • Encriptación: ${hasEncryption ? '✅ Activa' : '⚠️ Desarrollo'}`);
  console.log(`\n📌 Endpoints:`);
  console.log(`   • GET  /webhook - Verificación`);
  console.log(`   • POST /webhook - Webhook`);
  console.log(`   • GET  /status - Estado`);
  console.log(`   • GET  /health - Health check`);
  console.log(`   • GET  / - Página principal`);
  console.log('\n' + '⭐'.repeat(30) + '\n');
});

// Manejo de errores global
process.on('uncaughtException', (err) => {
  console.error('❌ Error no capturado:', err);
  // No matamos el proceso en producción
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Promesa rechazada:', reason);
});

module.exports = app;
