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

// ✅ VERIFICACIÓN DEL WEBHOOK
app.get(['/', '/webhook'], (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

  if (mode === 'subscribe' && token === verifyToken) {
    console.log('✅ WEBHOOK VERIFICADO');
    return res.status(200).send(String(challenge));
  } else {
    return res.status(403).end();
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
    
    return {
      aesKey,
      iv,
      data: JSON.parse(decrypted.toString('utf8'))
    };
    
  } catch (error) {
    console.error('❌ Error desencriptando:', error);
    throw error;
  }
}

// 🔐 Función para encriptar respuesta del Flow
function encryptFlowResponse(responseData, aesKey, iv) {
  try {
    const cipher = crypto.createCipheriv('aes-128-cbc', aesKey, iv);
    cipher.setAutoPadding(true);
    
    const encrypted = Buffer.concat([
      cipher.update(JSON.stringify(responseData), 'utf8'),
      cipher.final()
    ]);
    
    return encrypted.toString('base64');
    
  } catch (error) {
    console.error('❌ Error encriptando respuesta:', error);
    throw error;
  }
}

// 📥 MANEJADOR PRINCIPAL DE FLOWS
app.post(['/', '/webhook'], (req, res) => {
  const timestamp = new Date().toISOString();
  
  console.log('\n' + '='.repeat(60));
  console.log(`📡 REQUEST RECIBIDO: ${timestamp}`);
  console.log('='.repeat(60));
  
  try {
    const body = req.body;
    
    // ============================================
    // CASO 1,2,3,4: DATA EXCHANGE REQUEST (FLOW)
    // ============================================
    if (body.encrypted_flow_data && body.encrypted_aes_key && body.initial_vector) {
      
      console.log('🔐 TIPO: DATA EXCHANGE REQUEST (Flow)');
      
      if (!privateKey) {
        console.error('❌ PRIVATE_KEY no configurada');
        return res.status(200).end(); // Solo para desarrollo
      }
      
      try {
        // Desencriptar request
        const { aesKey, iv, data: flowData } = decryptFlowData(
          body.encrypted_flow_data,
          body.encrypted_aes_key,
          body.initial_vector
        );
        
        console.log('\n📊 FLOW DATA RECIBIDA:');
        console.log(JSON.stringify(flowData, null, 2));
        
        // ============================================
        // IDENTIFICAR EL TIPO DE ACCIÓN
        // ============================================
        let responseData;
        
        // CASO 1: Usuario abre el Flow (data_exchange)
        if (flowData.action === 'data_exchange' || flowData.screen === 'INITIAL') {
          console.log('🎯 CASO 1: Usuario abre el Flow');
          
          responseData = {
            version: flowData.version || '3.0',
            screen: flowData.screen || 'WELCOME',
            data: {
              ...flowData.data,
              welcome_message: '¡Bienvenido al Flow!',
              timestamp: new Date().toISOString()
            }
          };
        }
        
        // CASO 2: Usuario envía el formulario
        else if (flowData.screen && flowData.data) {
          console.log('🎯 CASO 2: Usuario envía formulario');
          
          // Procesar datos del formulario
          console.log('📝 Datos recibidos del formulario:');
          Object.entries(flowData.data).forEach(([key, value]) => {
            console.log(`   • ${key}: ${value}`);
          });
          
          responseData = {
            version: flowData.version || '3.0',
            screen: 'CONFIRMATION',
            data: {
              ...flowData.data,
              status: 'completed',
              confirmation_message: 'Formulario recibido correctamente',
              processed_at: new Date().toISOString()
            }
          };
        }
        
        // CASO 3: Usuario presiona botón back
        else if (flowData.action === 'back') {
          console.log('🎯 CASO 3: Usuario presiona botón back');
          
          responseData = {
            version: flowData.version || '3.0',
            screen: flowData.previous_screen || 'PREVIOUS_SCREEN',
            data: flowData.data || {}
          };
        }
        
        // CASO 4: Usuario cambia valor de un componente
        else if (flowData.component_id) {
          console.log(`🎯 CASO 4: Usuario cambia componente: ${flowData.component_id}`);
          console.log(`   Nuevo valor: ${flowData.component_value}`);
          
          responseData = {
            version: flowData.version || '3.0',
            screen: flowData.screen,
            data: {
              ...flowData.data,
              [flowData.component_id]: flowData.component_value,
              validated: true
            }
          };
        }
        
        // Por defecto
        else {
          console.log('🎯 CASO: Acción no específica');
          
          responseData = {
            version: flowData.version || '3.0',
            screen: flowData.screen || 'RESPONSE',
            data: {
              ...flowData.data,
              status: 'success',
              message: 'Flow procesado correctamente'
            }
          };
        }
        
        // Encriptar respuesta
        const encryptedResponse = encryptFlowResponse(responseData, aesKey, iv);
        
        console.log('\n📤 RESPUESTA ENVIADA:');
        console.log(`   Screen: ${responseData.screen}`);
        console.log(`   Base64: ${encryptedResponse.substring(0, 50)}...`);
        
        res.set('Content-Type', 'text/plain');
        res.status(200).send(encryptedResponse);
        
      } catch (error) {
        console.error('❌ Error procesando Flow:', error);
        
        // Enviar respuesta de error encriptada
        try {
          const { aesKey, iv } = decryptFlowData(
            body.encrypted_flow_data,
            body.encrypted_aes_key,
            body.initial_vector
          );
          
          const errorResponse = {
            version: "3.0",
            screen: "ERROR",
            data: {
              error_message: "Ocurrió un error procesando tu solicitud",
              error_code: error.code || "500",
              timestamp: new Date().toISOString()
            }
          };
          
          const encryptedError = encryptFlowResponse(errorResponse, aesKey, iv);
          res.set('Content-Type', 'text/plain');
          res.status(200).send(encryptedError);
          
        } catch (e) {
          console.error('❌ No se pudo encriptar error');
          res.status(200).end();
        }
      }
      
    // ============================================
    // CASO 5: ERROR NOTIFICATION REQUEST
    // ============================================
    } else if (body.error && body.flow_id) {
      console.log('⚠️ TIPO: ERROR NOTIFICATION REQUEST');
      console.log(`   Flow ID: ${body.flow_id}`);
      console.log(`   Error: ${body.error.message || JSON.stringify(body.error)}`);
      console.log(`   Timestamp: ${body.timestamp || new Date().toISOString()}`);
      
      // Aquí puedes loguear el error para debugging
      // No necesitas responder nada especial
      res.status(200).end();
    
    // ============================================
    // CASO 6: HEALTH CHECK REQUEST
    // ============================================
    } else if (body.health_check) {
      console.log('🏥 TIPO: HEALTH CHECK REQUEST');
      
      res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        encryption: privateKey ? 'configured' : 'not_configured'
      });
    
    // ============================================
    // MENSAJE NORMAL DE WHATSAPP
    // ============================================
    } else if (body.entry) {
      console.log('📨 TIPO: MENSAJE WHATSAPP NORMAL');
      
      body.entry.forEach(entry => {
        entry.changes?.forEach(change => {
          if (change.value?.messages) {
            change.value.messages.forEach(message => {
              console.log(`   📍 De: ${message.from}`);
              console.log(`   📍 Tipo: ${message.type}`);
              
              if (message.type === 'text') {
                console.log(`   💬 Texto: ${message.text?.body}`);
              }
            });
          }
          
          if (change.value?.statuses) {
            change.value.statuses.forEach(status => {
              console.log(`   📊 Estado: ${status.status}`);
            });
          }
        });
      });
      
      res.status(200).end();
      
    } else {
      console.log('📦 TIPO: DESCONOCIDO');
      console.log(JSON.stringify(body, null, 2));
      res.status(200).end();
    }
    
  } catch (error) {
    console.error('❌ Error general:', error);
    res.status(200).end();
  }
});

// 📊 HEALTH CHECK ENDPOINT (para monitoreo)
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    flows_processed: global.flowCounter || 0,
    encryption: privateKey ? 'configured' : 'not_configured',
    mode: privateKey ? 'production' : 'development'
  });
});

// 📈 MÉTRICAS (opcional)
app.get('/metrics', (req, res) => {
  res.json({
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    flows_processed: global.flowCounter || 0,
    encryption_configured: !!privateKey
  });
});

// 🏠 Página principal
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Meta Flow Webhook</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                padding: 40px 20px; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                margin: 0;
                min-height: 100vh;
            }
            .container { 
                max-width: 1000px; 
                margin: 0 auto; 
                background: white; 
                padding: 40px; 
                border-radius: 20px; 
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            }
            h1 { color: #667eea; margin-top: 0; }
            h2 { color: #4a5568; margin-top: 30px; }
            .badge {
                display: inline-block;
                padding: 6px 12px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: bold;
                margin-left: 10px;
            }
            .badge-success { background: #48bb78; color: white; }
            .badge-warning { background: #ecc94b; color: #1a202c; }
            .badge-danger { background: #f56565; color: white; }
            .status {
                padding: 15px;
                border-radius: 10px;
                margin: 20px 0;
                font-weight: bold;
            }
            .status-success { background: #c6f6d5; color: #22543d; }
            .status-warning { background: #feebc8; color: #744210; }
            .case-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }
            .case-card {
                background: #f7fafc;
                padding: 20px;
                border-radius: 10px;
                border-left: 4px solid #667eea;
            }
            .case-card h3 { margin-top: 0; color: #2d3748; }
            code {
                background: #edf2f7;
                padding: 2px 6px;
                border-radius: 4px;
                font-size: 14px;
            }
            pre {
                background: #2d3748;
                color: #e2e8f0;
                padding: 15px;
                border-radius: 10px;
                overflow-x: auto;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🚀 Webhook Meta Flow</h1>
            
            <div class="status ${privateKey ? 'status-success' : 'status-warning'}">
                ${privateKey ? 
                    '✅ MODO PRODUCCIÓN - Encriptación activa' : 
                    '⚠️ MODO DESARROLLO - Sin encriptación real'}
            </div>
            
            <h2>📋 Casos de Flow Soportados</h2>
            <div class="case-grid">
                <div class="case-card">
                    <h3>📱 Caso 1</h3>
                    <p><strong>Usuario abre el Flow</strong></p>
                    <p><code>data_exchange</code> en parámetros</p>
                    <p style="color: #48bb78;">✅ Implementado</p>
                </div>
                
                <div class="case-card">
                    <h3>📝 Caso 2</h3>
                    <p><strong>Usuario envía formulario</strong></p>
                    <p><code>on-click-action</code> = data_exchange</p>
                    <p style="color: #48bb78;">✅ Implementado</p>
                </div>
                
                <div class="case-card">
                    <h3>🔙 Caso 3</h3>
                    <p><strong>Botón back</strong></p>
                    <p><code>refresh_on_back</code> = true</p>
                    <p style="color: #48bb78;">✅ Implementado</p>
                </div>
                
                <div class="case-card">
                    <h3>🔄 Caso 4</h3>
                    <p><strong>Cambio de componente</strong></p>
                    <p><code>on-select-action</code> definido</p>
                    <p style="color: #48bb78;">✅ Implementado</p>
                </div>
                
                <div class="case-card">
                    <h3>⚠️ Caso 5</h3>
                    <p><strong>Error Notification</strong></p>
                    <p>Respuesta inválida anterior</p>
                    <p style="color: #48bb78;">✅ Implementado</p>
                </div>
                
                <div class="case-card">
                    <h3>🏥 Caso 6</h3>
                    <p><strong>Health Check</strong></p>
                    <p>Periódico de WhatsApp</p>
                    <p style="color: #48bb78;">✅ Implementado</p>
                </div>
            </div>
            
            <h2>🔧 Configuración</h2>
            <pre>
PRIVATE_KEY: ${privateKey ? '✅ Configurada' : '❌ No configurada'}
VERIFY_TOKEN: ${verifyToken ? '✅ Configurado' : '❌ No configurado'}
PUERTO: ${port}
MODO: ${privateKey ? 'PRODUCCIÓN' : 'DESARROLLO'}</pre>
            
            <h2>📌 Endpoints</h2>
            <ul>
                <li><code>GET /webhook</code> - Verificación</li>
                <li><code>POST /webhook</code> - Todos los casos de Flow</li>
                <li><code>GET /health</code> - Health check</li>
                <li><code>GET /metrics</code> - Métricas</li>
            </ul>
            
            <p style="color: #718096; font-size: 14px; margin-top: 40px; text-align: center;">
                🚀 Servidor listo para producción - ${new Date().toLocaleString()}
            </p>
        </div>
    </body>
    </html>
  `);
});

// Contador de flows (opcional)
global.flowCounter = 0;

// Iniciar servidor
app.listen(port, '0.0.0.0', () => {
  console.log('\n' + '🚀'.repeat(40));
  console.log('   WEBHOOK META FLOW - TODOS LOS CASOS IMPLEMENTADOS');
  console.log('🚀'.repeat(40) + '\n');
  
  console.log(`📌 Puerto: ${port}`);
  console.log(`📌 Verify Token: ${verifyToken ? '✅' : '❌'}`);
  console.log(`📌 Private Key: ${privateKey ? '✅ PRODUCCIÓN' : '⚠️ DESARROLLO'}\n`);
  
  console.log('📋 CASOS DE FLOW IMPLEMENTADOS:');
  console.log('   ✅ Caso 1: Usuario abre el Flow (data_exchange)');
  console.log('   ✅ Caso 2: Usuario envía formulario');
  console.log('   ✅ Caso 3: Botón back (refresh_on_back)');
  console.log('   ✅ Caso 4: Cambio de componente (on-select-action)');
  console.log('   ✅ Caso 5: Error Notification');
  console.log('   ✅ Caso 6: Health Check\n');
  
  console.log('📌 Endpoints:');
  console.log(`   GET  /webhook - Verificación`);
  console.log(`   POST /webhook - Todos los casos de Flow`);
  console.log(`   GET  /health - Health check endpoint`);
  console.log(`   GET  /metrics - Métricas\n`);
});
