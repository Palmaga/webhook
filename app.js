// Import Express.js
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken'); // Necesario para flow_token_signature

const app = express();

// Middleware para parsear JSON con rawBody para firma
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;
const appSecret = process.env.APP_SECRET; // Necesario para verificar JWT
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

// 🔐 Función para verificar flow_token_signature (JWT)
function verifyFlowTokenSignature(flowToken, signature) {
  if (!signature || !appSecret) {
    console.log('⚠️ No signature or APP_SECRET provided, skipping verification');
    return true;
  }
  
  try {
    const decoded = jwt.verify(signature, appSecret);
    console.log('✅ Flow token signature verified:', decoded);
    return decoded.flow_token === flowToken;
  } catch (error) {
    console.error('❌ Invalid flow token signature:', error.message);
    return false;
  }
}

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
  console.log(`📡 FLOW REQUEST RECIBIDO: ${timestamp}`);
  console.log('='.repeat(60));
  
  try {
    const body = req.body;
    
    // ============================================
    // CASO: DATA EXCHANGE REQUEST (FLOW ENCRIPTADO)
    // ============================================
    if (body.encrypted_flow_data && body.encrypted_aes_key && body.initial_vector) {
      
      console.log('🔐 TIPO: DATA EXCHANGE REQUEST');
      
      if (!privateKey) {
        console.error('❌ PRIVATE_KEY no configurada');
        return res.status(200).end();
      }
      
      try {
        // 1️⃣ Desencriptar request
        const { aesKey, iv, data: flowData } = decryptFlowData(
          body.encrypted_flow_data,
          body.encrypted_aes_key,
          body.initial_vector
        );
        
        console.log('\n📊 FLOW DATA DESENCRIPTADA:');
        console.log(JSON.stringify(flowData, null, 2));
        
        // 2️⃣ Validar versión (debe ser 3.0)
        const version = flowData.version || '3.0';
        if (version !== '3.0') {
          console.log(`⚠️ Versión inesperada: ${version}, usando 3.0`);
        }
        
        // 3️⃣ Verificar flow_token_signature (si existe)
        if (flowData.flow_token_signature) {
          const isValid = verifyFlowTokenSignature(
            flowData.flow_token,
            flowData.flow_token_signature
          );
          
          if (!isValid) {
            console.error('❌ Flow token signature inválida');
          }
        }
        
        // 4️⃣ Determinar acción y preparar respuesta según la documentación
        let responseData = {
          version: '3.0', // ⚠️ SIEMPRE 3.0
        };
        
        // CASO: INIT - Usuario abre el Flow
        if (flowData.action === 'INIT') {
          console.log('🎯 ACCIÓN: INIT (Usuario abre Flow)');
          
          responseData = {
            ...responseData,
            screen: flowData.screen || 'WELCOME',
            // data NO se incluye para INIT
            flow_token: flowData.flow_token // Mismo token que recibimos
          };
        }
        
        // CASO: BACK - Usuario presiona botón atrás
        else if (flowData.action === 'BACK') {
          console.log('🎯 ACCIÓN: BACK (Usuario presiona botón atrás)');
          
          responseData = {
            ...responseData,
            screen: flowData.previous_screen || flowData.screen,
            // data NO se incluye para BACK
            flow_token: flowData.flow_token
          };
        }
        
        // CASO: data_exchange - Usuario envía formulario
        else if (flowData.action === 'data_exchange' || flowData.screen) {
          console.log('🎯 ACCIÓN: data_exchange (Usuario envía datos)');
          
          // ⚠️ IMPORTANTE: "SUCCESS" es un nombre reservado, no puede usarse
          let screenName = 'CONFIRMATION';
          if (flowData.screen === 'SUCCESS') {
            console.log('⚠️ "SUCCESS" es nombre reservado, cambiando a CONFIRMATION');
            screenName = 'CONFIRMATION';
          } else {
            screenName = flowData.next_screen || 'CONFIRMATION';
          }
          
          responseData = {
            ...responseData,
            screen: screenName,
            data: {
              ...flowData.data,
              status: 'completed',
              confirmation_id: crypto.randomBytes(8).toString('hex'),
              processed_at: timestamp
            },
            flow_token: flowData.flow_token
          };
        }
        
        // CASO: Cambio de componente (on-select-action)
        else if (flowData.component_id) {
          console.log(`🎯 ACCIÓN: COMPONENT_CHANGE (${flowData.component_id})`);
          
          responseData = {
            ...responseData,
            screen: flowData.screen,
            data: {
              ...flowData.data,
              [flowData.component_id]: flowData.component_value,
              validated: true
            },
            flow_token: flowData.flow_token
          };
        }
        
        // CASO: Por defecto
        else {
          console.log('🎯 ACCIÓN: Desconocida, usando defaults');
          
          responseData = {
            ...responseData,
            screen: flowData.screen || 'RESPONSE',
            data: flowData.data || {},
            flow_token: flowData.flow_token
          };
        }
        
        console.log('\n📤 RESPUESTA PREPARADA:');
        console.log(JSON.stringify(responseData, null, 2));
        
        // 5️⃣ Encriptar respuesta
        const encryptedResponse = encryptFlowResponse(responseData, aesKey, iv);
        
        console.log('\n✅ Enviando respuesta encriptada');
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
              error_message: "Error procesando solicitud",
              error_code: error.code || "500"
            },
            flow_token: body.flow_token || crypto.randomBytes(16).toString('hex')
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
    // CASO: ERROR NOTIFICATION REQUEST
    // ============================================
    } else if (body.error && body.flow_id) {
      console.log('⚠️ TIPO: ERROR NOTIFICATION REQUEST');
      console.log(`   Flow ID: ${body.flow_id}`);
      console.log(`   Flow Token: ${body.flow_token}`);
      console.log(`   Error: ${body.error.message || JSON.stringify(body.error)}`);
      res.status(200).end();
    
    // ============================================
    // CASO: HEALTH CHECK REQUEST
    // ============================================
    } else if (body.health_check) {
      console.log('🏥 TIPO: HEALTH CHECK REQUEST');
      res.status(200).json({
        status: 'healthy',
        timestamp: timestamp,
        version: '3.0'
      });
    
    // ============================================
    // MENSAJE NORMAL DE WHATSAPP
    // ============================================
    } else if (body.entry) {
      console.log('📨 TIPO: MENSAJE WHATSAPP NORMAL');
      console.log(JSON.stringify(body, null, 2));
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

// 📊 Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '3.0',
    encryption: privateKey ? 'configured' : 'not_configured',
    app_secret: appSecret ? 'configured' : 'not_configured'
  });
});

// 🏠 Página principal
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Meta Flow Webhook - Documentación</title>
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
                max-width: 1200px; 
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
            .status {
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
                font-weight: bold;
            }
            .status-success { background: #c6f6d5; color: #22543d; }
            .status-warning { background: #feebc8; color: #744210; }
            table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }
            th, td {
                border: 1px solid #e2e8f0;
                padding: 12px;
                text-align: left;
            }
            th {
                background: #f7fafc;
                font-weight: bold;
            }
            code {
                background: #edf2f7;
                padding: 2px 6px;
                border-radius: 4px;
                font-size: 14px;
                font-family: 'Courier New', monospace;
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
            <h1>🚀 Webhook Meta Flow v3.0</h1>
            
            <div class="status ${privateKey ? 'status-success' : 'status-warning'}">
                ${privateKey ? 
                    '✅ MODO PRODUCCIÓN - Encriptación RSA activa' : 
                    '⚠️ MODO DESARROLLO - Sin encriptación real'}
            </div>
            
            <h2>📋 Estructura de Request (Según documentación Meta)</h2>
            <pre>
{
  "version": "3.0",                    // Requerido, siempre 3.0
  "screen": "SCREEN_NAME",            // Requerido (excepto INIT/BACK)
  "action": "INIT|BACK|data_exchange", // Requerido
  "data": { ... },                    // Opcional (INIT/BACK no lo incluyen)
  "flow_token": "string",            // Requerido - Token de sesión
  "flow_token_signature": "string"   // Opcional - JWT con app secret
}</pre>
            
            <h2>📤 Estructura de Respuesta (Según documentación Meta)</h2>
            <pre>
{
  "version": "3.0",        // Requerido, siempre 3.0
  "screen": "string",      // Requerido - "SUCCESS" está reservado ❌
  "data": { ... },        // Opcional - No incluir en INIT/BACK
  "flow_token": "string"  // Requerido - Mismo que se recibió
}</pre>
            
            <h2>🎯 Casos de Flow Implementados</h2>
            <table>
                <tr>
                    <th>Caso</th>
                    <th>Acción</th>
                    <th>Screen</th>
                    <th>Data</th>
                    <th>Estado</th>
                </tr>
                <tr>
                    <td>📱 Abrir Flow</td>
                    <td><code>INIT</code></td>
                    <td>WELCOME</td>
                    <td>❌ No incluir</td>
                    <td style="color: #48bb78;">✅ Implementado</td>
                </tr>
                <tr>
                    <td>🔙 Botón Back</td>
                    <td><code>BACK</code></td>
                    <td>Anterior</td>
                    <td>❌ No incluir</td>
                    <td style="color: #48bb78;">✅ Implementado</td>
                </tr>
                <tr>
                    <td>📝 Enviar Form</td>
                    <td><code>data_exchange</code></td>
                    <td>CONFIRMATION</td>
                    <td>✅ Incluir</td>
                    <td style="color: #48bb78;">✅ Implementado</td>
                </tr>
                <tr>
                    <td>🔄 Cambio Componente</td>
                    <td><code>component_change</code></td>
                    <td>Misma</td>
                    <td>✅ Incluir</td>
                    <td style="color: #48bb78;">✅ Implementado</td>
                </tr>
            </table>
            
            <h2>🔧 Configuración Actual</h2>
            <pre>
VERSIÓN: 3.0
VERIFY_TOKEN: ${verifyToken ? '✅' : '❌'}
APP_SECRET: ${appSecret ? '✅ (JWT signatures)' : '❌ (sin verificación)'}
PRIVATE_KEY: ${privateKey ? '✅ PRODUCCIÓN' : '⚠️ DESARROLLO'}</pre>
            
            <h2>⚠️ Restricciones Importantes</h2>
            <ul>
                <li><strong style="color: #f56565;">"SUCCESS" es un nombre reservado</strong> - No puede usarse como nombre de screen</li>
                <li><strong>INIT y BACK</strong> - No deben incluir campo <code>data</code> en la respuesta</li>
                <li><strong>Version</strong> - Siempre debe ser "3.0"</li>
                <li><strong>flow_token</strong> - Siempre debe devolverse el mismo que se recibió</li>
            </ul>
            
            <p style="color: #718096; font-size: 14px; margin-top: 40px; text-align: center;">
                🚀 Servidor compatible con Meta Flow API v3.0 - ${new Date().toLocaleString()}
            </p>
        </div>
    </body>
    </html>
  `);
});

// Instalar jsonwebtoken si no está instalado
try {
  require.resolve('jsonwebtoken');
} catch (e) {
  console.log('⚠️ jsonwebtoken no está instalado. Ejecuta: npm install jsonwebtoken');
}

// Iniciar servidor
app.listen(port, '0.0.0.0', () => {
  console.log('\n' + '🚀'.repeat(40));
  console.log('   WEBHOOK META FLOW v3.0 - DOCUMENTACIÓN OFICIAL');
  console.log('🚀'.repeat(40) + '\n');
  
  console.log(`📌 Puerto: ${port}`);
  console.log(`📌 Versión: 3.0`);
  console.log(`📌 Verify Token: ${verifyToken ? '✅' : '❌'}`);
  console.log(`📌 App Secret: ${appSecret ? '✅ (JWT)' : '❌ (sin signatures)'}`);
  console.log(`📌 Private Key: ${privateKey ? '✅ PRODUCCIÓN' : '⚠️ DESARROLLO'}\n`);
  
  console.log('📋 CASOS IMPLEMENTADOS SEGÚN DOC:');
  console.log('   ✅ INIT - Usuario abre Flow (sin data)');
  console.log('   ✅ BACK - Botón atrás (sin data)');
  console.log('   ✅ data_exchange - Envío formulario (con data)');
  console.log('   ✅ component_change - Cambio de componente');
  console.log('   ✅ ERROR_NOTIFICATION - Notificación de error');
  console.log('   ✅ HEALTH_CHECK - Health check periódico\n');
  
  console.log('⚠️ RESTRICCIONES:');
  console.log('   • "SUCCESS" es nombre reservado - NO USAR');
  console.log('   • INIT/BACK - NO incluir campo data');
  console.log('   • version - SIEMPRE "3.0"\n');
  
  if (!appSecret) {
    console.log('⚠️  flow_token_signature: No se verificará (APP_SECRET no configurado)');
  }
  if (!privateKey) {
    console.log('⚠️  IMPORTANTE: Modo DESARROLLO - Sin encriptación real');
    console.log('   Configura PRIVATE_KEY para producción\n');
  }
});

module.exports = app;
