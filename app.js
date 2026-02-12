const express = require('express');
const crypto = require('crypto');

const app = express();

app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;
let privateKey = process.env.PRIVATE_KEY;

if (privateKey) {
  privateKey = privateKey.replace(/\\n/g, '\n');
}

// ✅ VERIFICACIÓN - IGUAL QUE ANTES
app.get(['/', '/webhook'], (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;
  
  if (mode === 'subscribe' && token === verifyToken) {
    return res.status(200).send(String(challenge));
  }
  res.status(403).end();
});

// 🔓 FUNCIÓN DESENCRIPTAR - VERSIÓN ESTABLE
function decryptFlowData(encryptedFlowData, encryptedAesKey, initialVector) {
  const aesKey = crypto.privateDecrypt(
    {
      key: privateKey,
      padding: 4, // RSA_PKCS1_OAEP_PADDING
      oaepHash: 'sha256',
    },
    Buffer.from(encryptedAesKey, 'base64')
  );
  
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
}

// 🔐 FUNCIÓN ENCRIPTAR - VERSIÓN ESTABLE
function encryptFlowResponse(responseData, aesKey, iv) {
  const cipher = crypto.createCipheriv('aes-128-cbc', aesKey, iv);
  cipher.setAutoPadding(true);
  
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(responseData), 'utf8'),
    cipher.final()
  ]);
  
  return encrypted.toString('base64');
}

// 📥 POST WEBHOOK - VERSIÓN ESTABLE
app.post(['/', '/webhook'], (req, res) => {
  try {
    const body = req.body;
    
    if (body.encrypted_flow_data && body.encrypted_aes_key && body.initial_vector) {
      
      if (!privateKey) {
        return res.status(200).end();
      }
      
      const { aesKey, iv, data: flowData } = decryptFlowData(
        body.encrypted_flow_data,
        body.encrypted_aes_key,
        body.initial_vector
      );
      
      // ⚠️ LO MÁS IMPORTANTE - SIEMPRE INCLUIR flow_token
      const responseData = {
        version: '3.0',
        screen: flowData.screen || 'RESPONSE',
        flow_token: flowData.flow_token // ✅ OBLIGATORIO
      };
      
      // Solo agregar data si NO es INIT/BACK
      if (flowData.action !== 'INIT' && flowData.action !== 'BACK') {
        responseData.data = {
          ...flowData.data,
          status: 'success',
          timestamp: new Date().toISOString()
        };
      }
      
      const encryptedResponse = encryptFlowResponse(responseData, aesKey, iv);
      
      res.set('Content-Type', 'text/plain');
      return res.status(200).send(encryptedResponse);
      
    } else {
      // Mensaje normal de WhatsApp
      res.status(200).end();
    }
    
  } catch (error) {
    console.error('Error:', error);
    res.status(200).end();
  }
});

app.listen(port, '0.0.0.0', () => {
  console.log(`✅ Webhook iniciado en puerto ${port}`);
});
