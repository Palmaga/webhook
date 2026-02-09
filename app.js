// Route for GET requests (Health check / Verification)
app.get('/', (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

  if (mode === 'subscribe' && token === verifyToken) {
    console.log('WEBHOOK VERIFIED');
    // Convertimos el challenge a Base64 y lo enviamos directamente
    const base64Challenge = Buffer.from(challenge).toString('base64');
    res.set('Content-Type', 'text/plain');
    res.status(200).send(base64Challenge);
  } else {
    res.status(403).end();
  }
});

// Route for POST requests (Data handling)
app.post('/', (req, res) => {
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  console.log(`\nWebhook received ${timestamp}\n`);
  console.log(JSON.stringify(req.body, null, 2));

  // La respuesta a un Flow debe ser un JSON cifrado o un Base64 válido
  const responseData = "SUCCESS"; 
  const base64Response = Buffer.from(responseData).toString('base64');
  
  res.set('Content-Type', 'text/plain');
  res.status(200).send(base64Response);
});
