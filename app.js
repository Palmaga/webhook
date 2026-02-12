import express from "express";
import crypto from "crypto";

const PORT = 3000;
const app = express();
app.use(express.json());

const PRIVATE_KEY = process.env.PRIVATE_KEY as string;
/* 
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIOSMqpgOTAKgCAggA
MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECGXonuaPlXAwBIIEyB3NpmZPFaE1
/YXaXQe11cuvMX47lAVvP7vU/w2k1eNpVjWBfcIS0cLbG+7V1U16GKMt4+fDETTY
KgJfaLKS6ARspvX96+g/shcqT0UOeFn/vBFpgCIWToOlGpLESBNXCquOqG0zmipa
cWJF1ST18Y2xx976EAY8J83o4Q1XQZlrknirbrt0b87SoCoweEN0uwxWhy1KGyIB
qCLDwzHBJrtT8GBBmUnHpJfB0sxkrvUxizEZKufmT56WVyAwW09LYSf7p95qBrEZ
relzcx1jn7alV9eYxn2kkpDTbZNPcNWxvvGoulEEkIK4WE9pwxAbe7Od+TpzId7a
/CTRtT1sKCsHxJSZzrH3Lff1iQqVxyuI0yikwGwsrZgXlJXYnW+ZjfZ2v3ZbdRl8
+NeOm7FqWn0IgnLUd+MMk7f64b5ZfibKJ9skD7CYWjHhRIsLQhrv120P9AXfOUpL
MvdpRLw3JEnEqxHZGOvzhqkUBHIoMLs3cTzzPEJh6xvibexR6nMH5UKKTCae7mQp
Xc1Wt+VYtd6I+83QHdNjT6gWJMyLCnFLjr/x4w0yFv2Q7mTWIvsUp2g6StRiZYFL
nb9iERD1GpJMuSvo97VTiBBjWci/IbHhKNkoXc0/yQFB/SNHO4LiCxGxHV8xgapk
xPbCmpNgms+GU+o6vouu7Rh4ra6r7IREw+hNafRha/0VVKUSixCZt8nRr2Nl9J0p
2VZdW94gJi6g84d1hHnzkUwv1xxvjT6BODj0ZELozyh+xGDbpjSgK8iZD+SOVrkI
yiTKKNHVG43YGH9Blq/n5JH2RlNIZalxI9w7DheZ7ueJY1MB4rX/T4GpdmXlo1Bo
MbEHO8Xw6hCqnVj0/0a+7UkSuorcMryyk0UbnXHqOezjnxPDtFJEmUSnAN2FA5k6
HIggKA9SN/zFvB1CgH8ypYnXkWrKivExvHmcnHG3EVRpcgRj9BYlLbaxaskaDP9E
8mD3jFXY7iIKTW1XTb5XU78eTcsb4mP3usU87/SV7xO5CHiU2fi4MemBn0at+3rM
/HWBcFmmxhheVB86xwlhCtYIBXJClp9NKZ25XKTpQShEXyi4iVaoCIuzvc9YwPBv
HCWZLZN7vs0d47BRY0rrUJ2DHGHecXzyvXDi5B2ij/V5Jd0cQkYV9bK+ShGD1NUN
LPv1yHdIUh2+dg9KfZNupFkrPibjPknquvUTfQcS0YwDWjYuyBwJVONrqRPabIqN
erzT9jX7hGjP4PM7aCfJhXRQxythn5H+lDpsP0Xz164X4J+w3kOfhnCdRHCfICkm
eGYpsJ+eE2r0kBhkK9loOp7sEz86EcSM5hnxpUTPKCWMplu4u//hLDL+iaU+PQ7q
Gv1tcWoOy4rCP8JFgIMEQbu90DUQTbpwSrvKhqFnMo/QNaoKN1YTzQ9TjCDKLDjm
/JfpZ8jUDkf3ISuR+AP5iKCCErfwA+jF0TW4Jl9VdPqVwMM0tfzTezzq4c28LdZ/
2ieq0gDLmYNYS+aV+UBBFNrViNLS+SzRSCvqDDc8cfctC4Id+SkD3igZqC3kRxGs
Bw8Ks7GjBY4vHtyLkco6SVJfB0hGekfeNaGX962sMroS9OVl7AAfMr0nqe7e5oZE
dxM8BPgvtJJBLRqm7u6aQA==
-----END ENCRYPTED PRIVATE KEY-----
*/

app.post("/data", async ({ body }, res) => {
  const { decryptedBody, aesKeyBuffer, initialVectorBuffer } = decryptRequest(
    body,
    PRIVATE_KEY,
  );

  const { screen, data, version, action } = decryptedBody;
  // Return the next screen & data to the client
  const screenData = {
    screen: "SCREEN_NAME",
    data: {
      some_key: "some_value",
    },
  };

  // Return the response as plaintext
  res.send(encryptResponse(screenData, aesKeyBuffer, initialVectorBuffer));
});

const decryptRequest = (body: any, privatePem: string) => {
  const { encrypted_aes_key, encrypted_flow_data, initial_vector } = body;

  // Decrypt the AES key created by the client
  const decryptedAesKey = crypto.privateDecrypt(
    {
      key: crypto.createPrivateKey(privatePem),
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    Buffer.from(encrypted_aes_key, "base64"),
  );

  // Decrypt the Flow data
  const flowDataBuffer = Buffer.from(encrypted_flow_data, "base64");
  const initialVectorBuffer = Buffer.from(initial_vector, "base64");

  const TAG_LENGTH = 16;
  const encrypted_flow_data_body = flowDataBuffer.subarray(0, -TAG_LENGTH);
  const encrypted_flow_data_tag = flowDataBuffer.subarray(-TAG_LENGTH);

  const decipher = crypto.createDecipheriv(
    "aes-128-gcm",
    decryptedAesKey,
    initialVectorBuffer,
  );
  decipher.setAuthTag(encrypted_flow_data_tag);

  const decryptedJSONString = Buffer.concat([
    decipher.update(encrypted_flow_data_body),
    decipher.final(),
  ]).toString("utf-8");

  return {
    decryptedBody: JSON.parse(decryptedJSONString),
    aesKeyBuffer: decryptedAesKey,
    initialVectorBuffer,
  };
};

const encryptResponse = (
  response: any,
  aesKeyBuffer: Buffer,
  initialVectorBuffer: Buffer,
) => {
  // Flip the initialization vector
  const flipped_iv = [];
  for (const pair of initialVectorBuffer.entries()) {
    flipped_iv.push(~pair[1]);
  }
  // Encrypt the response data
  const cipher = crypto.createCipheriv(
    "aes-128-gcm",
    aesKeyBuffer,
    Buffer.from(flipped_iv),
  );
  return Buffer.concat([
    cipher.update(JSON.stringify(response), "utf-8"),
    cipher.final(),
    cipher.getAuthTag(),
  ]).toString("base64");
};

app.listen(PORT, () => {
  console.log(`App is listening on port ${PORT}!`);
});
