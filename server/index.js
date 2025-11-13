const express = require("express");
const app = express();
const cors = require("cors");
const port = 3042;
const secp = require("ethereum-cryptography/secp256k1");
const { hexToBytes, toHex, utf8ToBytes } = require("ethereum-cryptography/utils");
const {sha256} = require ("ethereum-cryptography/sha256.js");
app.use(cors());
app.use(express.json());

const balances = {
  "0x1": 100,
  "0x2": 50,
  "0x3": 75,
  "0x0705ae80b1d70cbebdee":100
};


function verify (req) {
  const { payload, signature, recoveryBit } = req.body;
  console.log("Decoded payload", payload);
  const payloadBytes = utf8ToBytes(JSON.stringify(payload));
  const msgHash = sha256(payloadBytes);
  const pubKey = secp.recoverPublicKey(msgHash, hexToBytes(signature), recoveryBit);
  const address = "0x" + toHex(pubKey).slice(-20);
  const {sender} = payload;
  if (!secp.verify(signature,msgHash,pubKey))
  { 
    console.log ("Authentication failed");
    return false;
  }
  if (sender !== address)
  {
    console.log ("Sender_Address does pass to Public Key")
    return false;
  }
  if (! (address in balances))
  {
     console.log (`Address  ${address} not found`);
     return false;
  }
  return true;
}

app.get("/balance/:address", (req, res) => {
  const { address } = req.params;
  const balance = balances[address] || 0;
  res.send({ balance });
});

app.post("/send", (req, res) => {
  const { payload, signature, recoveryBit } = req.body;
  if (!verify(req))
  {
    console.log ("Authentication Failed");
    return;
  }

  const { sender, amount, recipient } = req.body.payload;

  setInitialBalance(sender);
  setInitialBalance(recipient);

  if (balances[sender] < amount) {
    res.status(400).send({ message: "Not enough funds!" });
  } else {
    balances[sender] -= amount;
    balances[recipient] += amount;
    res.send({ balance: balances[sender] });
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}!`);
});

function setInitialBalance(address) {
  if (!balances[address]) {
    balances[address] = 0;
  }
}
