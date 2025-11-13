import { useState } from "react";
import server from "./server";
import { sha256 } from "ethereum-cryptography/sha256.js";
import { hexToBytes, toHex, utf8ToBytes } from "ethereum-cryptography/utils";
import * as secp from "ethereum-cryptography/secp256k1";

function AuthenticatedTransfer({ privateKey, recipient, sendAmount }) {
  var normalizedKey = (privateKey || "").trim().replace(/^0x/i, "");
  if (!normalizedKey) {
    throw new Error("Private key is required to sign a transfer");
  }
  if (!recipient) {
    throw new Error("Recipient address is required");
  }

  const amount = Number(sendAmount);
  if (!Number.isFinite(amount) || amount <= 0) {
    throw new Error("Send amount must be a positive number");
  }
  if (!Number.isInteger(amount)) {
    throw new Error("Send amount must be an integer");
  }
  //normalizedKey = "d7dd5741a3c91c88a39ea74e8df44c0c6ac687d32e17ba37aed951055ff70ce0"
  const privateKeyBytes = hexToBytes(normalizedKey);
  const publicKey = secp.getPublicKey(privateKeyBytes);
  const sender = "0x" + toHex(publicKey).slice(-20);
  const payload = { sender, amount, recipient };
  const payloadBytes = utf8ToBytes(JSON.stringify(payload));
  const msgHashBytes = sha256(payloadBytes);
  const [signature, recoveryBit] = secp.signSync(msgHashBytes, privateKeyBytes, {
    recovered: true,
  });

  return {
    payload,
    signature: toHex(signature),
    recoveryBit,
  };
}

function Transfer({ address, setBalance }) {
  const [sendAmount, setSendAmount] = useState("");
  const [recipient, setRecipient] = useState("");
  const [pvtKey,setPvtKey] = useState("");
  const setValue = (setter) => (evt) => setter(evt.target.value);

  async function transfer(evt) {
    evt.preventDefault();

    try {
      const signedTransfer = AuthenticatedTransfer({
        privateKey: pvtKey,
        recipient,
        sendAmount,
      });

      const requestBody = {
        payload: signedTransfer.payload,
        signature: signedTransfer.signature,
        recoveryBit: signedTransfer.recoveryBit,
      };

      const {
        data: { balance },
      } = await server.post(`send`, requestBody);
      setBalance(balance);
    } catch (ex) {
      const message = ex?.response?.data?.message || ex.message;
      alert(message || "Transfer failed");
    }
  }

  return (
    <form className="container transfer" onSubmit={transfer}>
      <h1>Send Transaction</h1>
      <label>
        Your PvtKey
        <input
          placeholder="0x123132"
          value={pvtKey}
          onChange={setValue(setPvtKey)}
        ></input>
      </label>

      <label>
        Send Amount
        <input
          placeholder="1, 2, 3..."
          value={sendAmount}
          onChange={setValue(setSendAmount)}
        ></input>
      </label>

      <label>
        Recipient
        <input
          placeholder="Type an address, for example: 0x2"
          value={recipient}
          onChange={setValue(setRecipient)}
        ></input>
      </label>

      <input type="submit" className="button" value="Transfer" />
    </form>
  );
}

export default Transfer;
