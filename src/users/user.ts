import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT } from "../config";
import { getNodeRegistry } from "../registry/registry";
import {
  generateRsaKeyPair,
  createRandomSymmetricKey,
  rsaEncrypt,
  symEncrypt,
  exportPubKey,
  exportSymKey
} from "../crypto"; // Import des fonctions nécessaires pour la cryptographie

let lastReceivedMessage: string | null=null;
let lastSentMessage: string | null=null;

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export type Body = {
  message: string;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  // Vérifie que l'API fonctionne
  _user.get("/status", (req, res) => {
    res.send("live");
  });

  // Récupérer le dernier message reçu
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  // Récupérer le dernier message envoyé
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  // ROUTE POUR ENVOYER UN MESSAGE À TRAVERS LE RÉSEAU
  _user.post("/sendMessage", async (req, res) => {
    const { message, destinationUserId } = req.body;

    // Sélectionner 3 nœuds distincts depuis le registre
    const nodes = getNodeRegistry();
    if (nodes.length < 3) {
      return res.status(500).json({ error: "Not enough nodes in the registry." });
    }

    // Sélectionner 3 nœuds distincts aléatoirement
    const shuffledNodes = nodes.sort(() => 0.5 - Math.random()).slice(0, 3);

    console.log("Selected nodes:", shuffledNodes);

    // Application du chiffrement en 3 couches (de l'intérieur vers l'extérieur)
    let encryptedMessage = message;

    for (let i = 2; i >= 0; i--) {
      const node = shuffledNodes[i];
      const nodePort = (4000 + node.nodeId).toString().padStart(10, "0");

      // Générer une clé symétrique unique pour ce nœud
      const symKey = await createRandomSymmetricKey();

      // Chiffrer le message + destination avec la clé symétrique
      const encryptedPayload = await symEncrypt(symKey, nodePort + encryptedMessage);

      // Supposons que vous avez une clé symétrique (symKey) déjà générée
      const { publicKey, privateKey } = await generateRsaKeyPair(); // Générer la paire de clés RSA

// Exporter la clé publique en Base64
      const publicKeyBase64 = await exportPubKey(publicKey);
      // Convertir la clé symétrique (symKey) en Base64 pour qu'elle soit utilisée dans le chiffrement RSA
      const symKeyBase64 = await exportSymKey(symKey);

// Maintenant, vous pouvez appeler rsaEncrypt avec la clé publique en Base64
      const encryptedSymKey = await rsaEncrypt(symKeyBase64, publicKeyBase64);

      // Construire le message chiffré (clé symétrique + message)
      encryptedMessage = encryptedSymKey + encryptedPayload;
    }

    // Envoyer le message chiffré au premier nœud
    const entryNode = shuffledNodes[0];
    await fetch(`http://localhost:${4000 + entryNode.nodeId}/message`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: encryptedMessage }),
    });

    lastSentMessage = message;
    return res.status(200).json({ success: true, message: "Message sent successfully" });
  });

  // ROUTE POUR RECEVOIR UN MESSAGE
  _user.post("/message", (req, res) => {
    lastReceivedMessage = req.body.message;
    res.json({ result: lastReceivedMessage });
  });

  // Démarrer le serveur pour l'utilisateur
  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(`User ${userId} is listening on port ${BASE_USER_PORT + userId}`);
  });

  return server;
}

