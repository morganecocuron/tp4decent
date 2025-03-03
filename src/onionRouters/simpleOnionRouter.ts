import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT } from "../config";
import { rsaDecrypt, symDecrypt, importPrvKey, importSymKey } from "../crypto";

//Messages all set to 0
let lastReceivedEncryptedMessage: string | null = null;
let lastReceivedDecryptedMessage: string | null = null;
let lastMessageDestination: number | null = null;

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  // TODO implement the status route
  onionRouter.get("/status/", (req, res) => {
    res.send("live");
  });

  // Get last received encrypted message
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  // Get last received decrypted message
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  // Get last message destination
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  // Route to handle incoming messages
  onionRouter.post("/message", async (req, res) => {
    const { message } = req.body;
    let decryptedMessage = message;

    // Déchiffre la première couche avec la clé privée du nœud
    for (let i = 0; i < 1; i++) {  // Déchiffre une couche (une seule couche pour chaque nœud)
      const nodePrivateKey = await importPrvKey("privateKeyInBase64");//
      decryptedMessage = await rsaDecrypt(decryptedMessage, nodePrivateKey);

      // Le message contient maintenant la partie symétrique chiffrée à envoyer au prochain nœud
      const symKeyBase64 = decryptedMessage;  // Supposons que decryptedMessage contient la clé symétrique en Base64
      const symKey = await importSymKey(symKeyBase64);  // Importez la clé symétrique à partir du Base64
      decryptedMessage = await symDecrypt(decryptedMessage, symKeyBase64);  // Utilisez le CryptoKey pour déchiffrer le message
    }

    // Si c'est le dernier nœud, le message est envoyé à l'utilisateur cible
    if (nextNodeIsUser(decryptedMessage)) {
      const destinationUserId = getDestinationUserId(decryptedMessage);
      await sendMessageToUser(destinationUserId, decryptedMessage);
      lastMessageDestination = destinationUserId;
    } else {
      // Sinon, le message est envoyé au prochain nœud
      const nextNode = getNextNode(decryptedMessage);
      await forwardMessageToNextNode(nextNode, decryptedMessage);
    }

    lastReceivedEncryptedMessage = message;
    lastReceivedDecryptedMessage = decryptedMessage;
    res.json({ result: decryptedMessage });
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });
  return server;
}

// Récupère la clé privée du nœud
async function getNodePrivateKey(nodeId: number) {
  // Simuler la récupération de la clé privée
  return "privateKey" + nodeId; // Exemple, il faut récupérer la vraie clé privée
}

// Vérifie si le message est destiné à un utilisateur
function nextNodeIsUser(message: string) {
  return message.includes("user");
}

// Extrait l'ID de l'utilisateur de la destination
function getDestinationUserId(message: string) {
  return 1;  // À adapter selon la logique exacte
}

// Envoie le message à l'utilisateur
async function sendMessageToUser(userId: number, message: string) {
  // Code pour envoyer un message à l'utilisateur, probablement via HTTP
  console.log(`Sending message to user ${userId}:`, message);
}

// Récupère le prochain nœud à qui envoyer le message
function getNextNode(message: string) {
  return 2; // Juste un exemple
}

// Transfert le message au prochain nœud
async function forwardMessageToNextNode(nextNode: number, message: string) {
  const port = 4000 + nextNode;
  await fetch(`http://localhost:${port}/message`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  });
}