import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

const registeredNodes: Node[] = [];

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json()); // Utilisation de express.json() pour le parsing des JSON

  // Route pour vérifier si le serveur est en ligne
  _registry.get("/status", (req: Request, res: Response) => {
    return res.send("live"); // Retour explicite
  });

  // Route pour récupérer tous les nœuds enregistrés
  _registry.get("/getNodeRegistry", (req: Request, res: Response) => {
    return res.json({ nodes: registeredNodes }); // Retour explicite
  });

  // Route pour enregistrer un nouveau nœud
  _registry.post("/registerNode", (req: Request, res: Response) => {
    const { nodeId, pubKey }: RegisterNodeBody = req.body;

    // Validation des données reçues
    if (!nodeId || !pubKey) {
      return res.status(400).json({ message: "NodeId and pubKey are required" }); // Retour explicite pour erreur
    }

    const pubKeyRegex = /^[A-Za-z0-9+/=]+$/;
    if (!pubKeyRegex.test(pubKey)) {
      return res.status(400).json({ message: "Invalid public key format" });
    }

    // Vérification si la clé publique est déjà utilisée (unicité des clés publiques)
    const existingNodeByPubKey = registeredNodes.find(n => n.pubKey === pubKey);
    if (existingNodeByPubKey) {
      return res.status(400).json({ message: "Duplicate public key, node not registered" });
    }

    // Vérification si le nœud est déjà enregistré
    const existingNodeById = registeredNodes.find(n => n.nodeId === nodeId);
    if (existingNodeById) {
      return res.status(400).json({ message: "Node already registered" });
    }

    // Ajouter le nouveau nœud au registre
    const newNode: Node = { nodeId, pubKey };
    registeredNodes.push(newNode);

    // Réponse de succès
    return res.status(201).json({ message: "Node registered successfully", node: newNode }); // Retour explicite
  });

  // Route pour récupérer la clé privée d'un nœud (à ajouter plus tard si nécessaire)
  _registry.get("/getPrivateKey", (req: Request, res: Response) => {
    return res.json({ message: "This route would normally return the private key of a node (for testing purposes)" }); // Retour explicite
  });

  // Lancer le serveur et retourner le serveur
  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`Registry is listening on port ${REGISTRY_PORT}`);
  });

  // Ajout du return explicite pour garantir que la fonction renvoie un résultat
  return server;
}

// Fonction pour obtenir le registre des nœuds
export function getNodeRegistry(): Node[] {
  return registeredNodes;
}