import bodyParser from "body-parser";
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

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  // TODO implement the status route
  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  // You should create an HTTP POST route called /registerNode which allows for nodes to register themselves on the registry.
  _registry.post("/registerNode", (req: Request<{}, {}, RegisterNodeBody>, res) => {
    const { nodeId, pubKey } = req.body;
    const nodes = _registry.locals.nodes as Node[];
    nodes.push({ nodeId, pubKey });
    res.send({ result: "ok" });
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
