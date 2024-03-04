import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT } from "../config";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  // TODO implement the status route
  onionRouter.get("/status", (req, res) => {
    res.send('live');
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  //Generate a /getLastReceivedEncryptedMessage GET route that should respond with a JSON payload containing a result property containing the last received message in its encrypted form, this should be the value that is received by the node in the request. By default (before receiving anything), it needs to return null.
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    const result = req.query.message || null;
    res.send({ result: result });
  });

  //Generate a /getLastReceivedDecryptedMessage GET route that should respond with a JSON payload containing a result property containing the last received message in its encrypted form, this should be the value of the data that is forwarded to the next node / user.
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    const result = req.query.message || null;
    res.send({ result: result });
  });

  //Generate a /getLastMessageDestination GET route should respond with a JSON payload containing a result property containing the destination (port) of the last received message. The destination can be a node or user port.
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    const result = req.query.destination || null;
    res.send({ result: result });
  });

  return server;
}
