import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT } from "../config";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  // TODO implement the status route
  _user.get("/status", (req, res) => {
    res.send('live');
  });

  //Generate a /getLastReceivedMessage that should respond with a JSON payload containing a result property containing the last received message of the user.
  _user.get("/getLastReceivedMessage", (req, res) => {
    const result = req.query.message || null;
    res.send({ result: result });
  });

  //Generate a /getLastSentMessage GET route that should respond with a JSON payload containing a result property containing last sent message of the user.
  _user.get("/getLastSentMessage", (req, res) => {
    const result = req.query.message || null;
    res.send({ result: result });
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}
