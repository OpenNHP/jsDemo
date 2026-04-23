import { buildNHPPacket, parseNHPPacket, NHP_PACKET_TYPES } from "./dist/index.js"

const agentPrivKey  = "QL2U9Ag18Fqdc1Bpw4wx/sNJbFqq36rfhtkPm2WId1c=";
const agentPubKey   = "Z0QA6bPlRpq8xWsVFe8NGR43bjGHjK0mX7CT1daudAA=";
const serverPrivKey = "oLqkmcl6wVqUaOOrGo4xvpaUkuCThgM37DUZKGExFVE=";
const serverPubKey  = "E3o8gUUxI5dUAUiEOi6SvgV9bWKmjpWWQaOO6GChO2A=";

console.group("=== CURVE25519 full round-trip ===");

// Step 1: Agent → Server (KNK)
console.group("Step 1: Agent builds KNK");
const knockPayload = JSON.stringify({
  usrId: "user@example.com",
  devId: "device-001",
  aspId: "demo",
  resId: "resource-1"
});
const knkPacket = await buildNHPPacket(
  NHP_PACKET_TYPES.KNK,
  agentPrivKey, agentPubKey,
  serverPubKey,
  knockPayload, true, "curve25519"
);
console.log("KNK packet:", knkPacket.length, "bytes");
console.groupEnd();

// Step 2: Server → Agent (ACK) — server replies with access grant
console.group("Step 2: Server builds ACK");
const ackPayload = JSON.stringify({
  errCode: "",
  resHost: { "demo": "192.168.1.100:8080" },
  opnTime: 300,
  agentAddr: "1.2.3.4:12345"
});
const ackPacket = await buildNHPPacket(
  NHP_PACKET_TYPES.ACK,
  serverPrivKey, serverPubKey,
  agentPubKey,
  ackPayload, true, "curve25519"
);
console.log("ACK packet:", ackPacket.length, "bytes");
console.groupEnd();

// Step 3: Agent parses ACK
console.group("Step 3: Agent parses ACK");
try {
  const parsed = await parseNHPPacket(
    ackPacket,
    agentPrivKey, agentPubKey,
    serverPubKey
  );
  console.log("Packet type:", parsed.type, "(expected 2 = ACK)");
  const msg = JSON.parse(parsed.message);
  console.log("Access granted!");
  console.log("  Resource host:", msg.resHost);
  console.log("  Open time:", msg.opnTime, "seconds");
  console.log("  Agent address:", msg.agentAddr);
} catch (err) {
  console.error("Parse failed:", err.message);
}
console.groupEnd();

console.groupEnd();
