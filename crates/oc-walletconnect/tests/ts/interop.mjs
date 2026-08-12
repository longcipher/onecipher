// Official `@walletconnect/sign-client` interop driver (L4).
//
// Runs as a child process of `tests/ts_interop.rs`:
//   1. Creates a SignClient (dApp role).
//   2. Generates a pairing URI and prints "URI <wc:...>".
//   3. Waits for "APPROVE\n" on stdin, then:
//        - pairs with the URI,
//        - approves the session proposal,
//        - sends a `personal_sign` session request,
//        - prints "RESULT <json>" or "ERROR <msg>".
//
// The Rust test injects the URI into its wallet server and replies APPROVE
// once the pairing is registered.

import { SignClient } from "@walletconnect/sign-client";
import { readline } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";

const RELAY_URL = process.env.OC_TEST_RELAY || "wss://relay.walletconnect.com";
const PROJECT_ID = process.env.OC_WC_PROJECT_ID || "";

async function main() {
  const client = await SignClient.init({
    projectId: PROJECT_ID,
    relayUrl: RELAY_URL,
    metadata: {
      name: "OneCipher Interop Test",
      description: "Official sign-client interop driver",
      url: "https://localhost:3000",
      icons: [],
    },
  });

  // Generate a pairing URI.
  const { uri, approval } = await client.core.pairing.create({
    relay: { protocol: "irn" },
  });
  console.log(`URI ${uri}`);

  // Wait for the Rust side to inject the pairing and tell us to continue.
  const rl = readline({ input, output });
  await rl.question("");
  rl.close();

  // Pair with the URI (the wallet subscribes to this topic).
  await client.pair({ uri });
  console.log("PAIRED");

  // Approve the session proposal.
  const sessionProposal = await approval();
  const session = await client.approve({
    id: sessionProposal.id,
    namespaces: {
      eip155: {
        accounts: ["eip155:1:0x0123456789abcdef0123456789abcdef01234567"],
        methods: ["personal_sign", "eth_sendTransaction", "eth_requestAccounts"],
        events: ["accountsChanged", "chainChanged"],
      },
    },
  });
  console.log("SESSION_APPROVED");

  // Send a personal_sign request.
  try {
    const result = await client.request({
      topic: session.topic,
      chainId: "eip155:1",
      request: {
        method: "personal_sign",
        params: ["0xdeadbeef", "0x0123456789abcdef0123456789abcdef01234567"],
      },
    });
    console.log(`RESULT ${JSON.stringify(result)}`);
  } catch (e) {
    console.log(`ERROR ${e.message || String(e)}`);
  }
}

main().catch((e) => {
  console.log(`ERROR ${e.message || String(e)}`);
  process.exit(1);
});
