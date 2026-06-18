import { assert, test } from "@hazae41/phobos";
import { ed25519 } from "../mod.ts";

test("signature", () => {
  const key = ed25519.SecretKey.random()
  const pub = key.publish()

  const msg = Uint8Array.fromHex("deadbeef")
  const sig = key.sign(msg)

  assert(pub.verify(msg, sig))
})