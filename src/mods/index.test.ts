import { fromNoble } from "./ed25519/noble.js"

import * as ed25519c from "@noble/curves/ed25519"
import * as ed25519 from "@noble/ed25519"

fromNoble({ ed25519 })
fromNoble(ed25519c)