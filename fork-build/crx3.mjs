// Fork build: pack a zip into a signed CRX3 file (the format Chrome and Edge install from an update_url).
// No dependencies; uses Node's built-in crypto.
//
//   node crx3.mjs keygen <key.pem>            create a 2048-bit RSA signing key (PKCS#8 PEM)
//   node crx3.mjs id <key.pem>                print the extension ID this key gives
//   node crx3.mjs pack <in.zip> <key.pem> <out.crx>   sign and write the CRX3; prints the extension ID
//
// CRX3 layout: "Cr24" | uint32le 3 | uint32le headerSize | CrxFileHeader (protobuf) | zip
//   CrxFileHeader { repeated AsymmetricKeyProof sha256_with_rsa = 2; bytes signed_header_data = 10000; }
//   AsymmetricKeyProof { bytes public_key = 1; bytes signature = 2; }
//   SignedData { bytes crx_id = 1; }   crx_id = first 16 bytes of SHA-256(public key DER)
//   signature = RSA-SHA256("CRX3 SignedData\0" | uint32le len(signed_header_data) | signed_header_data | zip)
import { createHash, createPrivateKey, createPublicKey, createSign, generateKeyPairSync } from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";

function varint(n) {
  const out = [];
  while (n > 0x7f) { out.push((n & 0x7f) | 0x80); n >>>= 7; }
  out.push(n);
  return Buffer.from(out);
}
// Length-delimited protobuf field (wire type 2).
const field = (num, bytes) => Buffer.concat([varint((num << 3) | 2), varint(bytes.length), bytes]);
const u32le = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };

function keyInfo(pemPath) {
  const priv = createPrivateKey(readFileSync(pemPath));
  const pubDer = createPublicKey(priv).export({ type: "spki", format: "der" });
  const crxId = createHash("sha256").update(pubDer).digest().subarray(0, 16);
  // Extension IDs are the crx_id in hex, written with the letters a-p instead of 0-f.
  const extId = [...crxId.toString("hex")].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
  return { priv, pubDer, crxId, extId };
}

const [cmd, a, b, c] = process.argv.slice(2);
if (cmd === "keygen") {
  if (!a) throw new Error("usage: keygen <key.pem>");
  if (existsSync(a)) throw new Error(`${a} already exists; refusing to overwrite a signing key`);
  const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  writeFileSync(a, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
  console.log(keyInfo(a).extId);
} else if (cmd === "id") {
  console.log(keyInfo(a).extId);
} else if (cmd === "pack") {
  if (!a || !b || !c) throw new Error("usage: pack <in.zip> <key.pem> <out.crx>");
  const zip = readFileSync(a);
  const { priv, pubDer, crxId, extId } = keyInfo(b);
  const signedHeaderData = field(1, crxId);
  const signer = createSign("sha256");
  signer.update(Buffer.from("CRX3 SignedData\x00", "binary"));
  signer.update(u32le(signedHeaderData.length));
  signer.update(signedHeaderData);
  signer.update(zip);
  const signature = signer.sign(priv);
  const proof = Buffer.concat([field(1, pubDer), field(2, signature)]);
  const header = Buffer.concat([field(2, proof), field(10000, signedHeaderData)]);
  writeFileSync(c, Buffer.concat([Buffer.from("Cr24"), u32le(3), u32le(header.length), header, zip]));
  console.log(extId);
} else {
  console.error("usage: node crx3.mjs keygen|id|pack ...");
  process.exit(2);
}
