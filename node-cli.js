require('./drunkcrypt');

// shim rand with secure randomness
globalThis.rand = bits => {
    const buffer = require('crypto').randomBytes(Math.ceil(bits / 8));
    const str = [...buffer].map(b => b.toString(2).padStart(8, '0')).join``;
    return BigInt('0b' + str.slice(0, bits));
};

const [,, ...args] = process.argv;

({
    help,
    'generate-keys': generateKeys,
    encrypt: encryptCLI,
    decrypt: decryptCLI,
}[args[0]] || help)();

function generateKeys() {
    const { public, private } = getKeyPair();
    console.log(`public:\n${public.toString(36)}\nprivate:\n${private.toString(36)}`);
}

function encryptCLI() {
    const public = bigIntBase36(args[1])
    console.log(JSON.stringify(encrypt(args[2], public)));
}

function decryptCLI() {
    const private = bigIntBase36(args[1])
    console.log(decrypt(JSON.parse(args[2]), private));
}

function bigIntBase36(str) {
  let result = 0n;
  for (const char of str.toLowerCase()) {
    const digit = BigInt(parseInt(char, 36));
    result = result * 36n + digit;
  }
  return result;
}

function help() {
  console.log(`
Usage:
  node node-cli.js <command> [options]

Commands:
  generate-keys                               Generate a new key pair
  encrypt <public-key-path> <message>         Encrypt a message using a public key
  decrypt <private-key-path> <encrypted-data> Decrypt a message using a private key
  help                                        Show this help message

Examples:
  node node-cli.js generate-keys
  node node-cli.js encrypt "Hello world"
  node node-cli.js decrypt "encrypted-base64-string"
  `);
}
