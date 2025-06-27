# drunkcrypt

an attempt to see how reasonably secure E2E cryptography can be implemented from scratch, as simple and concise as possible. the result being quite a loose, unidiomatic, and terse script

## usage

raw API

```javascript
const { public, private } = getKeyPair();

const message = 'unicorn poop 🦄 💩';

const blob = encrypt(message, public);

console.log(`encrypted blob: ${JSON.stringify(blob)}`)

const dec = decrypt(blob, private);

console.log(`decrypted text: ${dec}`);
```

node CLI

```bash
node node-cli.js generate-keys
node node-cli.js encrypt "your-public-key" "your-message"
node node-cli.js decrypt "your-private-key" "encrypted-message"
```

example

```bash
➤ node node-cli.js generate-keys | awk '/^public:/ {getline; print > "public.txt"} /^private:/ {getline; print > "private.txt"}'
➤ node node-cli.js encrypt "$(public.txt)" "$(cat message.txt)" > encrypted.txt
➤ cat encrypted.txt
{"text":[240,241,97,127,97,85,151,218,57,251,41,246,131,209,140,92,76,15,232,103,231,49,103,19,20,148],"nonce":[15,16,245,131,98,123,9,45,237,178,203,26],"key":"51264744630139075979114151416676649985668427488089011879616605317115659221608496558526215105808998817649952442766294200555911690103718168616645460909179805921485740297143961637627942917138874095143470342737301722723777200567210619107017179769594778103732250495293486865898224582829579279198611999085106415677","pub":"82326675834711386302845051387062747839092182520208416700060391626625159324224076932021778740856945616541787883181903282013764379454774310943128990984922545047881276454545816463790630004926778395823329034642259518451160416695292937206789987389224479988604498028239428315042125348582073277806696244928735049913"}
➤ node node-cli.js decrypt "$(private.txt)" "$(cat encrypted.txt)"
this is the secret message
```

## implementation details

a hybrid encryption scheme is used with a public and private keypair

* encrypt the message with ChaCha20 and a new, randomly generated key
* use RSA and PKCS#1 v1.5 to encrypt this new key with your public key
* transport the encrypted message and encrypted key

to decrypt:

* decrypt the key with your private key
* decrypt the message with the decrypted key
