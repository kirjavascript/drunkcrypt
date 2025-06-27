keySize=512 // change this to 2048 if evading a nation-state
e=0x10001n // public exponent

// replace this with runtime-specific secure randomness
rand=bits=>BigInt('0b' + Array.from({ length: bits }, _ => [] + 0|Math.random() * 2).join``)

randRange = (min, max) => {
  range = max - min;
  do { r = rand(range.toString(2).length); } while (r > range);
  return min + r;
}

chunk=([...b],n)=>0 in b?[b,...chunk(b.splice(n),n)]:b

// miller-rabin
isPrime = (n, k = 5) => {
  if (n < 2n || n % 2n === 0n) return n === 2n;
  let s = 0n, d = n - 1n;
  while (d % 2n === 0n) d /= 2n, s++;
  while (k--) {
    let x = modPow(2n + randRange(2n, n - 2n), d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let r = 1n; r < s && x !== n - 1n; r++) x = modPow(x, 2n, n);
    if (x !== n - 1n) return false;
  }
  return true;
}

// (base^exp) % mod
modPow = (base, exp, mod) => {
  let r = 1n;
  for (base %= mod; exp > 0n; exp /= 2n) {
    if (exp % 2n) r = (r * base) % mod;
    base = (base * base) % mod;
  }
  return r;
}

randKey=_=>((rand(keySize-2) << 1n) | 1n) + (1n << 511n)
getPrime=_=>{while(!isPrime(n=randKey()));return n}

getKeyPair=_=> {
    p = q = getPrime()
    do { q = getPrime() } while(p === q)

    n = p * q
    phi = (p - 1n) * (q - 1n)
    d = modInv(e, phi)

    return { public: n, private: d };
}

// extended euclidean algorithm
modInv = (a, m) => {
  [m0, x0, x1] = [m, 0n, 1n];
  while (a > 1n) {
    q = a / m;
    [a, m] = [m, a % m];
    [x0, x1] = [x1 - q * x0, x0];
  }
  return x1 < 0n ? x1 + m0 : x1;
}

// RSA

encryptRSA=(text, pub)=>{
    byteToHex=_=>_.toString(16).padStart(2,0)
    bytes=[...text].map(c=>byteToHex(c.charCodeAt``));

    //PKCS padding
    keyBytes=keySize/8
    padSize=keyBytes-bytes.length-3
    if (padSize<8) throw new Error('message too long')
    padding=[...Array(padSize)].map(_=>byteToHex(Number((rand(8)+1n)%256n)))
    bytes.unshift('00', '02', ...padding, '00');

    num=BigInt('0x' + bytes.join``);
    return modPow(num, e, pub);
}

decryptRSA=(msg, pub, priv)=>{
    msg=modPow(msg, priv, pub);
    msg=msg.toString(16)
    msg=msg.length & 1 ? '0' + msg : msg

    bytes=chunk(msg, 2).map(b => parseInt(b.join``,16))
    // pad zeros
    bytes.unshift(...Array((keySize/8)-bytes.length).fill(0));
    if (bytes[0] !== 0 || bytes[1] !== 2) throw new Error('invalid padding')

    return String.fromCharCode(...bytes.slice(-~bytes.findIndex((d,i)=>!d&&i)))
}

// chacha20

rotl=(v, c)=>((v << c) | (v >>> (32 - c))) >>> 0

quarterRound=(s, a, b, c, d)=>{
  s[a] = (s[a] + s[b]) >>> 0; s[d] ^= s[a]; s[d] = rotl(s[d], 16);
  s[c] = (s[c] + s[d]) >>> 0; s[b] ^= s[c]; s[b] = rotl(s[b], 12);
  s[a] = (s[a] + s[b]) >>> 0; s[d] ^= s[a]; s[d] = rotl(s[d], 8);
  s[c] = (s[c] + s[d]) >>> 0; s[b] ^= s[c]; s[b] = rotl(s[b], 7);
}

asciiTo32=s=>[...s].reduce((a, _, i)=>(
    i%4 ? a : [...a,s.charCodeAt(i)|s.charCodeAt(i+1)<<8|s.charCodeAt(i+2)<<16|s.charCodeAt(i+3)<<24]
),[])

constants=asciiTo32('expand 32-byte k')

block=(key, counter, nonce)=>{
    state = [...constants, ...key, counter, ...nonce]
    copy = [...state]
    diagonalRounds = (a=Array(4).fill()).map((_,i)=>a.map((_,j)=>i+4*j));
    columnRounds = a.map((_,i)=>[i,(i+1)%4+4,(i+2)%4+8,(i+3)%4+12]);

    for (let i = 0; i < 10; i++) {
        diagonalRounds.forEach(args => quarterRound(copy, ...args));
        columnRounds.forEach(args => quarterRound(copy, ...args));
    }
    for (let i = 0; i < 16; i++) copy[i] = (copy[i] + state[i]) >>> 0;

    return copy.flatMap(value=>[value,(value>>>8),(value>>>16),(value>>24)].map(v=>v&0xff));
}

chacha20=(key, nonce, plaintext)=>{
    chunks = chunk([...plaintext], 64);
    counter = 0;

    return chunks.flatMap(c=>{
        _block = block(key, counter++, nonce)
        return [...c].map((d,i)=>d^_block[i])
    });
}

encrypt=(text,pub)=>{ // -> blob
    key = Array.from({ length: 32 }, _=>Number(rand(8)))
    nonce = Array.from({ length: 12 }, _=>Number(rand(8)))
    text = chacha20(key, nonce, new TextEncoder().encode(text));
    key = encryptRSA(String.fromCharCode(...key), pub);
    return { text, nonce, key: String(key), pub: String(pub) };
}

decrypt=(blob,priv)=>{
    key = [...decryptRSA(BigInt(blob.key), BigInt(blob.pub), priv)]
    decrypted = chacha20(key.map(d=>d.charCodeAt``), blob.nonce, blob.text);
    return new TextDecoder().decode(Uint8Array.from(decrypted));
}
