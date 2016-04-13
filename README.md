# node-steam-crypto

Node.js implementation of Steam crypto. All keys, data, and signatures are passed as Buffers.

Fork of, and compatible with, [steam-crypto](https://www.npmjs.com/package/steam-crypto).

## verifySignature(data, signature[, algorithm])

Verifies an RSA signature using the Steam system's public key. `algorithm` defaults to "RSA-SHA1". Returns `true` if the signature is valid, or `false` if not.

## generateSessionKey()

Generates a 32 byte random blob of data and encrypts it with RSA using the Steam system's public key. Returns an object with the following properties:
* `plain` - the generated session key
* `encrypted` - the encrypted session key

## symmetricEncrypt(input, sessionKey)

Encrypts `input` using `sessionKey` and returns the result.

## symmetricDecrypt(input, sessionKey)

Decrypts `input` using `sessionKey` and returns the result.
