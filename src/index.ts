
import Crypto from "crypto";
import fs from "fs";
const g_PubkeySystem = fs.readFileSync(__dirname + '../system.pem');

/**
 * Verifies a signature using the Steam "System" public key.
 * @param {Buffer} data
 * @param {Buffer} signature
 * @param {string} algorithm
 */
export function verifySignature(data: Buffer, signature: Buffer, algorithm: string) {
    let verify = Crypto.createVerify(algorithm || "RSA-SHA1");
    verify.update(data);
    verify.end();
    return verify.verify(g_PubkeySystem, signature);
};

/**
 * Generate a 32-byte symmetric session key and encrypt it with Steam's public "System" key.
 * @param nonce - If provided, will be appended to the session key when encrypting
 */
export function generateSessionKey(nonce: Buffer) {
    let sessionKey = Crypto.randomBytes(32);
    let cryptedSessionKey = Crypto.publicEncrypt(g_PubkeySystem, Buffer.concat([sessionKey, nonce || Buffer.alloc(0)]));
    return {
        plain: sessionKey,
        encrypted: cryptedSessionKey
    };
};

/**
 * AES-encrypt some data with a symmetric key.
 * If iv is not provided, one will be generated randomly
 */
export function symmetricEncrypt(input: Buffer, key: Buffer, iv?: Buffer): Buffer {
    iv = iv || Crypto.randomBytes(16);
    var aesIv = Crypto.createCipheriv('aes-256-ecb', key, '');
    aesIv.setAutoPadding(false);
    aesIv.end(iv);

    var aesData = Crypto.createCipheriv('aes-256-cbc', key, iv);
    aesData.end(input);

    return Buffer.concat([aesIv.read(), aesData.read()]);
};

/**
 * AES-encrypt some data with a symmetric key, and add an HMAC.
 * @param {Buffer} input
 * @param {Buffer} key
 */
export function symmetricEncryptWithHmacIv(input: Buffer, key: Buffer): Buffer {
    // IV is HMAC-SHA1(Random(3) + Plaintext) + Random(3). (Same random values for both)
    var random = Crypto.randomBytes(3);
    var hmac = Crypto.createHmac("sha1", key.slice(0, 16)); // we only want the first 16 bytes of the key for the hmac
    hmac.update(random);
    hmac.update(input);

    // the resulting IV must be 16 bytes long, so truncate the hmac to make room for the random
    return symmetricEncrypt(input, key, Buffer.concat([hmac.digest().slice(0, 16 - random.length), random]));
};

/**
 * AES-decrypt some data with a symmetric key, and check an HMAC.
 */
export function symmetricDecrypt(input: Buffer, key: Buffer) {
    var aesIv = Crypto.createDecipheriv('aes-256-ecb', key, '');
    aesIv.setAutoPadding(false);
    aesIv.end(input.slice(0, 16));
    var iv = aesIv.read();

    var aesData = Crypto.createDecipheriv('aes-256-cbc', key, iv);
    aesData.end(input.slice(16));
    var plaintext = aesData.read();

    // The last 3 bytes of the IV are a random value, and the remainder are a partial HMAC
    var remotePartialHmac = iv.slice(0, iv.length - 3);
    var random = iv.slice(iv.length - 3, iv.length);
    var hmac = Crypto.createHmac("sha1", key.slice(0, 16));
    hmac.update(random);
    hmac.update(plaintext);
    if (!remotePartialHmac.equals(hmac.digest().slice(0, remotePartialHmac.length))) {
        throw new Error("Received invalid HMAC from remote host.");
    }

    return plaintext;
};

/**
 * Decrypt something that was encrypted with AES/ECB/PKCS7
 */
export function symmetricDecryptECB(input: Buffer, key: Buffer) {
    let decipher = Crypto.createDecipheriv('aes-256-ecb', key, '');
    decipher.end(input);
    return decipher.read();
};
