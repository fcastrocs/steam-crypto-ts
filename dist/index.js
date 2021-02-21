"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const g_PubkeySystem = fs_1.default.readFileSync(path_1.default.join(__dirname, "../system.pem"));
var SteamCrypto;
(function (SteamCrypto) {
    function verifySignature(data, signature, algorithm) {
        let verify = crypto_1.default.createVerify(algorithm || "RSA-SHA1");
        verify.update(data);
        verify.end();
        return verify.verify(g_PubkeySystem, signature);
    }
    SteamCrypto.verifySignature = verifySignature;
    ;
    /**
 * Generate a 32-byte symmetric session key and encrypt it with Steam's public "System" key.
 * @param nonce - If provided, will be appended to the session key when encrypting
 */
    function generateSessionKey(nonce) {
        let sessionKey = crypto_1.default.randomBytes(32);
        let cryptedSessionKey = crypto_1.default.publicEncrypt(g_PubkeySystem, Buffer.concat([sessionKey, nonce || Buffer.alloc(0)]));
        return {
            plain: sessionKey,
            encrypted: cryptedSessionKey
        };
    }
    SteamCrypto.generateSessionKey = generateSessionKey;
    ;
    /**
     * AES-encrypt some data with a symmetric key.
     * If iv is not provided, one will be generated randomly
     */
    function symmetricEncrypt(input, key, iv) {
        iv = iv || crypto_1.default.randomBytes(16);
        var aesIv = crypto_1.default.createCipheriv('aes-256-ecb', key, '');
        aesIv.setAutoPadding(false);
        aesIv.end(iv);
        var aesData = crypto_1.default.createCipheriv('aes-256-cbc', key, iv);
        aesData.end(input);
        return Buffer.concat([aesIv.read(), aesData.read()]);
    }
    SteamCrypto.symmetricEncrypt = symmetricEncrypt;
    ;
    /**
     * AES-encrypt some data with a symmetric key, and add an HMAC.
     * @param {Buffer} input
     * @param {Buffer} key
     */
    function symmetricEncryptWithHmacIv(input, key) {
        // IV is HMAC-SHA1(Random(3) + Plaintext) + Random(3). (Same random values for both)
        var random = crypto_1.default.randomBytes(3);
        var hmac = crypto_1.default.createHmac("sha1", key.slice(0, 16)); // we only want the first 16 bytes of the key for the hmac
        hmac.update(random);
        hmac.update(input);
        // the resulting IV must be 16 bytes long, so truncate the hmac to make room for the random
        return symmetricEncrypt(input, key, Buffer.concat([hmac.digest().slice(0, 16 - random.length), random]));
    }
    SteamCrypto.symmetricEncryptWithHmacIv = symmetricEncryptWithHmacIv;
    ;
    /**
     * AES-decrypt some data with a symmetric key, and check an HMAC.
     */
    function symmetricDecrypt(input, key) {
        var aesIv = crypto_1.default.createDecipheriv('aes-256-ecb', key, '');
        aesIv.setAutoPadding(false);
        aesIv.end(input.slice(0, 16));
        var iv = aesIv.read();
        var aesData = crypto_1.default.createDecipheriv('aes-256-cbc', key, iv);
        aesData.end(input.slice(16));
        var plaintext = aesData.read();
        // The last 3 bytes of the IV are a random value, and the remainder are a partial HMAC
        var remotePartialHmac = iv.slice(0, iv.length - 3);
        var random = iv.slice(iv.length - 3, iv.length);
        var hmac = crypto_1.default.createHmac("sha1", key.slice(0, 16));
        hmac.update(random);
        hmac.update(plaintext);
        if (!remotePartialHmac.equals(hmac.digest().slice(0, remotePartialHmac.length))) {
            throw new Error("Received invalid HMAC from remote host.");
        }
        return plaintext;
    }
    SteamCrypto.symmetricDecrypt = symmetricDecrypt;
    ;
    /**
     * Decrypt something that was encrypted with AES/ECB/PKCS7
     */
    function symmetricDecryptECB(input, key) {
        let decipher = crypto_1.default.createDecipheriv('aes-256-ecb', key, '');
        decipher.end(input);
        return decipher.read();
    }
    SteamCrypto.symmetricDecryptECB = symmetricDecryptECB;
    ;
    /**
     * Hash input with sha1 algorithm
     */
    function sha1(input) {
        let buffer;
        // convert to buffer
        if (!Buffer.isBuffer(input)) {
            buffer = Buffer.from(input, 'utf8');
        }
        else {
            buffer = input;
        }
        let hash = crypto_1.default.createHash("sha1");
        hash.update(buffer);
        return hash.digest("hex");
    }
    SteamCrypto.sha1 = sha1;
})(SteamCrypto || (SteamCrypto = {}));
exports.default = SteamCrypto;
