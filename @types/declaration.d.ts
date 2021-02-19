/// <reference types="node" />
import Crypto from "crypto";
/**
 * Verifies a signature using the Steam "System" public key.
 * @param {Buffer} data
 * @param {Buffer} signature
 * @param {string} algorithm
 */
export declare function verifySignature(data: Buffer, signature: Buffer, algorithm: string): boolean;
/**
 * Generate a 32-byte symmetric session key and encrypt it with Steam's public "System" key.
 * @param nonce - If provided, will be appended to the session key when encrypting
 */
export declare function generateSessionKey(nonce?: Buffer): {
    plain: Buffer;
    encrypted: Buffer;
};
/**
 * AES-encrypt some data with a symmetric key.
 * If iv is not provided, one will be generated randomly
 */
export declare function symmetricEncrypt(input: Crypto.BinaryLike, key: Buffer, iv?: Buffer): Buffer;
/**
 * AES-encrypt some data with a symmetric key, and add an HMAC.
 * @param {Buffer} input
 * @param {Buffer} key
 */
export declare function symmetricEncryptWithHmacIv(input: Crypto.BinaryLike, key: Buffer): Buffer;
/**
 * AES-decrypt some data with a symmetric key, and check an HMAC.
 */
export declare function symmetricDecrypt(input: Buffer, key: Buffer): any;
/**
 * Decrypt something that was encrypted with AES/ECB/PKCS7
 */
export declare function symmetricDecryptECB(input: Buffer, key: Buffer): any;
