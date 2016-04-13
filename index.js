var Crypto = require('crypto');

var g_PubkeySystem = require('fs').readFileSync(__dirname + '/system.pem');

exports.verifySignature = function(data, signature, algorithm) {
	var verify = Crypto.createVerify(algorithm || "RSA-SHA1");
	verify.update(data);
	verify.end();
	return verify.verify(g_PubkeySystem, signature);
};

exports.generateSessionKey = function() {
	var sessionKey = Crypto.randomBytes(32);
	var cryptedSessionKey = Crypto.publicEncrypt(g_PubkeySystem, sessionKey);
	return {
		plain: sessionKey,
		encrypted: cryptedSessionKey
	};
};

exports.symmetricEncrypt = function(input, key) {
	var iv = Crypto.randomBytes(16);
	var aesIv = Crypto.createCipheriv('aes-256-ecb', key, '');
	aesIv.setAutoPadding(false);
	aesIv.end(iv);
	
	var aesData = Crypto.createCipheriv('aes-256-cbc', key, iv);
	aesData.end(input);
	
	return Buffer.concat([aesIv.read(), aesData.read()]);
};

exports.symmetricDecrypt = function(input, key) {
	var aesIv = Crypto.createDecipheriv('aes-256-ecb', key, '');
	aesIv.setAutoPadding(false);
	aesIv.end(input.slice(0, 16));
	
	var aesData = Crypto.createDecipheriv('aes-256-cbc', key, aesIv.read());
	aesData.end(input.slice(16));
	
	return aesData.read();
};
