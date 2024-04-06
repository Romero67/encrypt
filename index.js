"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = require("crypto");
class KeysCrypto {
    constructor(privateKeyBase64, publicKeyBase64) {
        this.privateKeyBase64 = privateKeyBase64;
        this.publicKeyBase64 = publicKeyBase64;
    }
}
class MyCrypto {
    constructor() {
        this.privateKey = null;
        this.publicKey = null;
    }
    //PUBLIC SIDE
    initPublicKey(publicKeyBase64) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                this.publicKey = yield this.importPublicKey(this.base64ToArrayBuffer(publicKeyBase64));
                return true;
            }
            catch (error) {
                return false;
            }
        });
    }
    importPublicKey(publicKeyPemBuffer) {
        return __awaiter(this, void 0, void 0, function* () {
            const publicKey = yield crypto_1.webcrypto.subtle.importKey("spki", publicKeyPemBuffer, {
                name: "RSA-OAEP",
                hash: "SHA-256",
            }, false, ["encrypt"]);
            return publicKey;
        });
    }
    encryptData(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.publicKey) {
                throw new Error('Debe inicializar la public key');
            }
            try {
                const self = this;
                const bufferData = self.stringToBuffer(data);
                const encryptedKey = yield crypto_1.webcrypto.subtle.encrypt({
                    name: "RSA-OAEP",
                }, self.publicKey, bufferData);
                return self.arrayBufferToBase64(encryptedKey);
            }
            catch (error) {
                throw new Error('Ha ocurrido un error durante el encryptado: ' + error);
            }
        });
    }
    //PRIVATE SIDE
    initPrivateKey(privateKeyBase64) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                this.privateKey = yield this.importPrivateKey(this.base64ToArrayBuffer(privateKeyBase64));
                return true;
            }
            catch (error) {
                return false;
            }
        });
    }
    importPrivateKey(privateKey) {
        return __awaiter(this, void 0, void 0, function* () {
            return yield crypto_1.webcrypto.subtle.importKey("pkcs8", // Key type (corrected)
            privateKey, // Key data
            {
                name: "RSA-OAEP", // Algorithm
                hash: "SHA-256", // Hash function
            }, false, // Not extractable (optional)
            ["decrypt"] // Usages
            );
        });
    }
    decrypt(messageEncrypted) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.privateKey) {
                throw new Error('Debe inicializar la private key');
            }
            try {
                const passwordBuffer = this.base64ToArrayBuffer(messageEncrypted);
                const passwordDecrypt = yield crypto_1.webcrypto.subtle.decrypt(this.privateKey.algorithm, this.privateKey, passwordBuffer);
                const decodedString = new TextDecoder().decode(passwordDecrypt);
                return decodedString;
            }
            catch (error) {
                console.error("[encrypt.js | decrypt] Error importing private key:", error);
                throw new Error('Ha ocurrido un error al descencriptar: ' + error);
            }
        });
    }
    //generate keys
    createKeys() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const { privateKey, publicKey } = yield crypto_1.webcrypto.subtle.generateKey({
                    name: 'RSA-OAEP',
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: 'SHA-256',
                }, true, ['encrypt', 'decrypt']);
                const a = yield crypto_1.webcrypto.subtle.exportKey('pkcs8', privateKey);
                const b = yield crypto_1.webcrypto.subtle.exportKey('spki', publicKey);
                const keys = new KeysCrypto(this.arrayBufferToBase64(a), this.arrayBufferToBase64(b));
                return keys;
            }
            catch (error) {
                console.error(`[encrypt.js | createKeys] error creating public and private keys: ${error}`);
                return null;
            }
        });
    }
    //helpers
    arrayBufferToBase64(arrayBuffer) {
        try {
            let base64 = '';
            let encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
            let bytes = new Uint8Array(arrayBuffer);
            let byteLength = bytes.byteLength;
            let byteRemainder = byteLength % 3;
            let mainLength = byteLength - byteRemainder;
            let a, b, c, d;
            let chunk;
            // Main loop deals with bytes in chunks of 3
            for (let i = 0; i < mainLength; i = i + 3) {
                // Combine the three bytes into a single integer
                chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
                // Use bitmasks to extract 6-bit segments from the triplet
                a = (chunk & 16515072) >> 18; // 16515072 = (2^6 - 1) << 18
                b = (chunk & 258048) >> 12; // 258048   = (2^6 - 1) << 12
                c = (chunk & 4032) >> 6; // 4032     = (2^6 - 1) << 6
                d = chunk & 63; // 63       = 2^6 - 1
                // Convert the raw binary segments to the appropriate ASCII encoding
                base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d];
            }
            // Deal with the remaining bytes and padding
            if (byteRemainder == 1) {
                chunk = bytes[mainLength];
                a = (chunk & 252) >> 2; // 252 = (2^6 - 1) << 2
                // Set the 4 least significant bits to zero
                b = (chunk & 3) << 4; // 3   = 2^2 - 1
                base64 += encodings[a] + encodings[b] + '==';
            }
            else if (byteRemainder == 2) {
                chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1];
                a = (chunk & 64512) >> 10; // 64512 = (2^6 - 1) << 10
                b = (chunk & 1008) >> 4; // 1008  = (2^6 - 1) << 4
                // Set the 2 least significant bits to zero
                c = (chunk & 15) << 2; // 15    = 2^4 - 1
                base64 += encodings[a] + encodings[b] + encodings[c] + '=';
            }
            return base64;
        }
        catch (error) {
            console.error(`[encrypt.js | arrayBufferToBase64] error parsing buffer array to base64: ${error}`);
            return null;
        }
    }
    base64ToArrayBuffer(base64) {
        try {
            const binaryString = atob(base64);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes.buffer;
        }
        catch (error) {
            console.error(`[encrypt.js | base64ToArrayBuffer] error parsing base64 to array buffer: ${error}`);
            return null;
        }
    }
    stringToBuffer(str) {
        try {
            const encoder = new TextEncoder();
            return encoder.encode(str);
        }
        catch (error) {
            console.error(`[myCrypto | stringToBuffer] error parsing string to buffer: ${error}`);
        }
    }
}
exports.default = MyCrypto;
module.exports = {
    MyCrypto
};
