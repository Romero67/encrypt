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
const hola = () => __awaiter(void 0, void 0, void 0, function* () {
    const criptonita = new MyCrypto();
    const privatekey = `MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDATo2h85z0BhFiOAbUgYO+crgcCUFR1XvEzPdOhtbAlW01G6D6VGekRL85a9Ubi6KNX+h5dtwFF0wnY3AsUzU+v6T9785+A/YhFEmpek09DRB8grGiX6qnP5NsmqvdmZ6Kie6MNt8nrAV22MY3JM8YOZCT+HukVjz5xZxsdaReKqQbhxZ/BO2soaGg1c0m1y1RJAvk1LLVY3GRTCSMmchgN908HF3/HgPdxuwOiLV5ofyv5Be88uMcdcMlaqYtgXlrqNtPn3tlWIT2bhj4BzNPgHXqCt07ZOxiL1Y37AGduxpx1KBsskwxdDowwAGN892amU7jq/bIABOG5Umf1d9JAgMBAAECggEAEq5u3tk6GZCPVsHHlBRC1pjxXrPddxQsklkw+x1pNkst0TduY3MYoGIXS344tRTTBTXYcRhFVm9FdBwaVQv+Q6q9XffSUPaUjfEZGNArOa+PtvDBTdtKSjYIXcgGwx+9wYqVtGROOF3jKAD1/Hxka9+HtoAwjq3b/Y2fXP/uqEED4xpVwl3q9ym8pDUNRcgCji2pAWiZmI63A2gP2gu42NqSu79n3zKViE9opsYmf+gXcayvKqSjoYpDJI7j2ivcJ/dMNsbgWtRK6+fqrtb12xf3+cB4gxH0/ez82rCXTGrIP1vaViqPhELLFEDmcBglhd26OCanx12wNzHKgNPYWwKBgQD0Ep9u5Ee+LE9XE4So1gJJCRA/WGa7VO/RxGb8czQDG4r9ln+1zjciAX4kia/qiu+V4rCFMZWad247bRRGWy0FYOrMcPPxplIKDVirbNg0UT6QXl3DlE2LQ9jzsPtI8pp9lCW5fgSYgNTkZ0ecGtcHzhi+a/zAf9Dh06YjRZtjywKBgQDJtFVVlknjhTLqMJqbcizCGFa9+DB8HA2/hYS929o5dBEIzz6KISlH1qg9lvMUUHHjziQoeeFx0B6F8Bumh31asj2y8haNjtO+mMo17BrsVVca2xgRz10Fe8mTnfFio0h5jjQC0Unur5Wmm7EGaZRQ3MwoFgSpgRVgMC4sTICuuwKBgDS5NSGSRIErNzRbLgP+vt2iDJVydjavYWLR52FPTYQCViLzeMEAO96nreUcrRigTKL3JiSPkn6cn/5MUN3l4jLQPchN+hRQVlZ/jZDyYT3j8vzitaSDC8EytdHmgFHAvmi0MPYB5+I9qj9wpAJvtdWkyqmP0DiRI8E0pCXoamnDAoGAVwQuQEMa00XWZkPbny4Ncxqu6TuWJySvJa3DS2j6ZwjUhHlr4IlX1r8bS57AdUYTLBT1cmTKRqBjWqLwOtJ+2M7GYVmhMyan4LTnn4WhQ825S0OzyZMs7T2vA7kCtuv8Szx24bRKcedb50mJgFux+YSXqr98+WdPwnRmpwPGDBsCgYB3YdXYU2yN0GbtVYwPvjkMV0cJwsMfP2uJ8CgRPYYZcqiP0mI1bZUVOvsb7YCob0tExRYV4DSEMHc7NpRp0+ZaxM6p2fls4kRDkpI4ltJaxrTiVsUJ3pyNi/91M6TQ6sYOzb+MU30YnkMVIRhuC9XMECPYNM2mWmMO+DItyXCElg==`;
    const publickey = `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwE6NofOc9AYRYjgG1IGDvnK4HAlBUdV7xMz3TobWwJVtNRug+lRnpES/OWvVG4uijV/oeXbcBRdMJ2NwLFM1Pr+k/e/OfgP2IRRJqXpNPQ0QfIKxol+qpz+TbJqr3ZmeionujDbfJ6wFdtjGNyTPGDmQk/h7pFY8+cWcbHWkXiqkG4cWfwTtrKGhoNXNJtctUSQL5NSy1WNxkUwkjJnIYDfdPBxd/x4D3cbsDoi1eaH8r+QXvPLjHHXDJWqmLYF5a6jbT597ZViE9m4Y+AczT4B16grdO2TsYi9WN+wBnbsacdSgbLJMMXQ6MMABjfPdmplO46v2yAAThuVJn9XfSQIDAQAB`;
    yield criptonita.initPrivateKey(privatekey);
    yield criptonita.initPublicKey(publickey);
    const msj = "Hola 123";
    console.log("mensaje: ", msj);
    const encryptMsj = yield criptonita.encryptData(msj);
    console.log("mensaje encryptado: ", encryptMsj);
    const descryptMsj = yield criptonita.decrypt(encryptMsj);
    console.log("mensaje descriptado: ", descryptMsj);
});
hola();
module.exports = {
    MyCrypto
};
