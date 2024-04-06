
import { webcrypto } from 'crypto';

class KeysCrypto {
    public privateKeyBase64: string
    public publicKeyBase64: string

    constructor(privateKeyBase64: string, publicKeyBase64: string){
        this.privateKeyBase64 = privateKeyBase64
        this.publicKeyBase64 = publicKeyBase64
    }
}

export default class MyCrypto {

    privateKey?: CryptoKey = null
    publicKey?: CryptoKey = null

    //PUBLIC SIDE

    async initPublicKey(publicKeyBase64: string){

        try {
            this.publicKey = await this.importPublicKey(this.base64ToArrayBuffer(publicKeyBase64))
            return true
        } catch (error) {
            return false
        }
        
    }

    private async importPublicKey(publicKeyPemBuffer: ArrayBuffer){
        const publicKey = await webcrypto.subtle.importKey(
            "spki",
            publicKeyPemBuffer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256",
            },
            false,
            ["encrypt"]
        );
        return publicKey;
    }

    async encryptData(data: string) {
        if(!this.publicKey){
            throw new Error('Debe inicializar la public key')
        }
        try {
            const self = this
            const bufferData = self.stringToBuffer(data)
            
            const encryptedKey = await webcrypto.subtle.encrypt(
                {
                    name: "RSA-OAEP",
                },
                self.publicKey,
                bufferData
            );

            return self.arrayBufferToBase64(encryptedKey);

        } catch (error) {
            throw new Error('Ha ocurrido un error durante el encryptado: '+error)
        }
    }

    //PRIVATE SIDE

    async initPrivateKey(privateKeyBase64: string): Promise<boolean> {
        try {
            this.privateKey =  await this.importPrivateKey(this.base64ToArrayBuffer(privateKeyBase64))
            return true
        } catch (error) {
            return false
        }
    }

    private async importPrivateKey(privateKey: ArrayBuffer) {
        return await webcrypto.subtle.importKey(
            "pkcs8", // Key type (corrected)
            privateKey, // Key data
            {
                name: "RSA-OAEP", // Algorithm
                hash: "SHA-256", // Hash function
            },
            false, // Not extractable (optional)
            ["decrypt"] // Usages
        );
    }
    
    async decrypt(messageEncrypted: string): Promise<string> {
        if(!this.privateKey){
            throw new Error('Debe inicializar la private key')
        }
        try {
            
            const passwordBuffer = this.base64ToArrayBuffer(messageEncrypted)

            const passwordDecrypt = await webcrypto.subtle.decrypt(this.privateKey.algorithm, this.privateKey, passwordBuffer)
            const decodedString = new TextDecoder().decode(passwordDecrypt);

            return decodedString

        } catch (error) {
            console.error("[encrypt.js | decrypt] Error importing private key:", error);

            throw new Error('Ha ocurrido un error al descencriptar: '+error)
        }
    }

    //generate keys

    async createKeys(): Promise<KeysCrypto> {
        try {
            const { privateKey, publicKey } = await webcrypto.subtle.generateKey(
                {
                    name: 'RSA-OAEP',
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: 'SHA-256',
                },
                true,
                ['encrypt', 'decrypt'],
            );
    
            const a = await webcrypto.subtle.exportKey('pkcs8', privateKey);
            const b = await webcrypto.subtle.exportKey('spki', publicKey);
    
            const keys = new KeysCrypto(this.arrayBufferToBase64(a), this.arrayBufferToBase64(b))

            return keys;
        } catch (error) {
            console.error(`[encrypt.js | createKeys] error creating public and private keys: ${error}`)
            return null
        }
    }

    //helpers

    private arrayBufferToBase64(arrayBuffer: ArrayBuffer): string {
        try {
            let base64 = '';
            let encodings =
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

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
            } else if (byteRemainder == 2) {
            chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1];

            a = (chunk & 64512) >> 10; // 64512 = (2^6 - 1) << 10
            b = (chunk & 1008) >> 4; // 1008  = (2^6 - 1) << 4

            // Set the 2 least significant bits to zero
            c = (chunk & 15) << 2; // 15    = 2^4 - 1

            base64 += encodings[a] + encodings[b] + encodings[c] + '=';
            }

            return base64;
        } catch (error) {
            console.error(`[encrypt.js | arrayBufferToBase64] error parsing buffer array to base64: ${error}`)
            return null
        }
    }

    private base64ToArrayBuffer(base64: string): ArrayBuffer {
        try {
            const binaryString = atob(base64);
            const bytes = new Uint8Array(binaryString.length);
    
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return bytes.buffer;
        } catch (error) {
            console.error(`[encrypt.js | base64ToArrayBuffer] error parsing base64 to array buffer: ${error}`)
            return null
        }
    }

    private stringToBuffer(str: string) {
        try {

            const encoder = new TextEncoder();
            return encoder.encode(str);

        } catch (error) {
            console.error(`[myCrypto | stringToBuffer] error parsing string to buffer: ${error}`)
        }
    }    

}

module.exports = {
    MyCrypto
};