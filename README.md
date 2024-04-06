# Web Crypto

## Description
NPM package to easily utilize the "webcrypto" library. It leverages the native "webcrypto" dependency in Node.js, allowing you to create your own keys for encrypting/decrypting messages within a Node.js environment! Very simple!

## Getting Started

### Install using npm 
npm i encrypt-web

### Install using Yarn 
yarn add encrypt-web

## Usage Examples

### Creating Keys and Encrypting/Decrypting with SHA-256 Algorithm

```javascript
const {MyCrypto} = require('encrypt-web')

const example = async()=>{

    const webcrypto = new MyCrypto()
    
    // You should securely store the keys somewhere
    const keys = await webcrypto.createKeys()
    
    const msj = "Hola 123"

    // First, initialize the public key for encryption
    await webcrypto.initPublicKey(keys.publicKeyBase64)

    // Then encrypt the message
    const encryptMsj = await webcrypto.encryptData(msj)

    console.log("Encrypted message: ",encryptMsj)

    // Similarly for decryption but with the private key
    await webcrypto.initPrivateKey(keys.privateKeyBase64)
    const decryptMsj = await webcrypto.decrypt(encryptMsj)

    console.log("Decrypted message: ",decryptMsj)

}

example()
