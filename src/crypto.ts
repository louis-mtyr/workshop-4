import { webcrypto } from "crypto";
import { generateKeyPair } from 'crypto';

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  // TODO implement this function using the crypto package to generate a public and private RSA key pair.
  //      the public key should be used for encryption and the private key for decryption. Make sure the
  //      keys are extractable.
    return new Promise((resolve, reject) => {
        generateKeyPair(
            'rsa',
            {
                modulusLength: 2048,
                publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem',
                },
                privateKeyEncoding: {
                    type: 'pkcs8',
                    format: 'pem',
                },
            },
            (err, publicKeyPem, privateKeyPem) => {
                if (err) {
                    reject(err);
                } else {
                    try {
                        const publicKey = crypto.subtle.importKey(
                            'spki',
                            Buffer.from(publicKeyPem),
                            { name: 'RSA-OAEP', hash: 'SHA-256' },
                            false,
                            ['encrypt']
                        );

                        const privateKey = crypto.subtle.importKey(
                            'pkcs8',
                            Buffer.from(privateKeyPem),
                            { name: 'RSA-OAEP', hash: 'SHA-256' },
                            false,
                            ['decrypt']
                        );

                        Promise.all([publicKey, privateKey]).then((keys) => {
                            resolve({
                                publicKey: keys[0],
                                privateKey: keys[1],
                            });
                        });
                    } catch (error) {
                        reject(error);
                    }
                }
            }
        );
    });
}
// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  // TODO implement this function to return a base64 string version of a public key
    const exportedKey = await crypto.subtle.exportKey('spki', key);
    const exportedKeyBuffer = new Uint8Array(exportedKey);
    const base64Key = arrayBufferToBase64(exportedKey);
    return base64Key;

}


// Export a crypto private key to a base64 string format
export async function exportPrvKey(
  key: webcrypto.CryptoKey | null
): Promise<string | null> {
  // TODO implement this function to return a base64 string version of a private key
    if (key === null) {
        return null;
    }

    const exportedKey = await crypto.subtle.exportKey('pkcs8', key);
    const exportedKeyBuffer = new Uint8Array(exportedKey);
    const base64Key = arrayBufferToBase64(exportedKeyBuffer.buffer);
    return base64Key;

}

// Import a base64 string public key to its native format
export async function importPubKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // TODO implement this function to go back from the result of the exportPubKey function to it's native crypto key object
    const keyBuffer = base64ToArrayBuffer(strKey);
    const publicKey = await crypto.subtle.importKey(
        'spki',
        keyBuffer,
        {
            name: 'RSA-OAEP',
            hash: { name: 'SHA-256' },
        },
        true,
        ['encrypt']
    );
    return publicKey;
}

// Import a base64 string private key to its native format
export async function importPrvKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // TODO implement this function to go back from the result of the exportPrvKey function to it's native crypto key object
    const keyBuffer = base64ToArrayBuffer(strKey);
    const privateKey = await crypto.subtle.importKey(
        'pkcs8',
        keyBuffer,
        {
            name: 'RSA-OAEP',
            hash: { name: 'SHA-256' },
        },
        true,
        ['decrypt']
    );
    return privateKey;
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(
  b64Data: string,
  strPublicKey: string
): Promise<string> {
  // TODO implement this function to encrypt a base64 encoded message with a public key
  // tip: use the provided base64ToArrayBuffer function
    const publicKey = await importPubKey(strPublicKey);
    const dataBuffer = base64ToArrayBuffer(b64Data);

    const encryptedData = await crypto.subtle.encrypt(
        {
            name: 'RSA-OAEP',
        },
        publicKey,
        dataBuffer
    );

    const encryptedArrayBuffer = new Uint8Array(encryptedData);
    const encryptedB64 = arrayBufferToBase64(encryptedArrayBuffer.buffer);
    return encryptedB64;
}
    
// Decrypts a message using an RSA private key
export async function rsaDecrypt(
  data: string,
  privateKey: webcrypto.CryptoKey
): Promise<string> {
    const dataBuffer = base64ToArrayBuffer(data);

    const decryptedData = await crypto.subtle.decrypt(
        {
            name: 'RSA-OAEP',
        },
        privateKey,
        dataBuffer
    );

    const decryptedArrayBuffer = new Uint8Array(decryptedData);
    const decryptedMessage = new TextDecoder().decode(decryptedArrayBuffer);
    return decryptedMessage;
}

// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  // TODO implement this function using the crypto package to generate a symmetric key.
  //      the key should be used for both encryption and decryption. Make sure the
  //      keys are extractable.
    const key = await crypto.subtle.generateKey(
        {
            name: 'AES-GCM',
            length: 256,
        },
        true,
        ['encrypt', 'decrypt']
    );

    return key;
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  // TODO implement this function to return a base64 string version of a symmetric key
    const exportedKey = await crypto.subtle.exportKey('raw', key);
    const exportedArrayBuffer = new Uint8Array(exportedKey);
    const exportedB64 = arrayBufferToBase64(exportedArrayBuffer.buffer);
    return exportedB64;
}

// Import a base64 string format to its crypto native format
export async function importSymKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // TODO implement this function to go back from the result of the exportSymKey function to it's native crypto key object
    const keyBuffer = base64ToArrayBuffer(strKey);
    const importedKey = await crypto.subtle.importKey(
        'raw',
        keyBuffer,
        {
            name: 'AES-GCM',
            length: 256,
        },
        true,
        ['encrypt', 'decrypt']
    );
    return importedKey;
}

// Encrypt a message using a symmetric key
export async function symEncrypt(
  key: webcrypto.CryptoKey,
  data: string
): Promise<string> {
  // TODO implement this function to encrypt a base64 encoded message with a public key
  // tip: encode the data to a uin8array with TextEncoder
    const dataEncoder = new TextEncoder();
    const dataBuffer = dataEncoder.encode(data);

    const encryptedData = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: crypto.getRandomValues(new Uint8Array(12)),
        },
        key,
        dataBuffer
    );

    const encryptedArrayBuffer = new Uint8Array(encryptedData);
    const encryptedB64 = arrayBufferToBase64(encryptedArrayBuffer.buffer);
    return encryptedB64;
}

// Decrypt a message using a symmetric key
export async function symDecrypt(
  strKey: string,
  encryptedData: string
): Promise<string> {
  // TODO implement this function to decrypt a base64 encoded message with a private key
  // tip: use the provided base64ToArrayBuffer function and use TextDecode to go back to a string format
    const keyBuffer = base64ToArrayBuffer(strKey);
    const dataBuffer = base64ToArrayBuffer(encryptedData);

    const key = await crypto.subtle.importKey(
        'raw',
        keyBuffer,
        {
            name: 'AES-GCM',
            length: 256,
        },
        true,
        ['encrypt', 'decrypt']
    );

    const decryptedData = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: new Uint8Array(12),
        },
        key,
        dataBuffer
    );

    const decryptedArrayBuffer = new Uint8Array(decryptedData);
    const decryptedMessage = new TextDecoder().decode(decryptedArrayBuffer);
    return decryptedMessage;
}