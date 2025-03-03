import { webcrypto } from "crypto";

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
  const keyPair = await webcrypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true, // Les clés doivent être extractibles
      ["encrypt", "decrypt"]
  );

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey
  };
}

// Export a crypto public key to a base64 string format
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  if (!key || key.type !== "public") {
    throw new Error("Invalid public key provided.");
  }

  const exported = await webcrypto.subtle.exportKey("spki", key);
  return arrayBufferToBase64(exported);
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(
  key: webcrypto.CryptoKey | null
): Promise<string | null> {
  if (!key || key.type !== "private") {
    throw new Error("Invalid private key provided.");
  }

  const exported = await webcrypto.subtle.exportKey("pkcs8", key);
  return arrayBufferToBase64(exported);
}

// Import a base64 string public key to its native format
export async function importPubKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const buffer = base64ToArrayBuffer(strKey);

  return await webcrypto.subtle.importKey(
      "spki",
      buffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["encrypt"]
  );
}

// Import a base64 string private key to its native format
export async function importPrvKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const buffer = base64ToArrayBuffer(strKey);

  return await webcrypto.subtle.importKey(
      "pkcs8",
      buffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["decrypt"]
  );
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(
  b64Data: string,
  strPublicKey: string
): Promise<string> {
  /// Convert the base64 encoded data to an ArrayBuffer
  const dataBuffer = base64ToArrayBuffer(b64Data);

  // Import the public key from base64 string
  const publicKey = await importPubKey(strPublicKey);

  // Encrypt the data using the public key
  const encryptedBuffer = await webcrypto.subtle.encrypt(
      {
        name: "RSA-OAEP",
      },
      publicKey,
      dataBuffer
  );

  // Convert the encrypted ArrayBuffer back to a base64 string
  return arrayBufferToBase64(encryptedBuffer);
}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(
  data: string,
  privateKey: webcrypto.CryptoKey
): Promise<string> {
  // Convert the base64 encoded data to an ArrayBuffer
  const encryptedBuffer = base64ToArrayBuffer(data);

  // Decrypt the data using the private key
  const decryptedBuffer = await webcrypto.subtle.decrypt(
      {
        name: "RSA-OAEP",
      },
      privateKey,
      encryptedBuffer
  );

  // Convert the decrypted ArrayBuffer back to a string using TextDecoder
  const decoder = new TextDecoder();
  return decoder.decode(decryptedBuffer);
}

// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  const key = await webcrypto.subtle.generateKey(
      {
        name: "AES-GCM",
        length: 256, // 256 bits key length (can also be 128 or 192)
      },
      true, // Make the key extractable
      ["encrypt", "decrypt"] // The key should be usable for both encryption and decryption
  );

  return key;
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  // Export the symmetric key in the raw format
  const exportedKey = await webcrypto.subtle.exportKey("raw", key);

  // Convert the exported key (ArrayBuffer) to a base64 string
  return arrayBufferToBase64(exportedKey);
}

// Import a base64 string format to its crypto native format
export async function importSymKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  const rawKey = base64ToArrayBuffer(strKey);

  // Import the raw key into the CryptoKey format
  const key = await webcrypto.subtle.importKey(
      "raw",              // Raw format for symmetric key
      rawKey,             // The ArrayBuffer of the key
      { name: "AES-GCM" }, // Specify the algorithm (AES-GCM is commonly used for symmetric encryption)
      true,               // The key is extractable
      ["encrypt", "decrypt"] // Usages for this key (encryption and decryption)
  );

  // Return the imported key
  return key;
}

// Encrypt a message using a symmetric key
export async function symEncrypt(
  key: webcrypto.CryptoKey,
  data: string
): Promise<string> {
  // 1. Convert the data (message) into a Uint8Array using TextEncoder
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);

  // 2. Generate a random IV (Initialization Vector)
  const iv = crypto.getRandomValues(new Uint8Array(12)); // `crypto` est l'API globale de Web Crypto

  // 3. Encrypt the data using the symmetric key and AES-GCM algorithm
  const encryptedData = await webcrypto.subtle.encrypt(
      {
        name: "AES-GCM", // Algorithm to use for encryption
        iv: iv, // Initialization vector
      },
      key, // The symmetric key to encrypt with
      encodedData // The data to encrypt
  );

  // 4. Convert the encrypted ArrayBuffer to a base64 string
  return arrayBufferToBase64(encryptedData);
}

// Decrypt a message using a symmetric key
export async function symDecrypt(
  strKey: string,
  encryptedData: string
): Promise<string> {
  // 1. Convert the encrypted data from Base64 string to ArrayBuffer
  const encryptedArrayBuffer = base64ToArrayBuffer(encryptedData);

  // 2. Convert the base64 string of the key back to a CryptoKey (assuming it's a base64 encoded key)
  const keyBuffer = base64ToArrayBuffer(strKey);
  const key = await webcrypto.subtle.importKey(
      "raw", // Format of the key (in this case, it's raw symmetric key data)
      keyBuffer,
      { name: "AES-GCM" }, // Algorithm for the key (AES-GCM)
      false, // Don't extract the key
      ["decrypt"] // The key should be usable for decryption
  );

  // 3. Extract the IV from the encrypted data (assuming the IV is the first 12 bytes)
  const iv = encryptedArrayBuffer.slice(0, 12); // AES-GCM uses a 12-byte IV
  const encryptedMessage = encryptedArrayBuffer.slice(12); // The actual encrypted data

  try {
    // 4. Decrypt the message using the symmetric key and the IV
    const decryptedData = await webcrypto.subtle.decrypt(
        {
          name: "AES-CBC", // The algorithm used for encryption
          iv: iv, // The initialization vector (IV)
        },
        key, // The symmetric key for decryption
        encryptedMessage // The encrypted data to decrypt
    );

    // 5. Decode the decrypted data back into a string using TextDecoder
    const decoder = new TextDecoder();
    const decodedMessage = decoder.decode(decryptedData);

    // 6. Return the decrypted message
    return decodedMessage;
  } catch (error) {
    throw new Error("Decryption failed: " + error);
  }
}
