import { Buffer } from 'buffer';

/**
 * WebCrypto Abstraction for NIT Messenger
 * Provides real ChaCha20-Poly1305 equivalent (AES-GCM for WebCrypto compliance)
 * and true ECDH key exchanges using X25519 equivalent (P-256 for broader browser support).
 */

export class NoiseCrypto {
  private keyPair: CryptoKeyPair | null = null;
  private sharedSecret: CryptoKey | null = null;
  
  constructor() {}

  async generateKeyPair() {
    this.keyPair = await window.crypto.subtle.generateKey(
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
      true,
      ["deriveKey", "deriveBits"]
    );
    return this.keyPair;
  }

  async exportPublicKey(): Promise<string> {
    if (!this.keyPair) throw new Error("Key pair not generated");
    const exported = await window.crypto.subtle.exportKey("raw", this.keyPair.publicKey);
    return Buffer.from(exported).toString('base64');
  }

  async importPublicKey(base64Key: string): Promise<CryptoKey> {
    const keyData = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0));
    return await window.crypto.subtle.importKey(
      "raw",
      keyData,
      {
        name: "ECDH",
        namedCurve: "P-256",
      },
      true,
      []
    );
  }

  async deriveSharedSecret(remotePublicKey: CryptoKey) {
    if (!this.keyPair) throw new Error("Private key missing");
    
    // Derive a 256-bit AES-GCM key from the ECDH exchange
    this.sharedSecret = await window.crypto.subtle.deriveKey(
      {
        name: "ECDH",
        public: remotePublicKey,
      },
      this.keyPair.privateKey,
      {
        name: "AES-GCM",
        length: 256,
      },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async encryptBinary(data: Uint8Array): Promise<{ ciphertext: Uint8Array; iv: Uint8Array }> {
    if (!this.sharedSecret) throw new Error("Shared secret not derived");
    
    // In OSNOVA this would be ChaCha20Poly1305, mapped to AES-GCM for WebCrypto compliance
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    const encrypted = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      this.sharedSecret,
      data
    );

    return {
      ciphertext: new Uint8Array(encrypted),
      iv: iv
    };
  }

  async decryptBinary(ciphertext: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
    if (!this.sharedSecret) throw new Error("Shared secret not derived");

    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      this.sharedSecret,
      ciphertext
    );

    return new Uint8Array(decrypted);
  }
}
