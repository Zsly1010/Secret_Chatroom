let privateKey = null

// Worker receives instructions from the main thread
onmessage = async function (e) {
  const [messageType, messageId, text, key] = e.data
  let result

  try {
    switch (messageType) {
      case 'generate-keys':
        result = await generateKeypair()
        break
      case 'encrypt':
        result = await encrypt(text, key)
        break
      case 'decrypt':
        result = await decrypt(text)
        break
    }
  } catch (err) {
    result = `ERROR: ${err.message}`
  }

  // 将结果返回给主线程
  postMessage([messageId, result])
}

/** Generate the RSA-OAEP key pair and return the Base64-encoded public key */
async function generateKeypair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  )

  privateKey = keyPair.privateKey

  const exportedPublicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey)
  const publicKeyBase64 = btoa(String.fromCharCode(...new Uint8Array(exportedPublicKey)))

  return publicKeyBase64
}

/** Encrypt the plaintext with the other party's public key and return the Base64 ciphertext */
async function encrypt(content, publicKeyBase64) {
  const publicKeyDer = Uint8Array.from(atob(publicKeyBase64), c => c.charCodeAt(0))

  const publicKey = await crypto.subtle.importKey(
    'spki',
    publicKeyDer,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256',
    },
    false,
    ['encrypt']
  )

  const encoded = new TextEncoder().encode(content)
  const encrypted = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, encoded)

  return btoa(String.fromCharCode(...new Uint8Array(encrypted)))
}

/** Decrypts the Base64 ciphertext with the local private key and returns the plaintext */
async function decrypt(base64Ciphertext) {
  if (!privateKey) throw new Error('Private key not initialized.')

  const ciphertext = Uint8Array.from(atob(base64Ciphertext), c => c.charCodeAt(0))

  const decrypted = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    privateKey,
    ciphertext
  )

  return new TextDecoder().decode(decrypted)
}
