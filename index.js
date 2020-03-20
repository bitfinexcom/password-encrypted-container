const sodium = require('sodium-native')
const assert = require('nanoassert')

function isUInt32 (x) {
  return x >= 0 && x <= 0xffffffff
}

function isInt32 (x) {
  return x >= -0x7fffffff && x <= 0x7fffffff
}

class KeyHeader {
  constructor (buf) {
    assert(buf.byteLength >= KeyHeader.BYTES, 'KeyHeader buf too small')
    this.buffer = buf
  }

  set alg (val) {
    assert(isInt32(val), 'KeyHeader.alg must be int32')
    this.rotateNonce()
    return this.buffer.writeInt32LE(val, 0)
  }

  get alg () {
    // due to libsodium
    return this.buffer.readInt32LE(0)
  }

  set opslimit (val) {
    assert(isUInt32(val), 'KeyHeader.opslimit must be uint32')
    this.rotateNonce()
    return this.buffer.writeUInt32LE(val, 4)
  }

  get opslimit () {
    return this.buffer.readUInt32LE(4)
  }

  set memlimit (val) {
    assert(isUInt32(val), 'KeyHeader.memlimit must be uint32')
    this.rotateNonce()
    return this.buffer.writeUInt32LE(val, 8)
  }

  get memlimit () {
    return this.buffer.readUInt32LE(8)
  }

  get nonce () {
    return this.buffer.subarray(12, 12 + sodium.crypto_pwhash_SALTBYTES)
  }

  init (opslimit, memlimit) {
    this.alg = sodium.crypto_pwhash_ALG_ARGON2ID13
    this.opslimit = opslimit
    this.memlimit = memlimit
  }

  validate () {
    assert(this.alg === sodium.crypto_pwhash_ALG_ARGON2ID13)
  }

  rotateNonce () {
    sodium.randombytes_buf(this.nonce)
  }
}
KeyHeader.BYTES = 12 + sodium.crypto_pwhash_SALTBYTES

class DataHeader {
  constructor (buf) {
    assert(buf.byteLength >= DataHeader.BYTES, 'DataHeader buffer too small')
    this.buffer = buf
  }

  set alg (val) {
    assert(isInt32(val))
    this.rotateNonce()
    return this.buffer.writeUInt32LE(val, 0)
  }

  get alg () {
    return this.buffer.readUInt32LE(0)
  }

  get nonce () {
    return this.buffer.subarray(4, 4 + sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
  }

  init () {
    this.alg = 1
  }

  validate () {
    assert(this.alg === 1)
  }

  rotateNonce () {
    sodium.randombytes_buf(this.nonce)
  }
}
DataHeader.BYTES = 4 + sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

// Would be cool to add a libhydrogen style probe ie. blake2b(key=derivedKey, data=nonce)
class PasswordEncryptedBuffer {
  constructor (buf) {
    assert(buf.byteLength >= PasswordEncryptedBuffer.BYTES - DATA_MAC_BYTES, 'PasswordEncryptedBuffer buffer too small')
    this.destroyed = false

    this.key = sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
    this.buffer = buf

    this._keyHeader = new KeyHeader(this.buffer.subarray(4, 4 + KeyHeader.BYTES))
    this._dataHeader = new DataHeader(this.buffer.subarray(4 + KeyHeader.BYTES, 4 + KeyHeader.BYTES + DataHeader.BYTES))
  }

  set version (val) {
    assert(isUInt32(val))
    return this.buffer.writeUInt32LE(val, 0)
  }

  get version () {
    return this.buffer.readUInt32LE(0)
  }

  init (opslimit, memlimit) {
    this.version = 1
    this._keyHeader.init(opslimit, memlimit)
    this._dataHeader.init()
  }

  validate () {
    assert(this.version === 1)
    this._keyHeader.validate()
    this._dataHeader.validate()
  }

  deriveKey (passphrase, cb) {
    PasswordEncryptedBuffer.deriveKey(passphrase, {
      key: this.key,
      nonce: this._keyHeader.nonce,
      opslimit: this._keyHeader.opslimit,
      memlimit: this._keyHeader.memlimit,
      alg: this._keyHeader.alg
    }, (err) => {
      return cb(err, this.key)
    })
  }

  static deriveKey (passphrase, opts, cb) {
    assert(opts, 'opts must be given')
    assert(opts.opslimit, 'opts.opslimit must be set')
    assert(opts.memlimit, 'opts.memlimit must be set')
    const key = opts.key == null ? sodium.sodium_malloc(sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES) : opts.key
    const nonce = opts.nonce == null ? sodium.sodium_malloc(sodium.crypto_pwhash_SALTBYTES) : opts.nonce

    if (!opts.nonce) {
      sodium.randombytes_buf(nonce)
    }

    sodium.crypto_pwhash(
      key,
      passphrase,
      nonce,
      opts.opslimit,
      opts.memlimit,
      opts.alg || sodium.crypto_pwhash_ALG_ARGON2ID13
    )

    return cb(null, key, nonce)
  }

  decrypt (ciphertext) {
    const plaintext = sodium.sodium_malloc(ciphertext.byteLength - PasswordEncryptedBuffer.BYTES)

    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      plaintext,
      null,
      ciphertext.subarray(PasswordEncryptedBuffer.BYTES - DATA_MAC_BYTES),
      this._keyHeader.buffer,
      this._dataHeader.nonce,
      this.key
    )

    return plaintext
  }

  encrypt (plaintext) {
    const ciphertext = Buffer.alloc(plaintext.byteLength + PasswordEncryptedBuffer.BYTES)

    this._dataHeader.rotateNonce()
    sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      ciphertext.subarray(PasswordEncryptedBuffer.BYTES - DATA_MAC_BYTES),
      plaintext,
      this._keyHeader.buffer,
      null,
      this._dataHeader.nonce,
      this.key
    )
    ciphertext.set(this.buffer)

    return ciphertext
  }

  destroy () {
    sodium.sodium_memzero(this.key)
    sodium.sodium_memzero(this.buffer)

    this.destroyed = true
  }
}
const DATA_MAC_BYTES = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES
PasswordEncryptedBuffer.BYTES = 4 + KeyHeader.BYTES + DataHeader.BYTES + DATA_MAC_BYTES

const cache = new WeakMap()

class PasswordEncryptedContainer {
  constructor (key, peb) {
    cache.set(this, key)
    this.destroyed = false
    this.peb = peb
  }

  encrypt (plaintext) {
    if (this.destroyed === true) throw new Error('Destroyed')

    return this.peb.encrypt(plaintext)
  }

  encryptLength (plaintext) {
    return PasswordEncryptedBuffer.BYTES + plaintext.byteLength
  }

  decrypt (ciphertext) {
    if (this.destroyed === true) throw new Error('Destroyed')

    return this.peb.decrypt(ciphertext)
  }

  decryptLength (ciphertext) {
    return ciphertext.byteLength - PasswordEncryptedBuffer.BYTES
  }

  destroy () {
    if (this.destroyed === true) return

    this.peb.destroy()
    var key = cache.get(this)
    sodium.sodium_memzero(key)
    cache.delete(this)
    this.destroyed = true
  }

  compare (k1) {
    if (this.destroyed === true) throw new Error('Destroyed')
    PasswordEncryptedContainer.compare(cache.get(this), k1)
  }

  static create (passphrase, opts, cb) {
    opts = Object.assign({}, module.exports.MODERATE, opts)
    var initPeb = new PasswordEncryptedBuffer(Buffer.alloc(PasswordEncryptedBuffer.BYTES - DATA_MAC_BYTES))
    initPeb.init(opts.opslimit, opts.memlimit)
    initPeb.deriveKey(passphrase, (err, key) => {
      if (err) return cb(err)
      cb(null, new this(key, initPeb))
    })
  }

  static open (passphrase, buf, cb) {
    var initPeb = new PasswordEncryptedBuffer(buf.subarray(0, PasswordEncryptedBuffer.BYTES - DATA_MAC_BYTES))
    initPeb.validate()

    initPeb.deriveKey(passphrase, (err, key) => {
      if (err) return cb(err)
      cb(null, new this(key, initPeb))
    })
  }

  static compare (k1, k2) {
    return sodium.sodium_memcmp(k1, k2)
  }

  static deriveKey (passphrase, opts, cb) {
    return PasswordEncryptedBuffer.deriveKey(passphrase, opts, cb)
  }

  static memzero (buf) {
    sodium.sodium_memzero(buf)
  }
}

module.exports = PasswordEncryptedContainer

module.exports.MEMLIMIT_INTERACTIVE = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
module.exports.OPSLIMIT_INTERACTIVE = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
module.exports.INTERACTIVE = {
  memlimit: module.exports.MEMLIMIT_INTERACTIVE,
  opslimit: module.exports.OPSLIMIT_INTERACTIVE
}

module.exports.MEMLIMIT_MODERATE = sodium.crypto_pwhash_MEMLIMIT_MODERATE
module.exports.OPSLIMIT_MODERATE = sodium.crypto_pwhash_OPSLIMIT_MODERATE
module.exports.MODERATE = {
  memlimit: module.exports.MEMLIMIT_MODERATE,
  opslimit: module.exports.OPSLIMIT_MODERATE
}

module.exports.MEMLIMIT_SENSITIVE = sodium.crypto_pwhash_MEMLIMIT_SENSITIVE
module.exports.OPSLIMIT_SENSITIVE = sodium.crypto_pwhash_OPSLIMIT_SENSITIVE
module.exports.SENSITIVE = {
  memlimit: module.exports.MEMLIMIT_SENSITIVE,
  opslimit: module.exports.OPSLIMIT_SENSITIVE
}
