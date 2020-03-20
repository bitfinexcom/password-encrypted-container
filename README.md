# `password-encrypted-container`

> Password encrypted container

## Usage

### Create

```js
var PasswordEncryptedOverlay = require('password-encrypted-container')

var passwordBuffer = // ... (preferably sodium SecureBuffer)
// Note that the passwordBuffer is "consumed" by the constructor, ie. it will
// be cleared when a key has been derived from the password. If you need to keep
// the password, you should copy it and pass in the copy
PasswordEncryptedOverlay.create(
  passwordBuffer,
  PasswordEncryptedOverlay.MODERATE,
  onready
)

function onready (err, container) {
  PasswordEncryptedOverlay.memzero(passwordBuffer)
  if (err) throw err

  const ciphertext = container.encrypt(Buffer.from('My encrypted file'))
  const plaintext = container.decrypt(Buffer.from('My encrypted file'))
  storage.destroy()
  storage = null
}
```

### Read

```js
var PasswordEncryptedOverlay = require('password-encrypted-container')

var passwordBuffer = // ... (preferably sodium SecureBuffer)
var containerBuf = // Read from filesystem
PasswordEncryptedOverlay.open(passwordBuffer, containerBuf, function(err, container) {
  PasswordEncryptedOverlay.memzero(passwordBuffer)
  if (err) throw err

  const plaintext = storage.decrypt(containerBuf)
  storage.destroy()
  storage = null
})
```

## API

### `PasswordEncryptedOverlay.create(password, {memlimit, opslimit}, cb(err, container))`
Create a new container with the given hardness settings. Password must be a
`Buffer`, optimally a `SecureBuffer`. `password` should be zero'ed out after it
has been derived into a key. Hardness settings determine the resources spent
turning password into a encryption key. See the constants below for some
predefined settings. `memlimit` is the number of bytes of memory used, rounded
down to the nearest kilobyte. `opslimit` is the number of passes over the
memory. Both must be `Numbers` and fit in a 32-bit unsigned integer.

### `PasswordEncryptedOverlay.open(password, buf, cb(err, container))`
Open a existing container with encrypted with `password`. Password must be a
`Buffer`, optimally a `SecureBuffer`. `password` should be zero'ed out after it
has been derived into a key. `buf` must be an exisiting container

### `const plaintext = container.decrypt(buf)`
Read and decrypt into a `SecureBuffer` from `buf`.

### `const ciphertext = container.encrypt(buf)`
Encrypt a `Buffer`. This updates the settings and rotates the nonce.

### `container.compare(key)`
Compare the key contained in `container` with another key. Note this does not
compare passphrases, but keys.

### `container.destroy()`
Destroy the internal state, including zero'ing all internal data.
Makes all other methods unusable hereafter

### `PasswordEncryptedOverlay.deriveKey(password, {memlimit, opslimit, nonce?}, cb(err, key, nonce))`
Derive a key manually with an optional nonce. Useful if you want to compare passwords without
storing the password itself.

### `const equal = PasswordEncryptedOverlay.compareKeys(k1, k2)`
Compare two keys safely, in constant-time.

### `const equal = PasswordEncryptedOverlay.memzero(buf)`
Clear a buffer `buf`.

### Constants

* `PasswordEncryptedOverlay.INTERACTIVE`
  - `PasswordEncryptedOverlay.MEMLIMIT_INTERACTIVE`
  - `PasswordEncryptedOverlay.OPSLIMIT_INTERACTIVE`
* `PasswordEncryptedOverlay.MODERATE`
  - `PasswordEncryptedOverlay.MEMLIMIT_MODERATE`
  - `PasswordEncryptedOverlay.OPSLIMIT_MODERATE`
* `PasswordEncryptedOverlay.SENSITIVE`
  - `PasswordEncryptedOverlay.MEMLIMIT_SENSITIVE`
  - `PasswordEncryptedOverlay.OPSLIMIT_SENSITIVE`

## Install

```sh
npm install password-encrypted-container
```

## License

[ISC](LICENSE)
