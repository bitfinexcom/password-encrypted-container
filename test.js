var test = require('tape')

var PasswordEncryptedOverlay = require('.')

test('Write and reread', function (assert) {
  var pwd = Buffer.from('secret') // use sodium buffers in real life
  var msg = Buffer.from('Hello world')
  PasswordEncryptedOverlay.create(Buffer.from(pwd), {}, function (err, peo) {
    if (err) return assert.error(err)

    var encrypted = peo.encrypt(msg)
    assert.ok(peo.decrypt(encrypted).equals(msg))
    var encrypted2 = peo.encrypt(msg)
    assert.notEqual(encrypted, encrypted2)
    peo.destroy()

    PasswordEncryptedOverlay.open(Buffer.from(pwd), encrypted, function (err, peo2) {
      if (err) return assert.error(err)

      assert.ok(peo2.decrypt(encrypted).equals(msg))
      peo2.destroy()
      assert.end()
    })
  })
})
