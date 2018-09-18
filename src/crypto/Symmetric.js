const ALGO = 'AES-CBC'

export default class Symmetric {
  constructor(key, iv) {
    this.key = key
    this.iv = iv
  }

  static async build(exportedKey) {
    const { key, iv } = await (exportedKey
      ? this.import(exportedKey)
      : this.generate())
    return new this(key, iv)
  }

  async encryptString(string) {
    return this.encrypt(Symmetric.encode(string))
  }

  async decryptString(data) {
    return Symmetric.decode(await this.decrypt(data))
  }

  async encrypt(data) {
    return new Uint8Array(
      (await window.crypto.subtle.encrypt(
        { name: ALGO, iv: this.iv },
        this.key,
        data
      ))
    )
  }

  async decrypt(data) {
    return window.crypto.subtle.decrypt(
      { name: ALGO, iv: this.iv },
      this.key,
      data
    )
  }

  async export() {
    return Symmetric.mergeByteArrays(
      this.iv,
      new Uint8Array((await window.crypto.subtle.exportKey('raw', this.key)))
    )
  }

  static mergeByteArrays(...arrays) {
    const totalLength = arrays.reduce(
      (length, array) => length + array.length,
      0
    )
    const result = new Uint8Array(totalLength)
    arrays.reduce((mergedLength, array) => {
      result.set(array, mergedLength)
      return (mergedLength = mergedLength + array.length)
    }, 0)
    return result
  }

  static encode(data) {
    return new TextEncoder().encode(data)
  }

  static decode(data) {
    return new TextDecoder().decode(data)
  }

  static randomIV() {
    const array = new Uint8Array(16)
    window.crypto.getRandomValues(array)
    return array
  }

  static async generate() {
    return {
      iv: this.randomIV(),
      key: await window.crypto.subtle.generateKey(
        {
          name: ALGO,
          length: 256
        },
        true,
        ['encrypt', 'decrypt']
      )
    }
  }

  static async import(exportedKey) {
    const iv = exportedKey.slice(0, 16)
    const rawKey = exportedKey.slice(16, exportedKey.length)
    return {
      iv,
      key: await window.crypto.subtle.importKey(
        'raw',
        rawKey,
        {
          name: ALGO,
          length: 256
        },
        true,
        ['encrypt', 'decrypt']
      )
    }
  }
}
