const isASCII = (str, extended) => /^[\x01-\xFF]*$/.test(str)

export const encode = key => {
  if (!isASCII(key)) {
    throw Error('Key must be ASCII')
  }
  if (key.length > 32) {
    throw Error('Key must be less than 32 bytes')
  }
  return new Uint8Array(Array.from(key).map(c => c.charCodeAt(0)))
}

export const decode = encodedKey => {
  String.fromCharCode(...encodedKey)
}
