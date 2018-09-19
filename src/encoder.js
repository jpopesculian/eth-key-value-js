const isAscii = str => /^[\x01-\xFF]+$/.test(str)
const isHex = str => /^(0x)?[0-9A-Fa-f]+$/.test(str)

export const text = {
  encode: text => new Uint8Array(Array.from(text).map(c => c.charCodeAt(0))),
  decode: encodedText => String.fromCharCode(...encodedText)
}

export const ascii = {
  encode: (ascii, limit = 32) => {
    if (!isAscii(ascii)) {
      throw Error('Input must be ASCII')
    }
    if (limit > 0 && ascii.length > limit) {
      throw Error('Ascii must be less than 32 bytes')
    }
    return text.encode(ascii)
  },

  decode: encodedAscii => {
    return text.decode(encodedAscii)
  }
}

export const hex = {
  encode: hex => {
    if (!isHex(hex)) {
      throw Error('Input must be a valid Hex')
    }
    if (hex.startsWith('0x')) {
      hex = hex.slice(2)
    }
    const bytes = []
    for (let c = 0; c < hex.length; c += 2)
      bytes.push(parseInt(hex.substr(c, 2), 16))
    return new Uint8Array(bytes)
  },
  decode: encodedHex => {
    const hex = []
    for (let i = 0; i < encodedHex.length; i++) {
      hex.push((encodedHex[i] >>> 4).toString(16))
      hex.push((encodedHex[i] & 0xf).toString(16))
    }
    return hex.join('')
  }
}
