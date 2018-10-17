const setGlobal = object => {
  for (const key in object) {
    if (object.hasOwnProperty(key)) {
      window[key] = object[key]
      global[key] = object[key]
    }
  }
}

const loaded = () =>
  new Promise((resolve, reject) => {
    window.addEventListener('load', () => {
      resolve()
    })
  })

const polyfillHttpProvider = (...libraries) => {
  for (let library of libraries) {
    library.providers.HttpProvider.prototype.sendAsync =
      library.providers.HttpProvider.prototype.send
  }
}

const validWeb3 = web3 => {
  if (!web3 || !(web3.version && typeof web3.version === 'string')) {
    return false
  }
  return web3.version.match(/^1.0.*/) !== null
}

export const setProvider = (web3, { development }) => {
  let provider = web3.currentProvider
  if (development) {
    provider = new web3.providers.HttpProvider('http://localhost:9545')
  } else {
    provider = new web3.providers.HttpProvider()
  }
  web3.setProvider(provider)
  return provider
}

export default async () => {
  await loaded()
  let web3 = window.web3
  let Web3 = window.Web3
  if (!validWeb3(web3)) {
    Web3 = (await import('web3')).default
    web3 = new Web3()
  }
  polyfillHttpProvider(web3, Web3)
  setGlobal({ web3, Web3 })
  return {
    web3,
    Web3
  }
}
