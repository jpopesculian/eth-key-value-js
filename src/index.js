import getWeb3, { setProvider } from './web3'
import Symmetric from './crypto/Symmetric'
import EthCrypto from 'eth-crypto'
import KeyValueStore from './KeyValueStore'
import { ascii, json, text } from './encoder'
import msgpack from 'msgpack-lite'
import _ from 'lodash/fp'

const IDENTITY_1 = {
  address: '0xc85Bd11BA90F629bdEdAc15a406b6801F0a991A4',
  privateKey: '0xe57b73d530d8f3136f892b587f137d9e24f4ddede02037182aa66f0e8c5dea81',
  publicKey: 'bacb473a3fd348e263cb5d23900cdc98711b6ddf3c70d089728835e4023ffae8da00abd825593410e1b5d627e3ddd3195f864892f7546df39a27a57b44dd836e'
}
const IDENTITY_2 = {
  address: '0x3AA62f3be3874A1d044da4d180a8FC83A2dE6619',
  privateKey: '0xc0358077d9adca88ef02d224a36e9f9a4d57ff4196160b82d97bff6543086955',
  publicKey: '6e858bab73919406cd689fed578dcb84abe614ce0790e12e79d6e01b79902d8ddac4ea54dbbd04a4264319f02d8e050a092b4ddb4b3140c1ac5d8acb57e41318'
}
const IDENTITY_3 = {
  address: '0x573A42e255500BFd3E93543b02EBf801d3170A18',
  privateKey: '0x4e6c7da648cf0e0a7f8c01508ce0b9ff47544e7fb2300c6b9db4bc4905e2ef67',
  publicKey: '1c57ec8bd3a27de499cf47b8b96aa90ea4c56297782612d13069da9c3da279c2709fe1de64b2a2773e3f1e3954a309d89d647196f1a50d0d8768dd8380a4c5f3'
}

window.id1 = IDENTITY_1
window.id2 = IDENTITY_2
window.id3 = IDENTITY_3
window.EthCrypto = EthCrypto
window.Symmetric = Symmetric
window.KeyValueStore = KeyValueStore
window.ascii = ascii
window.json = json
window.text = text
window.msgpack = msgpack
window._ = _

const init = async () => {
  const { web3 } = await getWeb3()
  const provider = setProvider(web3, { development: true })
  const accounts = await web3.eth.getAccounts()
  window.id1.account = accounts[0]
  window.id2.account = accounts[1]
  window.id3.account = accounts[3]
  window.store1 = await KeyValueStore.build(null, accounts[0], id1.privateKey)
  window.store2 = await KeyValueStore.build(null, accounts[1], id2.privateKey)
  window.store3 = await KeyValueStore.build(null, accounts[2], id3.privateKey)

  const k = 'hello'
  const v = 'hi'

  await store1.setPublicKey(id1.publicKey)
  await store2.setPublicKey(id2.publicKey)
  await store3.setPublicKey(id3.publicKey)

  try {
    await store1.create(k, v)
  } catch (e) {
    console.warn('Already created')
  }
  await store1.write(k, v)

  await store1.addAdmin(k, store2.sender)
  await store2.grantReadAccess(k, store3.sender)
  console.log('ready')
}

init()
