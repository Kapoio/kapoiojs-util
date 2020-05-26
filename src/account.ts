const ethjsUtil = require('ethjs-util')
import * as assert from 'assert'
import * as secp256k1 from 'secp256k1'
const EdDSA = require('elliptic').eddsa;
import * as BN from 'bn.js'
import { zeros, bufferToHex, toBuffer } from './bytes'
import { keccak, keccak256, keccakFromString, rlphash } from './hash'
import { assertIsHexString, assertIsBuffer } from './helpers'

/**
 * Returns a zero address.
 */
export const zeroAddress = function(): string {
  const addressLength = 64
  const addr = zeros(addressLength)
  return bufferToHex(addr)
}

/**
 * Checks if the address is a valid. Accepts checksummed addresses too.
 */
export const isValidAddress = function(hexAddress: string): boolean {
  assertIsHexString(hexAddress)
  return /^0x[0-9a-fA-F]{128}$/.test(hexAddress)
}

/**
 * Checks if a given address is a zero address.
 */
export const isZeroAddress = function(hexAddress: string): boolean {
  assertIsHexString(hexAddress)
  const zeroAddr = zeroAddress()
  return zeroAddr === hexAddress
}

/**
 * Returns a checksummed address.
 *
 * If a eip1191ChainId is provided, the chainId will be included in the checksum calculation. This
 * has the effect of checksummed addresses for one chain having invalid checksums for others.
 * For more details, consult EIP-1191.
 *
 * WARNING: Checksums with and without the chainId will differ. As of 2019-06-26, the most commonly
 * used variation in Ethereum was without the chainId. This may change in the future.
 */
export const toChecksumAddress = function(hexAddress: string, eip1191ChainId?: number): string {
  assertIsHexString(hexAddress)
  const address = ethjsUtil.stripHexPrefix(hexAddress).toLowerCase()

  const prefix = eip1191ChainId !== undefined ? eip1191ChainId.toString() + '0x' : ''

  const hash = keccakFromString(prefix + address).toString('hex')
  let ret = '0x'

  for (let i = 0; i < address.length; i++) {
    if (parseInt(hash[i], 16) >= 8) {
      ret += address[i].toUpperCase()
    } else {
      ret += address[i]
    }
  }

  return ret
}

/**
 * Checks if the address is a valid checksummed address.
 *
 * See toChecksumAddress' documentation for details about the eip1191ChainId parameter.
 */
export const isValidChecksumAddress = function(
  hexAddress: string,
  eip1191ChainId?: number,
): boolean {
  return isValidAddress(hexAddress) && toChecksumAddress(hexAddress, eip1191ChainId) === hexAddress
}

/**
 * Generates an address of a newly created contract.
 * @param from The address which is creating this new address
 * @param nonce The nonce of the from account
 */
export const generateAddress = function(from: Buffer, nonce: Buffer): Buffer {
  assertIsBuffer(from)
  assertIsBuffer(nonce)
  const nonceBN = new BN(nonce)

  if (nonceBN.isZero()) {
    // in RLP we want to encode null in the case of zero nonce
    // read the RLP documentation for an answer if you dare
    return rlphash([from, null])
  }

  // Only take the lower 160bits of the hash
  return rlphash([from, Buffer.from(nonceBN.toArray())])
}

/**
 * Generates an address for a contract created using CREATE2.
 * @param from The address which is creating this new address
 * @param salt A salt
 * @param initCode The init code of the contract being created
 */
export const generateAddress2 = function(from: Buffer, salt: Buffer, initCode: Buffer): Buffer {
  assertIsBuffer(from)
  assertIsBuffer(salt)
  assertIsBuffer(initCode)

  assert(from.length === 64)
  assert(salt.length === 32)

  const address = keccak256(
    Buffer.concat([Buffer.from('ff', 'hex'), from, salt, keccak256(initCode)]),
  )

  return address
}

/**
 * Checks if the private key satisfies the rules of the curve secp256k1.
 */
export const isValidPrivate = function(privateKey: Buffer, isStealthAddress: boolean = true): boolean {
  let valid
  try {
    if(!isStealthAddress) {
      valid = secp256k1.privateKeyVerify(privateKey)
    }
    else {
      var ed = new EdDSA('ed25519')

      var key = ed.keyFromSecret(privateKey)
      valid = ed.isPoint(key.pub())
    }
  } catch (e) {
    if (e.message === 'Expected private key to be an Uint8Array with length 32') {
      valid = false
    } else {
      throw e
    }
  }

  return valid
}

/**
 * Checks if the public key satisfies the rules of the curve secp256k1
 * and the requirements of Ethereum.
 * @param publicKey The two points of an uncompressed key, unless sanitize is enabled
 * @param sanitize Accept public keys in other formats
 * @param isStealthAddress checks if its a contract identity address
 */
export const isValidPublic = function(publicKey: Buffer, sanitize: boolean = false, isStealthAddress: boolean = true): boolean {
  assertIsBuffer(publicKey)
  if (publicKey.length === 64) {
    // Convert to SEC1 for secp256k1
    if(!isStealthAddress) {
      return secp256k1.publicKeyVerify(Buffer.concat([Buffer.from([4]), publicKey]))
    }

  }

  if (!sanitize) {
    return false
  }

  if(isStealthAddress) {
    var ed = new EdDSA('ed25519')
    return ed.isPoint(publicKey)
  }
  else {
    return secp256k1.publicKeyVerify(publicKey)
  }
}

/**
 * Returns the ethereum address of a given public key.
 * Accepts "Ethereum public keys" and SEC1 encoded keys.
 * @param pubKey The two points of an uncompressed key, unless sanitize is enabled
 * @param sanitize Accept public keys in other formats
 */
export const pubToAddress = function(pubKey: Buffer, sanitize: boolean = false): Buffer {
  assertIsBuffer(pubKey)
  if (sanitize && pubKey.length !== 64) {
    pubKey = toBuffer(secp256k1.publicKeyConvert(pubKey, false).slice(1))
  }
  assert(pubKey.length === 64)
  // Only take the lower 160bits of the hash
  return keccak(pubKey)
}
export const publicToAddress = pubToAddress

/**
 * Returns the ethereum address of a given private key.
 *
 * @param privateKey A private key must be 256 bits wide
 * @param isStealthAddress checks if its a contract identity address
 */
export const privateToAddress = function(privateKey: Buffer, isStealthAddress: boolean = false): Buffer {
  return publicToAddress(privateToPublic(privateKey, isStealthAddress))
}

/**
 * Returns the ethereum public key of a given private key.
 * @param privateKey A private key must be 256 bits wide
 * @param isStealthAddress checks if its a contract identity address
 */
export const privateToPublic = function(privateKey: Buffer, isStealthAddress: boolean = false): Buffer {
  assertIsBuffer(privateKey)
  // skip the type flag and use the X, Y points
  if(!isStealthAddress) {
    return toBuffer(secp256k1.publicKeyCreate(privateKey, false).slice(1))
  }
  else {
    var ed = new EdDSA('ed25519')

    var key = ed.keyFromSecret(privateKey)
    return key.pub()
  }
}

/**
 * Converts a public key to the Ethereum format.
 */
export const importPublic = function(publicKey: Buffer): Buffer {
  assertIsBuffer(publicKey)
  if (publicKey.length !== 64) {
    publicKey = toBuffer(secp256k1.publicKeyConvert(publicKey, false).slice(1))
  }
  return publicKey
}
