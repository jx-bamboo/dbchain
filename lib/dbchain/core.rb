require 'base64'
require 'OpenSSL'
require 'bip_mnemonic'
require 'bitcoin'

COSMOS_PREFIX = 'cosmos'
COSMOS_PATH = "m/44'/118'/0'/0/0"

#生成助记词 BipMnemonic.to_mnemonic(bits: 128)
#生成熵 BipMnemonic.to_entropy(mnemonic: words)
#生成种子 BipMnemonic.to_seed(mnemonic: words)
#转成16进制 a.unpack('H*')

#待解决方法
# base64ToBytes
# bip32FromSeed
# bip39MnemonicToSeed
# bech32Encode

module Dbchain
  class Core

    def sha512(bytes)
      Digest::SHA256.hexdigest bytes
    end

    def sha256(bytes)
       Digest::SHA256.hexdigest bytes
    end

    def ripemd160(bytes)
      Digest::RMD160.hexdigest bytes
    end

    def bip32FromSeed(prams)
    end

    def bip39MnemonicToSeed(prams1, prams2)
    end

    def bech32Encode(prams1, prams2)
    end

    # * Derive a keypair from a BIP32 master key.
    # * @param   masterKey - BIP32 master key
    # * @param   path      - BIP32 derivation path, defaulting to {@link COSMOS_PATH|`COSMOS_PATH`}
    # *
    # * @returns derived public and private key pair
    # * @throws  will throw if a private key cannot be derived
    def createKeyPairFromMasterKey(masterKey, path = COSMOS_PATH)
      privateKey = masterKey.derivePath(path)
      if(!privateKey)
          raise 'could not derive private key'
      end
      publicKey = secp256k1PublicKeyCreate(privateKey, true)
      return {
          privateKey,
          publicKey
      }
    end

    # * Create a {@link Wallet|`Wallet`} from a BIP32 master key.
    # * @param   masterKey - BIP32 master key
    # * @param   prefix    - Bech32 human readable part, defaulting to {@link COSMOS_PREFIX|`COSMOS_PREFIX`}
    # * @param   path      - BIP32 derivation path, defaulting to {@link COSMOS_PATH|`COSMOS_PATH`}
    # * @returns a keypair and address derived from the provided master key
    def createWalletFromMasterKey (masterKey, prefix = COSMOS_PREFIX, path = COSMOS_PATH)
      privateKey, publicKey = createKeyPairFromMasterKey(masterKey, path)
      address = createAddress(publicKey, prefix)
      return {
        privateKey,
        publicKey,
        address
      }
    end

    # * Create a {@link Wallet|`Wallet`} from a known mnemonic.
    # * @param   mnemonic - BIP39 mnemonic seed
    # * @param   password - optional password from {@link https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed|the BIP39 spec}
    # * @param   prefix   - Bech32 human readable part, defaulting to {@link COSMOS_PREFIX|`COSMOS_PREFIX`}
    # * @param   path     - BIP32 derivation path, defaulting to {@link COSMOS_PATH|`COSMOS_PATH`}
    # * @returns a keypair and address derived from the provided mnemonic
    # * @throws  will throw if the provided mnemonic is invalid
    def createMasterKeyFromMnemonic(mnemonic, password)
      seed = bip39MnemonicToSeed mnemonic, password
      bip32FromSeed seed
    end

    # * Create a {@link Wallet|`Wallet`} from a known mnemonic.
    # * @param   mnemonic - BIP39 mnemonic seed
    # * @param   password - optional password from {@link https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed|the BIP39 spec}
    # * @param   prefix   - Bech32 human readable part, defaulting to {@link COSMOS_PREFIX|`COSMOS_PREFIX`}
    # * @param   path     - BIP32 derivation path, defaulting to {@link COSMOS_PATH|`COSMOS_PATH`}
    # * @returns a keypair and address derived from the provided mnemonic
    # * @throws  will throw if the provided mnemonic is invalid
    def createWalletFromMnemonic(mnemonic, password, prefix = COSMOS_PREFIX, path = COSMOS_PATH)
      masterKey = createMasterKeyFromMnemonic mnemonic, password
      createWalletFromMasterKey masterKey, prefix, path
    end

    # * Derive a Bech32 address from a public key.
    # * @param   publicKey - public key bytes
    # * @param   prefix    - Bech32 human readable part, defaulting to {@link COSMOS_PREFIX|`COSMOS_PREFIX`}
    # * @returns Bech32-encoded address
    def createAddress(publicKey, prefix = COSMOS_PREFIX)
      hash1 = sha256 publicKey
      hash2 = ripemd160 hash1
      words = bech32ToWords hash2
      bech32Encode prefix, words
    end

    # * Create a transaction with metadata for signing.
    # * @param   tx   - unsigned transaction
    # * @param   meta - metadata for signing
    # * @returns a transaction with metadata for signing
    def createSignMsg(tx, meta)
      {
        account_number: meta.account_number,
        chain_id: meta.chain_id,
        fee: tx.fee,
        memo: tx.memo,
        msgs: tx.msg,
        sequence: meta.sequence
      }
    end

    # * Create a signature from a {@link StdSignMsg|`StdSignMsg`}.
    # *
    # * @param   signMsg - transaction with metadata for signing
    # * @param   keyPair - public and private key pair (or {@link Wallet|`Wallet`})
    # *
    # * @returns a signature and corresponding public key
    def createSignature(signMsg, { privateKey, publicKey })
      signatureObj = createSignatureBytes(signMsg, privateKey)
      {
        signature: bytesToBase64(signatureObj.signature), #node方法
        pub_key:   {
            type:  'tendermint/PubKeySecp256k1',
            value: bytesToBase64(publicKey)
        }
      }
    end

    # * Sign a transaction.
    # * This combines the {@link Tx|`Tx`} and {@link SignMeta|`SignMeta`} into a {@link StdSignMsg|`StdSignMsg`}, signs it,
    # * and attaches the signature to the transaction. If the transaction is already signed, the signature will be
    # * added to the existing signatures.
    # * @param   tx      - transaction (signed or unsigned)
    # * @param   meta    - metadata for signing
    # * @param   keyPair - public and private key pair (or {@link Wallet|`Wallet`})
    # * @returns a signed transaction
    def signTx(tx, meta, keyPair)
      signMsg    = createSignMsg(tx, meta)
      signature  = createSignature(signMsg, keyPair)
      signatures = ('signatures' in tx) ? [...tx.signatures, signature] : [signature]

      return {
          ...tx,
          signatures
      }
    end

    #secp256k1Sign Buffer ???
    # * Sign the sha256 hash of `bytes` with a secp256k1 private key.
    # *
    # * @param   bytes      - bytes to hash and sign
    # * @param   privateKey - private key bytes
    # *
    # * @returns signed hash of the bytes
    # * @throws  will throw if the provided private key is invalid
    def sign(bytes, privateKey)
      hash = sha256 bytes
      signature  = secp256k1Sign(hash, Buffer.from(privateKey))
    end

    # * Create signature bytes from a {@link StdSignMsg|`StdSignMsg`}.
    # *
    # * @param   signMsg    - transaction with metadata for signing
    # * @param   privateKey - private key bytes
    # *
    # * @returns signature bytes
    def createSignatureBytes(signMsg, privateKey)
      bytes = toCanonicalJSONBytes signMsg
      sign bytes, privateKey
    end

    # /**
    #  * Verify a {@link StdSignMsg|`StdSignMsg`} against multiple {@link StdSignature|`StdSignature`}s.
    #  *
    #  * @param   signMsg    - transaction with metadata for signing
    #  * @param   signatures - signatures
    #  *
    #  * @returns `true` if all signatures are valid and match, `false` otherwise or if no signatures were provided
    #  */
    def verifySignatures(signMsg, signatures)
        if signatures.length > 0
            return signatures.every(function (signature) {
                return verifySignature(signMsg, signature);
            });
        else
            return false
        end
    end

     #    /**
     # * Verify a {@link StdSignMsg|`StdSignMsg`} against a {@link StdSignature|`StdSignature`}.
     # *
     # * @param   signMsg   - transaction with metadata for signing
     # * @param   signature - signature
     # *
     # * @returns `true` if the signature is valid and matches, `false` otherwise
     # */
    def verifySignature(signMsg, signature)
        signatureBytes = base64ToBytes(signature.signature)
        publicKey = base64ToBytes(signature.pub_key.value)
        return verifySignatureBytes(signMsg, signatureBytes, publicKey)
    end

    # * Verify a signature against a {@link StdSignMsg|`StdSignMsg`}.
    # * @param   signMsg   - transaction with metadata for signing
    # * @param   signature - signature bytes
    # * @param   publicKey - public key bytes
    # * @returns `true` if the signature is valid and matches, `false` otherwise
    def verifySignatureBytes(signMsg, signature, publicKey)
        bytes = toCanonicalJSONBytes signMsg
        hash = sha256 bytes
        secp256k1Verify(hash, Buffer.from(signature), Buffer.from(publicKey))
    end

    # * Prepare a signed transaction for broadcast.
    # * @param   tx   - signed transaction
    # * @param   mode - broadcast mode
    # * @returns a transaction broadcast
    def createBroadcastTx(tx, mode = BROADCAST_MODE_SYNC)
      return {
        tx,
        mode
      }
    end






  end
end
