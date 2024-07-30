# lib/double_aes256_encryption_gem/single_encryption.rb

require 'openssl'
require 'base64'

module AES256DBEncryptor
  module SingleEncryption
    include AES256DBEncryptor::GlobalHelpers
    extend self

    def encrypt(plaintext)
      keys_and_ivs = load_keys_and_ivs
      cipher = OpenSSL::Cipher.new('AES-256-CBC')
      cipher.encrypt
      cipher.key = keys_and_ivs[:key1]
      cipher.iv = keys_and_ivs[:iv1]

      encrypted_data = cipher.update(plaintext) + cipher.final
      Base64.strict_encode64(encrypted_data)
    rescue StandardError => e
      plaintext
    end

    def decrypt(ciphertext)
      keys_and_ivs = load_keys_and_ivs
      decipher = OpenSSL::Cipher.new('AES-256-CBC')
      decipher.decrypt
      decipher.key = keys_and_ivs[:key1]
      decipher.iv = keys_and_ivs[:iv1]

      plaintext = decipher.update(Base64.strict_decode64(ciphertext)) + decipher.final
      plaintext.force_encoding('UTF-8')
    rescue StandardError => e
      ciphertext
    end
  end
end
