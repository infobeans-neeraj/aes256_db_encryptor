# lib/double_aes256_encryption_gem/single_encryption.rb

require 'openssl'
require 'base64'

module AES256DBEncryptor
  module SingleEncryption
    include AES256DBEncryptor::GlobalHelpers
    extend self

    def encrypt(plaintext)
      keys_and_ivs = load_keys_and_ivs
      encrypted_data = encrypt_data(plaintext, keys_and_ivs[:key1], keys_and_ivs[:iv1])
      Base64.strict_encode64(encrypted_data)
    rescue StandardError => e
      Rails.logger.info("An error occurred while encrypting data: #{e.message}")
      plaintext
    end

    def decrypt(ciphertext)
      keys_and_ivs = load_keys_and_ivs
      plaintext = decrypt_data(ciphertext, keys_and_ivs[:key1], keys_and_ivs[:iv1])
      plaintext.force_encoding('UTF-8')
    rescue StandardError => e
      Rails.logger.info("An error occurred while decrypting data: #{e.message}")
      ciphertext
    end
  end
end
