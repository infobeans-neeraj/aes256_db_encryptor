# lib/double_aes256_encryption_gem/double_encryption.rb

require 'openssl'
require 'base64'

module AES256DBEncryptor
  module DoubleEncryption
    include AES256DBEncryptor::GlobalHelpers
    extend self

    def encrypt(plaintext)
      keys_and_ivs = load_keys_and_ivs
      encrypted_data = encrypt_data(plaintext, keys_and_ivs[:key1], keys_and_ivs[:iv1])

      # Encrypt again with the second key
      doubly_encrypted_data = encrypt_data(encrypted_data, keys_and_ivs[:key2], keys_and_ivs[:iv2])

      Base64.strict_encode64(doubly_encrypted_data)
    rescue StandardError => e
      Rails.logger.info("An error occurred while encrypting data: #{e.message}")
      plaintext
    end

    def decrypt(ciphertext)
      keys_and_ivs = load_keys_and_ivs

      # Decrypt with the second key first
      decrypted_data = decrypt_data(ciphertext, keys_and_ivs[:key2], keys_and_ivs[:iv2])

      # Decrypt again with the first key
      plaintext = decrypt_data(decrypted_data, keys_and_ivs[:key1], keys_and_ivs[:iv1], method: 1)
      plaintext.force_encoding('UTF-8')
    rescue StandardError => e
      Rails.logger.info("An error occurred while decrypting data: #{e.message}")
      ciphertext
    end
  end
end
