# lib/double_aes256_encryption_gem/double_encryption.rb

require 'openssl'
require 'base64'

module AES256DBEncryptor
  module DoubleEncryption
    include AES256DBEncryptor::GlobalHelpers
    extend self

    def encrypt(plaintext)
      keys_and_ivs = load_keys_and_ivs
      cipher = OpenSSL::Cipher.new('AES-256-CBC')
      cipher.encrypt
      cipher.key = keys_and_ivs[:key1]
      cipher.iv = keys_and_ivs[:iv1]

      encrypted_data = cipher.update(plaintext) + cipher.final

      # Encrypt again with the second key
      second_cipher = OpenSSL::Cipher.new('AES-256-CBC')
      second_cipher.encrypt
      second_cipher.key = keys_and_ivs[:key2]
      second_cipher.iv = keys_and_ivs[:iv2]

      doubly_encrypted_data = second_cipher.update(encrypted_data) + second_cipher.final

      Base64.strict_encode64(doubly_encrypted_data)
    rescue StandardError => e
      plaintext
    end

    def decrypt(ciphertext)
      keys_and_ivs = load_keys_and_ivs
      decipher = OpenSSL::Cipher.new('AES-256-CBC')
      decipher.decrypt
      decipher.key = keys_and_ivs[:key2] # Decrypt with the second key first
      decipher.iv = keys_and_ivs[:iv2]

      decrypted_data = decipher.update(Base64.strict_decode64(ciphertext)) + decipher.final

      # Decrypt again with the first key
      second_decipher = OpenSSL::Cipher.new('AES-256-CBC')
      second_decipher.decrypt
      second_decipher.key = keys_and_ivs[:key1]
      second_decipher.iv = keys_and_ivs[:iv1]

      plaintext = second_decipher.update(decrypted_data) + second_decipher.final
      plaintext.force_encoding('UTF-8')
    rescue StandardError => e
      ciphertext
    end
  end
end
