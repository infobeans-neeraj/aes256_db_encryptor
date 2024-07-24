# lib/double_aes256_encryption_gem/double_encryption.rb

require 'openssl'
require 'base64'

module AES256DBEncryptor
  module DoubleEncryption
    extend self

    def encrypt(plaintext)
      cipher = OpenSSL::Cipher.new('AES-256-CBC')
      cipher.encrypt
      cipher.key = AES256DBEncryptor::Configuration.encryption_key
      cipher.iv = AES256DBEncryptor::Configuration.encryption_iv

      encrypted_data = cipher.update(plaintext) + cipher.final

      # Encrypt again with the second key
      second_cipher = OpenSSL::Cipher.new('AES-256-CBC')
      second_cipher.encrypt
      second_cipher.key = AES256DBEncryptor::Configuration.second_encryption_key
      second_cipher.iv = AES256DBEncryptor::Configuration.second_encryption_iv

      doubly_encrypted_data = second_cipher.update(encrypted_data) + second_cipher.final

      Base64.strict_encode64(doubly_encrypted_data)
    rescue StandardError => e
      plaintext
    end

    def decrypt(ciphertext)
      decipher = OpenSSL::Cipher.new('AES-256-CBC')
      decipher.decrypt
      decipher.key = AES256DBEncryptor::Configuration.second_encryption_key # Decrypt with the second key first
      decipher.iv = AES256DBEncryptor::Configuration.second_encryption_iv

      decrypted_data = decipher.update(Base64.strict_decode64(ciphertext)) + decipher.final

      # Decrypt again with the first key
      second_decipher = OpenSSL::Cipher.new('AES-256-CBC')
      second_decipher.decrypt
      second_decipher.key = AES256DBEncryptor::Configuration.encryption_key
      second_decipher.iv = AES256DBEncryptor::Configuration.encryption_iv

      plaintext = second_decipher.update(decrypted_data) + second_decipher.final
      plaintext.force_encoding('UTF-8')
    rescue StandardError => e
      ciphertext
    end
  end
end
