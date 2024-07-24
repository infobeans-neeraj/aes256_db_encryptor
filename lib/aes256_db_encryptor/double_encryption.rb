# lib/double_aes256_encryption_gem/double_encryption.rb

require 'openssl'
require 'base64'

module AES256DBEncryptor
  module DoubleEncryption
    extend self

    def encrypt(plaintext, key1, key2, iv)
      cipher = OpenSSL::Cipher.new('AES-256-CBC')
      cipher.encrypt
      cipher.key = key1
      cipher.iv = iv

      encrypted_data = cipher.update(plaintext) + cipher.final

      # Encrypt again with the second key
      second_cipher = OpenSSL::Cipher.new('AES-256-CBC')
      second_cipher.encrypt
      second_cipher.key = key2
      second_cipher.iv = iv

      doubly_encrypted_data = second_cipher.update(encrypted_data) + second_cipher.final

      Base64.strict_encode64(doubly_encrypted_data)
    end

    def decrypt(ciphertext, key1, key2, iv)
      decipher = OpenSSL::Cipher.new('AES-256-CBC')
      decipher.decrypt
      decipher.key = key2 # Decrypt with the second key first
      decipher.iv = iv

      decrypted_data = decipher.update(Base64.strict_decode64(ciphertext)) + decipher.final

      # Decrypt again with the first key
      second_decipher = OpenSSL::Cipher.new('AES-256-CBC')
      second_decipher.decrypt
      second_decipher.key = key1
      second_decipher.iv = iv

      plaintext = second_decipher.update(decrypted_data) + second_decipher.final
      plaintext.force_encoding('UTF-8')
    end
  end
end
