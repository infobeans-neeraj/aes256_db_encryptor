# lib/double_aes256_encryption_gem/single_encryption.rb

require 'openssl'
require 'base64'

module AES256DBEncryptor
  module SingleEncryption
    extend self

    def encrypt(plaintext)
      cipher = OpenSSL::Cipher.new('AES-256-CBC')
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv

      encrypted_data = cipher.update(plaintext) + cipher.final
      Base64.strict_encode64(encrypted_data)
    rescue StandardError => e
      plaintext
    end

    def decrypt(ciphertext)
      decipher = OpenSSL::Cipher.new('AES-256-CBC')
      decipher.decrypt
      decipher.key = key
      decipher.iv = iv

      plaintext = decipher.update(Base64.strict_decode64(ciphertext)) + decipher.final
      plaintext.force_encoding('UTF-8')
    rescue StandardError => e
      ciphertext
    end
  end
end
