# lib/double_aes256_encryption_gem/single_encryption.rb

require 'openssl'
require 'base64'

module AES256DBEncryptor
  module SingleEncryption
    extend self

    def encrypt(plaintext)
      cipher = OpenSSL::Cipher.new('AES-256-CBC')
      cipher.encrypt
      cipher.key = AES256DBEncryptor::Configuration.encryption_key
      cipher.iv = AES256DBEncryptor::Configuration.encryption_iv

      encrypted_data = cipher.update(plaintext) + cipher.final
      Base64.strict_encode64(encrypted_data)
    rescue StandardError => e
      plaintext
    end

    def decrypt(ciphertext)
      decipher = OpenSSL::Cipher.new('AES-256-CBC')
      decipher.decrypt
      decipher.key = AES256DBEncryptor::Configuration.encryption_key
      decipher.iv = AES256DBEncryptor::Configuration.encryption_iv

      plaintext = decipher.update(Base64.strict_decode64(ciphertext)) + decipher.final
      plaintext.force_encoding('UTF-8')
    rescue StandardError => e
      ciphertext
    end
  end
end
