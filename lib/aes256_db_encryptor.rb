# frozen_string_literal: true

require_relative "aes256_db_encryptor/version"

module AES256DBEncryptor
  class << self
    def encrypt(data, key)
      cipher = OpenSSL::Cipher.new('AES-256-CBC')
      cipher.encrypt
      cipher.key = Digest::SHA256.digest(key)
      iv = cipher.random_iv
      encrypted = cipher.update(data) + cipher.final
      Base64.strict_encode64(iv + encrypted)
    end

    def decrypt(encrypted_data, key)
      encrypted_data = Base64.strict_decode64(encrypted_data)
      iv = encrypted_data.slice!(0, 16)
      decipher = OpenSSL::Cipher.new('AES-256-CBC')
      decipher.decrypt
      decipher.key = Digest::SHA256.digest(key)
      decipher.iv = iv
      decipher.update(encrypted_data) + decipher.final
    end
  end
end
