# frozen_string_literal: true

require_relative "aes256_db_encryptor/version"
require_relative "aes256_db_encryptor/configuration"
require_relative "aes256_db_encryptor/global_helpers"
require 'active_support/concern'
require 'active_record'

# Load the generator
require "aes256_db_encryptor/generators/pem_file_generator"

module AES256DBEncryptor
  extend ActiveSupport::Concern
  autoload :DoubleEncryption, 'aes256_db_encryptor/double_encryption'
  autoload :SingleEncryption, 'aes256_db_encryptor/single_encryption'

  class << self
    attr_accessor :encryption_mode

    def configure
      yield self
    end

    def encryption_mode
      @encryption_mode || :double
    end

    def generate_aes_key
      # Generate a random AES-256 key
      encryption_key = OpenSSL::Cipher.new('AES-256-CBC').random_key

      # Base64 encode the encryption key for storage
      encoded_key = Base64.strict_encode64(encryption_key)
    end

    def generate_aes_iv
      # Generate a random AES-256 iv
      encryption_iv = OpenSSL::Cipher.new('AES-256-CBC').random_iv

      # Base64 encode the encryption iv for storage
      encoded_iv = Base64.strict_encode64(encryption_iv)
    end
  end

  class_methods do
    def aes_encrypt(*attributes)
      define_method(:encrypt_attributes) do
        attributes.each do |attr|
          value = self[attr]
          if AES256DBEncryptor.encryption_mode == :double
            self[attr] = AES256DBEncryptor::DoubleEncryption.encrypt(value) if value.present?
          else
            self[attr] = AES256DBEncryptor::SingleEncryption.encrypt(value) if value.present?
          end
        end
      end

      define_method(:decrypt_attributes) do
        attributes.each do |attr|
          value = self[attr]
          if AES256DBEncryptor.encryption_mode == :double
            self[attr] = AES256DBEncryptor::DoubleEncryption.decrypt(value) if value.present?
          else
            self[attr] = AES256DBEncryptor::SingleEncryption.decrypt(value) if value.present?
          end
        end
      end

      before_save :encrypt_attributes
      after_find :decrypt_attributes
    end
  end
end

ActiveRecord::Base.send(:include, AES256DBEncryptor)

require 'aes256_db_encryptor/double_encryption'
require 'aes256_db_encryptor/single_encryption'

# Default configuration
AES256DBEncryptor.configure do |config|
  config.encryption_mode = :single
end
