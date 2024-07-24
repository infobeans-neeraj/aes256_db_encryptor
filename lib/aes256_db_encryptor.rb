# frozen_string_literal: true

require_relative "aes256_db_encryptor/version"
require 'active_support/concern'
require 'active_record'

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
      OpenSSL::Cipher.new('AES-256-CBC').random_key
    end

    def generate_aes_iv
      OpenSSL::Cipher.new('AES-256-CBC').random_iv
    end
  end

  class_methods do
    def aes_encrypt(*attributes)
      define_method(:encrypt_attributes) do
        attributes.each do |attr|
          value = self[attr]
          if AES256DBEncryptor.encryption_mode == :double
            self[attr] = AES256DBEncryptor::DoubleEncryption.encrypt(value, encryption_key1, encryption_key2, iv) if value.present?
          else
            self[attr] = AES256DBEncryptor::SingleEncryption.encrypt(value, encryption_key, iv) if value.present?
          end
        end
      end

      define_method(:decrypt_attributes) do
        attributes.each do |attr|
          value = self[attr]
          if AES256DBEncryptor.encryption_mode == :double
            self[attr] = AES256DBEncryptor::DoubleEncryption.decrypt(value, encryption_key1, encryption_key2, iv) if value.present?
          else
            self[attr] = AES256DBEncryptor::SingleEncryption.decrypt(value, encryption_key, iv) if value.present?
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
