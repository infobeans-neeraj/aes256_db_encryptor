require 'active_support/concern'

module AES256DBEncryptor
  module ActiveRecordExtension
    extend ActiveSupport::Concern

    included do
      before_save :encrypt_sensitive_data
      after_save :decrypt_sensitive_data

      def encrypt_sensitive_data
        sensitive_attributes.each do |attr|
          if self[attr].present?
            self[attr] = AES256DBEncryptor.encrypt(self[attr], Rails.application.secrets.secret_key_base)
          end
        end
      end

      def decrypt_sensitive_data
        sensitive_attributes.each do |attr|
          if self[attr].present?
            self[attr] = AES256DBEncryptor.decrypt(self[attr], Rails.application.secrets.secret_key_base)
          end
        end
      end

      private

      def sensitive_attributes
        # Define which attributes you want to encrypt/decrypt
        # For example:
        # [:email, :phone_number]
        []
      end
    end
  end
end

ActiveSupport.on_load(:active_record) do
  include AES256DBEncryptor::ActiveRecordExtension
end