# spec/aes256_db_encryptor_spec.rb

require 'spec_helper'
require 'aes256_db_encryptor'

RSpec.describe AES256DBEncryptor do
  describe '.encrypt and .decrypt' do
    context 'when encryption_mode is :double' do
      before do
        AES256DBEncryptor.configure { |config| config.encryption_mode = :double }
        AES256DBEncryptor::Configuration.setup do
          self.encryption_key = AES256DBEncryptor.generate_aes_key
          self.encryption_iv = AES256DBEncryptor.generate_aes_iv
          self.second_encryption_key = AES256DBEncryptor.generate_aes_key
          self.second_encryption_iv = AES256DBEncryptor.generate_aes_iv
        end
      end

      it 'correctly encrypts and decrypts data using double encryption' do
        plaintext = 'secret data'
        encrypted_data = AES256DBEncryptor::DoubleEncryption.encrypt(plaintext)
        decrypted_data = AES256DBEncryptor::DoubleEncryption.decrypt(encrypted_data)

        expect(decrypted_data).to eq(plaintext)
      end
    end

    context 'when encryption_mode is :single' do
      before do
        AES256DBEncryptor.configure { |config| config.encryption_mode = :single }
        AES256DBEncryptor::Configuration.setup do
          self.encryption_key = AES256DBEncryptor.generate_aes_key
          self.encryption_iv = AES256DBEncryptor.generate_aes_iv
        end
      end

      it 'correctly encrypts and decrypts data using single encryption' do
        plaintext = 'secret data'
        encrypted_data = AES256DBEncryptor::SingleEncryption.encrypt(plaintext)
        decrypted_data = AES256DBEncryptor::SingleEncryption.decrypt(encrypted_data)

        expect(decrypted_data).to eq(plaintext)
      end
    end
  end
end
