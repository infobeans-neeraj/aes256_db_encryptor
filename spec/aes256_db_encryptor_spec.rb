# spec/aes256_db_encryptor_spec.rb

require 'spec_helper'
require 'aes256_db_encryptor'

RSpec.describe AES256DBEncryptor do
  describe '.encrypt and .decrypt' do
    context 'when encryption_mode is :double' do
      before do
        AES256DBEncryptor.configure { |config| config.encryption_mode = :double }
      end

      it 'correctly encrypts and decrypts data using double encryption' do
        plaintext = 'secret data'
        key1 = AES256DBEncryptor.generate_aes_key
        key2 = AES256DBEncryptor.generate_aes_key
        iv = AES256DBEncryptor.generate_aes_iv

        encrypted_data = AES256DBEncryptor::DoubleEncryption.encrypt(plaintext, key1, key2, iv)
        decrypted_data = AES256DBEncryptor::DoubleEncryption.decrypt(encrypted_data, key1, key2, iv)

        expect(decrypted_data).to eq(plaintext)
      end
    end

    context 'when encryption_mode is :single' do
      before do
        AES256DBEncryptor.configure { |config| config.encryption_mode = :single }
      end

      it 'correctly encrypts and decrypts data using single encryption' do
        plaintext = 'secret data'
        key = AES256DBEncryptor.generate_aes_key
        iv = AES256DBEncryptor.generate_aes_iv

        encrypted_data = AES256DBEncryptor::SingleEncryption.encrypt(plaintext, key, iv)
        decrypted_data = AES256DBEncryptor::SingleEncryption.decrypt(encrypted_data, key, iv)

        expect(decrypted_data).to eq(plaintext)
      end
    end
  end
end
