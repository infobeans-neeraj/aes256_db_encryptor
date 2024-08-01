require 'rails/generators'
require 'rails/generators/base'

module Encryptor
  module Generators
    class PemFileGenerator < Rails::Generators::Base
      include AES256DBEncryptor::GlobalHelpers

      source_root File.expand_path('config', __dir__)

      def create_pem_file
        generate_pem_file_content
        say "Created config/keys_and_ivs.pem with generated keys and IVs.", :green
      end

      private

      def generate_pem_file_content
        key1, iv1 = generate_key_iv
        keys_and_ivs = { key1: key1, iv1: iv1}

        if double_encryption_mode_enabled?
          key2, iv2 = generate_key_iv
          keys_and_ivs.merge!({key2: key2, iv2: iv2})
        end

        encrypted_content = encrypt_data_with_master_key(keys_and_ivs.to_yaml) # keys_and_ivs.to_yaml
        write_pem_file(encrypted_content) unless File.exist?(pem_file_path)
      end

      def encrypt_data_with_master_key(data)
        master_key = fetch_master_key
        cipher = OpenSSL::Cipher::AES.new(256, :CBC)
        cipher.encrypt
        cipher.key = master_key
        iv = cipher.random_iv
        encrypted_data = cipher.update(data) + cipher.final
        Base64.encode64(iv + encrypted_data)
      end

      def generate_key_iv
        [AES256DBEncryptor.generate_aes_key, AES256DBEncryptor.generate_aes_iv]
      end

      def write_pem_file(content)
        File.open(pem_file_path, 'w') do |file|
          file.flock(File::LOCK_EX)  # Exclusive lock
          file.write("-----BEGIN KEY-VALUE PAIRS-----\n")
          file.write(content)
          file.write("-----END KEY-VALUE PAIRS-----\n")
        end
      end

      def pem_file_path
        AES256DBEncryptor::GlobalHelpers::PEM_FILE_PATH
      end
    end
  end
end
