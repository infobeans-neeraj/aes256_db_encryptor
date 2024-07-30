module AES256DBEncryptor
  module GlobalHelpers
    extend ActiveSupport::Concern
    MASTER_KEY_ENV_VAR = 'AES256_MASTER_KEY'
    PEM_FILE_PATH = 'config/keys_and_ivs.pem'

    def fetch_master_key
      raise "Master key environment variable #{MASTER_KEY_ENV_VAR} not set" unless ENV[MASTER_KEY_ENV_VAR]
      Base64.decode64(ENV['AES256_MASTER_KEY'])
    end

    def load_keys_and_ivs
      if File.exist?(GlobalHelpers::PEM_FILE_PATH)
        load_keys_and_ivs_from_local_file
      else
        load_keys_and_ivs_from_env
      end
    end

    def load_keys_and_ivs_from_local_file
      pem_content = File.read(GlobalHelpers::PEM_FILE_PATH)
      encrypted_content = pem_content[/-----BEGIN KEY-VALUE PAIRS-----\n(.*?)\n-----END KEY-VALUE PAIRS-----/m, 1]
      decrypted_content = decrypt_data_with_master_key(encrypted_content)
      YAML.load(decrypted_content).transform_values { |v| Base64.decode64(v) }
    end

    def load_keys_and_ivs_from_env
      keys_and_ivs_hash = {}
      if AES256DBEncryptor.encryption_mode == :double
        keys_and_ivs_hash = {
          key1: AES256DBEncryptor::Configuration.encryption_key,
          iv1: AES256DBEncryptor::Configuration.encryption_iv,
          key2: AES256DBEncryptor::Configuration.second_encryption_key,
          iv2: AES256DBEncryptor::Configuration.second_encryption_iv
        }
      else
        keys_and_ivs_hash = {
          key1: AES256DBEncryptor::Configuration.encryption_key,
          iv1: AES256DBEncryptor::Configuration.encryption_iv
        }
      end

      return keys_and_ivs_hash
    end

    def decrypt_data_with_master_key(encrypted_data)
      master_key = fetch_master_key
      decoded_data = Base64.decode64(encrypted_data)
      iv = decoded_data[0, 16]
      encrypted_content = decoded_data[16..-1]

      cipher = OpenSSL::Cipher::AES.new(256, :CBC)
      cipher.decrypt
      cipher.key = master_key
      cipher.iv = iv
      cipher.update(encrypted_content) + cipher.final
    end
  end
end
