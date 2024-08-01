module AES256DBEncryptor
  module GlobalHelpers
    extend ActiveSupport::Concern
    MASTER_KEY_ENV_VAR = 'AES_MASTER_KEY'
    PEM_FILE_PATH = 'config/keys_and_ivs.pem'
    CIPHER_METHOD = 'AES-256-CBC'

    def fetch_master_key
      raise "Master key environment variable #{MASTER_KEY_ENV_VAR} not set" unless ENV[MASTER_KEY_ENV_VAR]
      Base64.decode64(ENV[MASTER_KEY_ENV_VAR])
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
    rescue StandardError => e
      Rails.logger.info("An error occurred while loading details from pem file: #{e.message}")
    end

    def load_keys_and_ivs_from_env
      keys_and_ivs_hash = {
        key1: AES256DBEncryptor::Configuration.encryption_key,
        iv1: AES256DBEncryptor::Configuration.encryption_iv
      }

      keys_and_ivs_hash.merge!({
        key2: AES256DBEncryptor::Configuration.second_encryption_key,
        iv2: AES256DBEncryptor::Configuration.second_encryption_iv
      }) if double_encryption_mode_enabled?

      return keys_and_ivs_hash
    end

    def decrypt_data_with_master_key(encrypted_data)
      decoded_data = Base64.decode64(encrypted_data)
      iv = decoded_data[0, 16]
      encrypted_content = decoded_data[16..-1]
      decrypt_data(encrypted_content, fetch_master_key, iv,  method: 1)
    end

    def double_encryption_mode_enabled?
      AES256DBEncryptor.encryption_mode == :double
    end

    def encrypt_data(data, key, iv)
      cipher = OpenSSL::Cipher.new(CIPHER_METHOD)
      cipher.encrypt
      cipher.key = key
      cipher.iv = iv
      cipher.update(data) + cipher.final
    end

    def decrypt_data(data, key, iv,  method: 2)
      decipher = OpenSSL::Cipher.new(CIPHER_METHOD)
      decipher.decrypt
      decipher.key = key
      decipher.iv = iv

      decipher.update(method.eql?(1) ? data : Base64.strict_decode64(data)) + decipher.final
    end
  end
end
