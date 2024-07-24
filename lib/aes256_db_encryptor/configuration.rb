module AES256DBEncryptor
  module Configuration
    class << self
      attr_accessor :encryption_key_base64, :encryption_iv_base64
      attr_accessor :second_encryption_key_base64, :second_encryption_iv_base64

      def setup(&block)
        instance_eval(&block) if block_given?
        decode_keys
      end

      def encryption_key=(value)
        @encryption_key_base64 = value
        decode_keys
      end

      def encryption_iv=(value)
        @encryption_iv_base64 = value
        decode_keys
      end

      def second_encryption_key=(value)
        @second_encryption_key_base64 = value
        decode_keys
      end

      def second_encryption_iv=(value)
        @second_encryption_iv_base64 = value
        decode_keys
      end

      def encryption_key
        @encryption_key
      end

      def encryption_iv
        @encryption_iv
      end

      def second_encryption_key
        @second_encryption_key
      end

      def second_encryption_iv
        @second_encryption_iv
      end

      private

      def decode_keys
        decode_key(:encryption_key_base64, :encryption_key)
        decode_key(:encryption_iv_base64, :encryption_iv)
        decode_key(:second_encryption_key_base64, :second_encryption_key)
        decode_key(:second_encryption_iv_base64, :second_encryption_iv)
      end

      def decode_key(encoded_key_attr, decoded_key_attr)
        encoded_key = instance_variable_get("@#{encoded_key_attr}")
        return unless encoded_key

        # Decode Base64 encoded key
        instance_variable_set("@#{decoded_key_attr}", Base64.strict_decode64(encoded_key))
      end
    end
  end
end
