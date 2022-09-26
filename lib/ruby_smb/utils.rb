module RubySMB
  module Utils

    def safe_encode(str, encoding)
      str.encode(encoding)
    rescue EncodingError
      if str.encoding == ::Encoding::ASCII_8BIT
        str.force_encoding(encoding)
      else
        raise
      end
    end

  end
end
