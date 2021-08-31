module RubySMB
  module Field
    # Represents a String in UTF-16LE
    class String16 < BinData::String
      def assign(val)
        super(val.to_s.encode('utf-16le')).force_encoding('utf-16le')
      end

      def snapshot
        super.force_encoding('utf-16le')
      end

      def read_and_return_value(io)
        super.force_encoding('utf-16le')
      end
    end
  end
end
