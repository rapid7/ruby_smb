module RubySMB
  module Field
    # Represents a NULL-Terminated String in UTF-16
    class Stringz16 < BinData::Stringz
      def assign(val)
        super(binary_string(val.encode('utf-16le')))
      end

      def snapshot
        # override to always remove trailing zero bytes
        result = _value
        result = trim_and_zero_terminate(result)
        result.chomp("\0\0").force_encoding('utf-16le')
      end

      private

      def append_zero_byte_if_needed!(str)
        str << "\0\0" if str.empty? || !str.end_with?("\0\0")
      end

      # Override parent on {BinData::Stringz} to use
      # a double NULL-byte instead of a single NULL-byte
      # as a terminator
      # @see BinData::Stringz
      def read_and_return_value(io)
        max_length = eval_parameter(:max_length)
        if max_length && max_length % 2 != 0
          raise ArgumentError, "[Stringz16] #max_length should be a multiple of "\
            "two, since it is Unicode (got #{max_length})"
        end
        str = ''
        i = 0
        ch = nil

        # read until double NULL-byte or we have read in the max number of bytes
        loop do
          break if ch == "\0\0" || (max_length && i == max_length)
          ch = io.readbytes(2)
          str << ch
          i += 2
        end

        trim_and_zero_terminate(str)
      end

      # Override parent method of #truncate_after_first_zero_byte! on
      # {BinData::Stringz} to use two consecutive NULL-bytes as the terimnator
      # instead of a single NULL-nyte.
      # @see BinData::Stringz
      def truncate_after_first_zero_byte!(str)
        str.sub!(/([^\0]*\0\0\0).*/, '\1')
      end

      def trim_to!(str, max_length = nil)
        if max_length
          max_length = 2 if max_length < 2
          str.slice!(max_length..-1)
          if str.length == max_length && str[-2, 2] != "\0\0"
            str[-2, 2] = "\0\0"
          end
        end
      end

    end
  end
end
