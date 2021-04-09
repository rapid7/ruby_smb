module RubySMB
  module Compression
    module LZNT1
      def self.compress(buf, chunk_size: 0x1000)
        out = ''
        until buf.empty?
          chunk = buf[0...chunk_size]
          compressed = compress_chunk(chunk)
          # chunk is compressed
          if compressed.length < chunk.length
            out << [0xb000 | (compressed.length - 1)].pack('v')
            out << compressed
          else
            out << [0x3000 | (chunk.length - 1)].pack('v')
            out << chunk
          end
          buf = buf[chunk_size..-1]
          break if buf.nil?
        end

        out
      end

      def self.compress_chunk(chunk)
        blob = chunk
        out = ''
        pow2 = 0x10
        l_mask3 = 0x1002
        o_shift = 12
        until blob.empty?
          bits = 0
          tmp = ''
          i = -1
          loop do
            i += 1
            bits >>= 1
            while pow2 < (chunk.length - blob.length)
              pow2 <<= 1
              l_mask3 = (l_mask3 >> 1) + 1
              o_shift -= 1
            end

            max_len = [blob.length, l_mask3].min
            offset, length = find(chunk[0...(chunk.length - blob.length)], blob, max_len)

            # try to find more compressed pattern
            _offset2, length2 = find(chunk[0...chunk.length - blob.length + 1], blob[1..-1], max_len)

            length = 0 if length < length2

            if length > 0
              symbol = ((offset - 1) << o_shift) | (length - 3)
              tmp << [symbol].pack('v')
              # set the highest bit
              bits |= 0x80
              blob = blob[length..-1]
            else
              tmp += blob[0]
              blob = blob[1..-1]
            end

            break if blob.empty? || i == 7
          end

          out << [bits >> (7 - i)].pack('C')
          out << tmp
        end

        out
      end

      def self.decompress(buf, length_check: true)
        out = ''
        until buf.empty?
          header = buf.unpack1('v')
          length = (header & 0xfff) + 1
          raise EncodingError, 'invalid chunk length' if length_check && length > (buf.length - 2)

          chunk = buf[2...length + 2]
          out << if header & 0x8000 == 0
                   chunk
                 else
                   decompress_chunk(chunk)
                 end
          buf = buf[length + 2..-1]
        end

        out
      end

      def self.decompress_chunk(chunk)
        out = ''
        until chunk.empty?
          flags = chunk[0].unpack1('C')
          chunk = chunk[1..-1]
          8.times do |i|
            if (flags >> i & 1) == 0
              out << chunk[0]
              chunk = chunk[1..-1]
            else
              flag = chunk.unpack1('v')
              pos = out.length - 1
              l_mask = 0xfff
              o_shift = 12
              while pos >= 0x10
                l_mask >>= 1
                o_shift -= 1
                pos >>= 1
              end

              length = (flag & l_mask) + 3
              offset = (flag >> o_shift) + 1

              if length >= offset
                out_offset = out[-offset..-1]
                tmp = out_offset * (0xfff / out_offset.length + 1)
                out << tmp[0...length]
              else
                out << out[-offset..-offset + length - 1]
              end
              chunk = chunk[2..-1]
            end
            break if chunk.empty?
          end
        end

        out
      end

      class << self
        private

        def find(src, target, max_len)
          result_offset = 0
          result_length = 0
          1.upto(max_len - 1) do |i|
            offset = src.rindex(target[0...i])
            next if offset.nil?

            tmp_offset = src.length - offset
            tmp_length = i
            if tmp_offset == tmp_length
              src_offset = src[offset..-1]
              tmp = src_offset * (0xfff / src_offset.length + 1)
              i.upto(max_len) do |j|
                offset = tmp.rindex(target[0...j])
                break if offset.nil?

                tmp_length = j
              end
            end

            if tmp_length > result_length
              result_offset = tmp_offset
              result_length = tmp_length
            end
          end

          result_length < 3 ? [0, 0] : [result_offset, result_length]
        end
      end
    end
  end
end
