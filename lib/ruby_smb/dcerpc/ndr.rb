module RubySMB
  module Dcerpc

    module NDR

      # Provide padding to align the string to the 32bit boundary
      def NDR.align(string)
        return "\x00" * ((4 - (string.length & 3)) & 3)
      end

      # Encode a 4 byte long
      # use to encode:
      #       long element_1;
      def NDR.long(string)
        return [string].pack('V')
      end

      # Encode a 2 byte short
      # use to encode:
      #       short element_1;
      def NDR.short(string)
        return [string].pack('v')
      end

      # Encode a single byte
      # use to encode:
      #       byte element_1;
      def NDR.byte(string)
        return [string].pack('C')
      end

      # Encode a byte array
      # use to encode:
      #       char  element_1
      def NDR.UniConformantArray(string)
        return long(string.length) + string + align(string)
      end

      # Encode a string
      # use to encode:
      #       char *element_1;
      def NDR.string(string)
        string << "\x00" # null pad
        return long(string.length) + long(0) + long(string.length) + string + align(string)
      end

      # Encode a string
      # use to encode:
      #       w_char *element_1;
      def NDR.wstring(string)
        string  = string + "\x00" # null pad
        return long(string.length) + long(0) + long(string.length) + NDR.to_unicode(string) + align(NDR.to_unicode(string))
      end

      # Encode a string and make it unique
      # use to encode:
      #       [unique] w_char *element_1;
      def NDR.uwstring(string)
        string  = string + "\x00" # null pad
        return long(rand(0xffffffff))+long(string.length) + long(0) + long(string.length) + NDR.to_unicode(string) + align(NDR.to_unicode(string))
      end

      # Encode a string that is already unicode encoded
      # use to encode:
      #       w_char *element_1;
      def NDR.wstring_prebuilt(string)
        # if the string len is odd, thats bad!
        if string.length % 2 > 0
          string = string + "\x00"
        end
        len = string.length / 2;
        return long(len) + long(0) + long(len) + string + align(string)
      end

      # alias to wstring, going away soon
      def NDR.UnicodeConformantVaryingString(string)
        NDR.wstring(string)
      end

      # alias to wstring_prebuilt, going away soon
      def NDR.UnicodeConformantVaryingStringPreBuilt(string)
        NDR.wstring_prebuilt(string)
      end

      def NDR.to_unicode(str='', type = 'utf-16le', mode = '', size = '')
        return '' if not str
        case type
          when 'utf-16le'
            return str.unpack('C*').pack('v*')
          when 'utf-16be'
            return str.unpack('C*').pack('n*')
          when 'utf-32le'
            return str.unpack('C*').pack('V*')
          when 'utf-32be'
            return str.unpack('C*').pack('N*')
          when 'utf-7'
            case mode
              when 'all'
                return str.gsub(/./){ |a|
                  out = ''
                  if 'a' != '+'
                    out = encode_base64(to_unicode(a, 'utf-16be')).gsub(/[=\r\n]/, '')
                  end
                  '+' + out + '-'
                }
              else
                return str.gsub(/[^\n\r\t\ A-Za-z0-9\'\(\),-.\/\:\?]/){ |a|
                  out = ''
                  if a != '+'
                    out = encode_base64(to_unicode(a, 'utf-16be')).gsub(/[=\r\n]/, '')
                  end
                  '+' + out + '-'
                }
            end
          when 'utf-8'
            if size == ''
              size = 2
            end

            if size >= 2 and size <= 7
              string = ''
              str.each_byte { |a|
                if (a < 21 || a > 0x7f) || mode != ''
                  # ugh.	turn a single byte into the binary representation of it, in array form
                  bin = [a].pack('C').unpack('B8')[0].split(//)

                  # even more ugh.
                  bin.collect!{|a_| a_.to_i}

                  out = Array.new(8 * size, 0)

                  0.upto(size - 1) { |i|
                    out[i] = 1
                    out[i * 8] = 1
                  }

                  i = 0
                  byte = 0
                  bin.reverse.each { |bit|
                    if i < 6
                      mod = (((size * 8) - 1) - byte * 8) - i
                      out[mod] = bit
                    else
                      byte = byte + 1
                      i = 0
                      redo
                    end
                    i = i + 1
                  }

                  if mode != ''
                    case mode
                      when 'overlong'
                        # do nothing, since we already handle this as above...
                      when 'invalid'
                        done = 0
                        while done == 0
                          # the ghetto...
                          bits = [7, 8, 15, 16, 23, 24, 31, 32, 41]
                          bits.each { |bit|
                            bit = (size * 8) - bit
                            if bit > 1
                              set = rand(2)
                              if out[bit] != set
                                out[bit] = set
                                done = 1
                              end
                            end
                          }
                        end
                      else
                        raise TypeError, 'Invalid mode.  Only "overlong" and "invalid" are acceptable modes for utf-8'
                    end
                  end
                  string << [out.join('')].pack('B*')
                else
                  string << [a].pack('C')
                end
              }
              return string
            else
              raise TypeError, 'invalid utf-8 size'
            end
          when 'uhwtfms' # suggested name from HD :P
            load_codepage()

            string = ''
            # overloading mode as codepage
            if mode == ''
              mode = 1252 # ANSI - Latan 1, default for US installs of MS products
            else
              mode = mode.to_i
            end
            if @@codepage_map_cache[mode].nil?
              raise TypeError, "Invalid codepage #{mode}"
            end
            str.each_byte {|byte|
              char = [byte].pack('C*')
              possible = @@codepage_map_cache[mode]['data'][char]
              if possible.nil?
                raise TypeError, "codepage #{mode} does not provide an encoding for 0x#{char.unpack('H*')[0]}"
              end
              string << possible[ rand(possible.length) ]
            }
            return string
          when 'uhwtfms-half' # suggested name from HD :P
            load_codepage()
            string = ''
            # overloading mode as codepage
            if mode == ''
              mode = 1252 # ANSI - Latan 1, default for US installs of MS products
            else
              mode = mode.to_i
            end
            if mode != 1252
              raise TypeError, "Invalid codepage #{mode}, only 1252 supported for uhwtfms_half"
            end
            str.each_byte {|byte|
              if ((byte >= 33 && byte <= 63) || (byte >= 96 && byte <= 126))
                string << "\xFF" + [byte ^ 32].pack('C')
              elsif (byte >= 64 && byte <= 95)
                string << "\xFF" + [byte ^ 96].pack('C')
              else
                char = [byte].pack('C')
                possible = @@codepage_map_cache[mode]['data'][char]
                if possible.nil?
                  raise TypeError, "codepage #{mode} does not provide an encoding for 0x#{char.unpack('H*')[0]}"
                end
                string << possible[ rand(possible.length) ]
              end
            }
            return string
          else
            raise TypeError, 'invalid utf type'
        end
      end

    end
  end
end