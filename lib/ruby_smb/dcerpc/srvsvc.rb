module RubySMB
  module Dcerpc
    module Srvsvc

      #https://msdn.microsoft.com/en-us/library/cc247293.aspx
      class PSyntaxIdT < BinData::Record
        endian :little
        uuid :if_uuid, value: '4b324fc8-1670-01d3-1278-5a47bf6ee188'
        uint16 :if_ver, initial_value: 3
        uint16 :if_ver_minor, initial_value: 0
      end

      class PSyntaxIdT1 < BinData::Record
        endian :little
        uuid :if_uuid, value: '8a885d04-1ceb-11c9-9fe8-08002b104860'
        uint16 :if_ver, initial_value: 2
        uint16 :if_ver_minor, initial_value: 0
      end

      class PContElemT < BinData::Record
        endian :little

        uint16 :p_cont_id, initial_value: 0
        uint8 :n_transfer_syn, value: -> { transfer_syntaxes.length }
        uint8 :reserved
        p_syntax_id_t :abstract_syntax
        array :transfer_syntaxes, type: :p_syntax_id_t1, initial_length: 1
      end

      class PContListT < BinData::Record
        endian :little

        uint8 :n_context_elem, value: -> { p_cont_elem.length }
        uint8 :reserved
        uint16 :reserved2
        array :p_cont_elem, type: :p_cont_elem_t, initial_length: 1
      end

      class NetShareEnumAll < BinData::Record
        endian :little

        uint32 :referent_id, initial_value: 0x00000001
        uint32 :max_count,    initial_value: -> { (server_unc.do_num_bytes / 2) + 1 }
        uint32 :offset,       initial_value: 0
        uint32 :actual_count, initial_value: -> {max_count}
        string :server_unc,   pad_front: false,
               initial_value: -> {host.encode('utf-16le')}

        uint16 :padding, initial_value: 0
        uint32 :level, initial_value: 1

        uint32 :ctr, initial_value: 1
        uint32 :ctr_referent_id, initial_value: 0x00000001
        uint32 :ctr_count, initial_value: 0
        uint32 :pointer_to_array, initial_value: 0

        uint32 :max_buffer, initial_value: 4294967295

        uint32 :resume_referent_id, value: 0x00000001
        uint32 :resume_handle, initial_value: 0

        def self.parse_response(response)

          shares = []

          res = response.dup
          win_error = res.slice!(-4, 4).unpack("V")[0]

          if win_error != 0
            raise RuntimeError, "Invalid DCERPC response: win_error = #{win_error}"
          end

          # Remove unused data
          res.slice!(0, 12) # level, CTR header, Reference ID of CTR
          share_count = res.slice!(0, 4).unpack("V")[0]
          res.slice!(0, 4) # Reference ID of CTR1
          share_max_count = res.slice!(0, 4).unpack("V")[0]

          if share_max_count != share_count
            raise RuntimeError, "Invalid DCERPC response: count != count max (#{share_count}/#{share_max_count})"
          end

          # ReferenceID / Type / ReferenceID of Comment
          types = res.slice!(0, share_count * 12).scan(/.{12}/n).map { |a| a[4, 2].unpack("v")[0] }

          share_count.times do |t|
            length, offset, max_length = res.slice!(0, 12).unpack("VVV")
            if offset != 0
              raise RuntimeError, "Invalid DCERPC response: offset != 0 (#{offset})"
            end

            if length != max_length
              raise RuntimeError, "Invalid DCERPC response: length !=max_length (#{length}/#{max_length})"
            end
            name = res.slice!(0, 2 * length).gsub('\x00', '')
            res.slice!(0, 2) if length % 2 == 1 # pad

            comment_length, comment_offset, comment_max_length = res.slice!(0, 12).unpack("VVV")

            if comment_offset != 0
              raise RuntimeError, "Invalid DCERPC response: comment_offset != 0 (#{comment_offset})"
            end

            if comment_length != comment_max_length
              raise RuntimeError, "Invalid DCERPC response: comment_length != comment_max_length (#{comment_length}/#{comment_max_length})"
            end

            comment = res.slice!(0, 2 * comment_length)

            res.slice!(0, 2) if comment_length % 2 == 1 # pad

            name = name.gsub("\x00", "")
            s_type = ['DISK', 'PRINTER', 'DEVICE', 'IPC', 'SPECIAL', 'TEMPORARY'][types[t]].gsub("\x00", "")
            comment = comment.gsub("\x00", "")

            shares << [name, s_type, comment]
          end

          shares
        end

        def self.create_bind
          RubySMB::Dcerpc::Bind.new(
              p_context_elem: RubySMB::Dcerpc::Srvsvc::PContListT.new
          )
        end
      end
    end
  end
end
