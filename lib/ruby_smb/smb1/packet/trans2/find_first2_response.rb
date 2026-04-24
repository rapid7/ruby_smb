module RubySMB
  module SMB1
    module Packet
      module Trans2
        # The Trans2 Parameter Block for this particular Subcommand
        class FindFirst2ResponseTrans2Parameters < BinData::Record
          endian  :little

          uint16  :sid,               label: 'Search ID'
          uint16  :search_count,      label: 'Search Count'
          uint16  :eos,               label: 'End of Search'
          uint16  :ea_error_offset,   label: 'Offset to EA Error'
          uint16  :last_name_offset,  label: 'Last Name Offset'

          # Returns the length of the Trans2Parameters struct
          # in number of bytes
          def length
            do_num_bytes
          end
        end

        # The Trans2 Data Block for this particular Subcommand
        class FindFirst2ResponseTrans2Data < BinData::Record
          string :buffer, label: 'Results Buffer', read_length: :buffer_read_length

          # Returns the length of the Trans2Data struct
          # in number of bytes
          def length
            do_num_bytes
          end
        end

        # The {RubySMB::SMB1::DataBlock} specific to this packet type.
        class FindFirst2ResponseDataBlock < RubySMB::SMB1::Packet::Trans2::DataBlock
          string                                  :pad1,               length: -> { pad1_length }
          find_first2_response_trans2_parameters  :trans2_parameters,  label: 'Trans2 Parameters'
          string                                  :pad2,               length: -> { pad2_length }
          find_first2_response_trans2_data        :trans2_data,        label: 'Trans2 Data', length: 0
        end

        # This class represents an SMB1 Trans2 FIND_FIRST2 Response Packet as defined in
        # [2.2.6.2.2 Response](https://msdn.microsoft.com/en-us/library/ee441704.aspx)
        class FindFirst2Response < RubySMB::GenericPacket
          include RubySMB::SMB1::Packet::Trans2::Win9xFraming

          COMMAND = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION2

          class ParameterBlock < RubySMB::SMB1::Packet::Trans2::Response::ParameterBlock
          end

          smb_header                       :smb_header
          parameter_block                  :parameter_block
          find_first2_response_data_block  :data_block

          def initialize_instance
            super
            parameter_block.setup << RubySMB::SMB1::Packet::Trans2::Subcommands::FIND_FIRST2
            smb_header.flags.reply = 1
          end

          # Returns the File Information in an array of appropriate
          # structs for the given FileInformationClass. Pulled out of
          # the string buffer.
          #
          # Info levels that carry a leading NextEntryOffset (e.g.
          # FindFileFullDirectoryInfo) are framed by that field. Info levels
          # without one (e.g. SMB_INFO_STANDARD, used by Win95/98/ME) are
          # packed sequentially; each entry's length is derived from the
          # record itself, and servers may insert an optional single NULL
          # pad byte between entries (see MS-CIFS Appendix A, note <153>).
          #
          # @param klass [Class] the FileInformationClass class to read the data as
          # @param buffer [String, nil] raw trans2_data bytes to parse instead of
          #   the BinData-parsed buffer. Used by callers that detect a padding
          #   mismatch between BinData's expected layout and what a Win9x-era
          #   server actually sent (no 4-byte alignment pad before the data),
          #   and want to re-feed the bytes from the server-reported data_offset.
          # @return [array<BinData::Record>] An array of structs holding the requested information
          # @raise [RubySMB::Error::InvalidPacket] if the string buffer is not a valid File Information packet
          def results(klass, unicode:, buffer: nil)
            blob = (buffer || data_block.trans2_data.buffer.to_binary_s).dup
            if klass.new.respond_to?(:next_offset)
              read_next_offset_entries(klass, blob, unicode: unicode)
            else
              read_sequential_entries(klass, blob, unicode: unicode)
            end
          end

          private

          def read_next_offset_entries(klass, blob, unicode:)
            entries = []
            until blob.empty?
              length = blob[0, 4].unpack1('V')
              data = length.zero? ? blob.slice!(0, blob.length) : blob.slice!(0, length)
              file_info = klass.new
              file_info.unicode = unicode if file_info.respond_to?(:unicode=)
              begin
                entries << file_info.read(data)
              rescue IOError
                raise RubySMB::Error::InvalidPacket, "Invalid #{klass} File Information packet in the string buffer"
              end
            end
            entries
          end

          def read_sequential_entries(klass, blob, unicode:)
            entries = []
            until blob.empty?
              file_info = klass.new
              file_info.unicode = unicode if file_info.respond_to?(:unicode=)
              begin
                file_info.read(blob)
              rescue IOError
                raise RubySMB::Error::InvalidPacket, "Invalid #{klass} File Information packet in the string buffer"
              end
              consumed = file_info.num_bytes
              break if consumed.zero?
              blob.slice!(0, consumed)
              # An entry with an empty file_name is a buffer-padding artifact, not a real entry; stop here.
              break if file_info.respond_to?(:file_name_length) && file_info.file_name_length.zero?
              entries << file_info
              # Skip optional single NULL pad byte inserted by some servers between entries.
              blob.slice!(0, 1) if blob.bytesize > 0 && blob.getbyte(0) == 0
            end
            entries
          end
        end
      end
    end
  end
end
