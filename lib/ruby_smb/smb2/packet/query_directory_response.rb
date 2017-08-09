module RubySMB
  module SMB2
    module Packet

      # An SMB2 Query Directory Response Packet as defined in
      # [2.2.34 SMB2 QUERY_DIRECTORY Response](https://msdn.microsoft.com/en-us/library/cc246552.aspx)
      class QueryDirectoryResponse < RubySMB::GenericPacket
        endian       :little
        smb2_header  :smb2_header
        uint16       :structure_size,  label: 'Structure Size',       initial_value: 9
        uint16       :buffer_offset,   label: 'Output Buffer Offset', initial_value: lambda { buffer.abs_offset }
        uint32       :buffer_length,   label: 'Output Buffer Length', initial_value: lambda { buffer.do_num_bytes }
        string       :buffer

        def initialize_instance
          super
          smb2_header.command = RubySMB::SMB2::Commands::QUERY_DIRECTORY
          smb2_header.flags.reply = 1
        end

        # Returns the File Information in an array of appropriate
        # structs for the given FileInformationClass. Pulled out of
        # the string buffer.
        #
        # @param klass [Class] the FileInformationClass class to read the data as
        # @return [array<BinData::Record>] An array of structs holding the requested information
        def results(klass)
          information_classes = []
          blob = self.buffer.to_binary_s.dup
          while blob.length > 0
            length = blob[0,4].unpack('V').first

            if length.zero?
              data = blob.slice!(0,blob.length)
            else
              data = blob.slice!(0,length)
            end

            information_classes << klass.read(data)
          end
          information_classes
        end

      end
    end
  end
end