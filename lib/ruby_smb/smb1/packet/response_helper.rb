module RubySMB
  module SMB1
    module Packet

      #Helper for parsing response packets
      module ResponseHelper
        def self.parse(string_input)
          parameter_word_count = BinData::Bit8.
            read(string_input[SMB1::Packet::SMBParameterBlock::SMB_PARAMETER_BLOCK_OFFSET]).
            to_i * 2 + SMB1::Packet::SMBParameterBlock::SMB_PARAMETER_WORD_COUNT

          data_byte_size = BinData::Bit16le.
            read(string_input[SMB1::Packet::SMBParameterBlock::SMB_PARAMETER_BLOCK_OFFSET + parameter_word_count,
                              SMB1::Packet::SMBDataBlock::SMB_DATA_BYTE_SIZE])

          smb_header = SMB1::Packet::SMBHeader.
            read(string_input[SMB1::Packet::SMBHeader::SMB_HEADER_BYTES])

          smb_parameter_block = SMB1::Packet::SMBParameterBlock.
            read(string_input[SMB1::Packet::SMBParameterBlock::SMB_PARAMETER_BLOCK_OFFSET,
                              parameter_word_count])

          smb_data_block = SMB1::Packet::SMBDataBlock.
            read(string_input[SMB1::Packet::SMBParameterBlock::SMB_PARAMETER_BLOCK_OFFSET +
                                parameter_word_count,
                              data_byte_size +
                                SMB1::Packet::SMBDataBlock::SMB_DATA_BYTE_SIZE])

          return {
            smb_header: smb_header,
            smb_parameter_block: smb_parameter_block,
            smb_data_block: smb_data_block
          }
        end
      end
    end
  end
end