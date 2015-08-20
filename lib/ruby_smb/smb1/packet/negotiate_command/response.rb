module RubySMB
  module SMB1
    module Packet
      module NegotiateCommand

        # Represents a SMB1 Negotiate response packet.
        # [2.2.4.52.2 Response](https://msdn.microsoft.com/en-us/library/ee441946.aspx)
        class Response < BinData::Record
          attr_accessor :nt_lm_response_block

          smb_header            :smb_header
          smb_parameter_block   :smb_parameter_block
          smb_data_block        :smb_data_block

          def self.parse(input)
            parsed_input = ResponseHelper.parse(input)

            response = self.new(
              :smb_header => parsed_input[:smb_header],
              :smb_parameter_block => parsed_input[:smb_parameter_block],
              :smb_data_block => parsed_input[:smb_data_block]
            )

            if response.smb_parameter_block.word_count > 0
              response.nt_lm_response_block = NegotiateCommand::NTLMParameterBlock.read(response.smb_parameter_block.to_binary_s)
            end

            return response
          end

          # Negotiate response is invalid if word count and byte count are BOTH 0
          def valid?
            smb_parameter_block.word_count != 0 || smb_data_block.byte_count != 0
          end
        end
      end
    end
  end
end