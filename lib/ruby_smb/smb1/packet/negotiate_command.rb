module RubySMB
  module SMB1
    module Packet

      # This class represents the negotiate command
      # [2.2.4.52 SMB_COM_NEGOTIATE](https://msdn.microsoft.com/en-us/library/ee441913.aspx)
      class NegotiateCommand < RubySMB::SMB1::SMBPacket
        def initialize_instance
          super
          self.command = RubySMB::SMB1::COMMANDS[:SMB_COM_NEGOTIATE]
        end

        #Request methods
        def dialects
          dialect_count = self.bytes.count("\x00")
          dialects_array = BinData::Array.new(:type => :dialect, :initial_length => dialect_count)
          dialects_array = dialects_array.read(self.bytes)
        end

        def dialects=(dialects=[])
          raise ArgumentError, 'Must be an Array of dialect strings' unless dialects.kind_of? Enumerable
          dialects_array = dialects.map {|dialect| Dialect.new(:dialect_string => dialect) }
          final_dialects = BinData::Array.new(:type => :dialect)
          final_dialects.assign(dialects_array)

          self.bytes = final_dialects.to_binary_s
        end


        #Response methods
        def dialect_index
          index = 0
          begin
            index = response_detail.dialect_index
          rescue
            index = BinData::Bit16.read(self.words)
          end
          index
        end

        private

        def response_detail
          RubySMB::SMB1::Packet::NTLMParameterBlock.read(self.words) if self.word_count > 1
        end
      end

      # This class represents the Dialect for a NegotiateRequest.
      class Dialect < BinData::Record
        bit8 :buffer_format, :value => 0x2
        stringz :dialect_string
      end

      # This class represents a SMB1 Negotiate nt lm response parameter block.
      class NTLMParameterBlock < BinData::Record
        bit16     :dialect_index
        bit8      :security_mode
        bit16     :max_mpx_count
        bit16     :max_number_vcs
        bit32     :max_buffer_size
        bit32     :max_raw_size
        bit32     :session_key
        bit32     :capabilities
        bit64     :system_time
        bit16     :server_time_zone
        bit8      :challenge_length
      end
    end
  end
end
