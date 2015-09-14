module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_NEGOTIATE Extended Security Response Packet as defined in
      # [2.2.4.5.2.1 Extended Security Response](https://msdn.microsoft.com/en-us/library/cc246326.aspx)
      class NegotiateResponseExtended < RubySMB::SMB1::Packet::Generic

        # An SMB_Parameters Block as defined by the {NegotiateResponseExtended}.
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          uint16          :dialect_index,     :label => 'Dialect Index'
          security_mode   :security_mode
          uint16          :max_mpx_count,     :label => 'Max Multiplex Count'
          uint16          :max_number_vcs,    :label => 'Max Virtual Circuits'
          uint32          :max_buffer_size,   :label => 'Max Buffer Size'
          uint32          :max_raw_size,      :label => 'Max Raw Size'
          uint32          :session_key,       :label => 'Session Key'
          capabilities    :capabilities
          file_time       :system_time,       :label => 'Server System Time'
          int16           :server_time_zone,  :label => 'Server TimeZone'
          uint8           :challenge_length,  :label => 'Challenge Length',     :initial_value => 0x00
        end

        # An SMB_Data Block as defined by the {NegotiateResponseExtended}
        class DataBlock < RubySMB::SMB1::DataBlock
          string  :server_guid,     :label => 'Server GUID',        :length => 16
          rest    :security_blob,   :label => 'GSS Security BLOB'
        end

        parameter_block :parameter_block
        data_block :data_block

        def initialize_instance
          super
          header = self.smb_header
          header.command = RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
          header.flags.reply = 1
        end
      end
    end
  end
end

