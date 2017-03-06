module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_NEGOTIATE Non-Extended Security Response Packet as defined in
      # [2.2.4.5.2.2 Non-Extended Security Response](https://msdn.microsoft.com/en-us/library/cc246327.aspx)
      class NegotiateResponse < RubySMB::GenericPacket
        # An SMB_Parameters Block as defined by the {NegotiateResponse}.
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          uint16          :dialect_index, label: 'Dialect Index'
          security_mode   :security_mode
          uint16          :max_mpx_count,     label: 'Max Multiplex Count'
          uint16          :max_number_vcs,    label: 'Max Virtual Circuits'
          uint32          :max_buffer_size,   label: 'Max Buffer Size'
          uint32          :max_raw_size,      label: 'Max Raw Size'
          uint32          :session_key,       label: 'Session Key'
          capabilities    :capabilities
          file_time       :system_time,       label: 'Server System Time'
          int16           :server_time_zone,  label: 'Server TimeZone'
          uint8           :challenge_length,  label: 'Challenge Length', initial_value: 0x08
        end

        # An SMB_Data Block as defined by the {NegotiateResponse}
        class DataBlock < RubySMB::SMB1::DataBlock
          string        :challenge,     label: 'Auth Challenge', length: 8
          stringz16     :domain_name,   label: 'Primary Domain'
          stringz16     :server_name,   label: 'Server Name'
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def initialize_instance
          super
          header = smb_header
          header.command = RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
          header.flags.reply = 1
        end

        def valid?
          smb_header.command == RubySMB::SMB1::Commands::SMB_COM_NEGOTIATE
        end
      end
    end
  end
end
