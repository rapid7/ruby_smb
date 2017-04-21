module RubySMB
  module SMB1
    module Packet

      # This class represents an SMB1 Echo Request Packet as defined in
      # [2.2.4.39.1 Request](https://msdn.microsoft.com/en-us/library/ee441746.aspx)
      class EchoRequest < RubySMB::GenericPacket


        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          uint16  :echo_count,  label: 'Echo Count',  initial_value: 1
        end

        class DataBlock < RubySMB::SMB1::DataBlock
          string  :data,  label: 'Data'
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def initialize_instance
          super
          smb_header.command = RubySMB::SMB1::Commands::SMB_COM_ECHO
        end

      end
    end
  end
end