module RubySMB
  module SMB1
    module Packet
      module Trans2

        # A Trans2 OPEN2 Request Packet as defined in
        # [2.2.6.1.1 Request](https://msdn.microsoft.com/en-us/library/ee441733.aspx)
        class Open2Request < BinData::Record

          class ParameterBlock < RubySMB::SMB1::Packet::Trans2::Request::ParameterBlock
          end

          class Trans2Parameters < BinData::Record
            open2_flags       :flags,       label: 'Flags'
            open2_access_mode :access_mode, label: 'AccessMode'
          end

          class DataBlock < RubySMB::SMB1::DataBlock

          end

          smb_header        :smb_header
          parameter_block   :parameter_block
          data_block        :data_block
        end
      end
    end
  end
end
