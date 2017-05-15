module RubySMB
  module SMB1
    module Packet
      module NtTrans

        # Class representing a generic NT Transaction request packet as defined in
        # [2.2.4.62.1 Request](https://msdn.microsoft.com/en-us/library/ee441534.aspx)
        class Request < RubySMB::GenericPacket

          class ParameterBlock < RubySMB::SMB1::Packet::NtTrans::Request::ParameterBlock
          end

          class Trans2Parameters < BinData::Record
            endian  :little

            struct :flags do
              bit4  :reserved
              bit1  :open_target_dir, label: 'Open Parent Directory'
              bit1  :request_opbatch, label: 'Request Batch OpLock'
              bit1  :request_oplock,  label: 'Request Exclusive OpLock'
              bit1  :reserved2,       label: 'Reserved Space'
              # byte boundary
              bit8  :reserved3,       label: 'Reserved Space'
              bit8  :reserved4,       label: 'Reserved Space'
              bit8  :reserved5,       label: 'Reserved Space'
            end

            uint32                  :root_directory_fid,  label: 'Root Directory FID'
            file_access_mask        :desired_access
            uint64                  :allocation_size,     label: 'Allocation Size'
            smb_ext_file_attributes :ext_file_attribute
            share_access            :share_access,        label: 'Share Access'

          end

          class DataBlock < RubySMB::SMB1::Packet::Trans2::DataBlock
            string :pad1,               length: lambda { pad1_length }
            string :trans2_parameters,  label: 'Trans2 Parameters'
            string :pad2,               length: lambda { pad2_length }
            string :trans2_data,        label: 'Trans2 Data'
          end

          smb_header        :smb_header
          parameter_block   :parameter_block
          data_block        :data_block

          def initialize_instance
            super
            smb_header.command = RubySMB::SMB1::Commands::SMB_COM_NT_TRANSACT
          end
        end
      end
    end
  end
end