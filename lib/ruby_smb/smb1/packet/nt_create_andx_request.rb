module RubySMB
  module SMB1
    module Packet

      # A SMB1 SMB_COM_NT_CREATE_ANDX Request Packet as defined in
      # [2.2.4.64.1 Request](https://msdn.microsoft.com/en-us/library/ee442175.aspx) and
      # [2.2.4.9.1 Client Request Extensions](https://msdn.microsoft.com/en-us/library/cc246332.aspx)
      class NtCreateAndxRequest < RubySMB::GenericPacket

        # A SMB1 Parameter Block as defined by the {NtCreateAndxRequest}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          endian :little
          struct :words, onlyif: -> { word_count.nonzero? } do
            and_x_block                        :andx_block
            uint8                              :reserved,            label: 'Reserved'
            uint16                             :name_length,         label: 'Name Length(bytes)', value: lambda { self.parent.data_block.bytes.file_name.length }
            nt_create_andx_flags               :flags,               label: 'Flags'
            uint32                             :root_directory_fid,  label: 'Root Directory FID'

            choice :desired_access, selection: lambda { ext_file_attributes.directory } do
              file_access_mask      0, label: 'Desired Access'
              directory_access_mask 1, label: 'Desired Access'
            end

            uint64                             :allocation_size,     label: 'Allocation Size'
            smb_ext_file_attributes            :ext_file_attributes, label: 'Extented File Attributes'
            share_access                       :share_access,        label: 'Share Access'
            # The following constants are defined in RubySMB::Dispositions
            uint32                             :create_disposition,  label: 'Create Disposition'
            create_options                     :create_options,      label: 'Create Options'
            # The following constants are defined in RubySMB::ImpersonationLevels
            uint32                             :impersonation_level, label: 'Impersonation Level'
            security_flags                     :security_flags,      label: 'Security Flags'
          end
        end

        # Represents the specific layout of the DataBlock for a {NtCreateAndxRequest} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
          struct :bytes, onlyif: -> { byte_count.nonzero? } do
            string :file_name, label: 'File Name'
          end
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def initialize_instance
          super
          smb_header.command = RubySMB::SMB1::Commands::SMB_COM_NT_CREATE_ANDX
        end

      end
    end
  end
end
