module RubySMB
  module SMB2
    module CreateContext
      # [2.2.14.2.5 SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0fe6be15-3a76-4032-9a44-56f846ac6244)
      class CreateQueryMaximalAccessResponse < BinData::Record
        NAME = CREATE_QUERY_MAXIMAL_ACCESS

        default_parameter length: 0

        endian :little
        nt_status             :query_status, label: 'Query Status'
        directory_access_mask :maximal_access, label: 'Maximal Access'
      end

      # [2.2.14.2.9 SMB2_CREATE_QUERY_ON_DISK_ID](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5c977939-1d8f-4774-9111-21e9195f3aca)
      class CreateQueryOnDiskIdResponse < BinData::Record
        NAME = CREATE_QUERY_ON_DISK_ID

        endian :little
        uint64   :disk_file_id, label: 'Disk File Id'
        uint64   :volume_id,    label: 'Volume Id'
        string   :reserved,     label: 'Reserved', length: 16
      end

      class CreateContextResponse < CreateContext
        delayed_io :data, read_abs_offset: -> { abs_offset + data_offset } do
          choice  :data, selection: -> { name.snapshot } do
            create_query_maximal_access_response CREATE_QUERY_MAXIMAL_ACCESS, length: :data_length
            create_query_on_disk_id_response     CREATE_QUERY_ON_DISK_ID,     length: :data_length
            string                               :default,                    read_length: :data_length
          end
        end
      end

      class CreateContextArrayResponse < CreateContextArray
        default_parameters type: :create_context_response
      end
    end
  end
end
