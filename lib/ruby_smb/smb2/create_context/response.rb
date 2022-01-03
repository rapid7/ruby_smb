module RubySMB
  module SMB2
    module CreateContext
      # [2.2.14.2.3 SMB2_CREATE_DURABLE_HANDLE_RESPONSE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/a3a11598-f228-47da-82bb-9418b9397041)
      class CreateDurableHandleResponse < BinData::Record
        NAME = CREATE_DURABLE_HANDLE

        endian :little
        string :reserved, label: 'Reserved', length: 8
      end

      # [2.2.14.2.12 SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/48c1049f-25a4-4f23-9a57-11ddd72ce985)
      class CreateDurableHandleV2Response < BinData::Record
        NAME = CREATE_DURABLE_HANDLE_V2

        endian :little
        uint32 :timeout,    label: 'Timeout'
        struct :flags,      label: 'Flags' do
          bit6 :reserved
          bit1 :persistent, label: 'Persistent Handle'
          bit1 :reserved1
          skip length: 3
        end
      end

      # [2.2.14.2.5 SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0fe6be15-3a76-4032-9a44-56f846ac6244)
      class CreateQueryMaximalAccessResponse < BinData::Record
        NAME = CREATE_QUERY_MAXIMAL_ACCESS

        endian :little
        nt_status         :query_status,   label: 'Query Status'
        file_access_mask  :maximal_access, label: 'Maximal Access'
      end

      # [2.2.14.2.9 SMB2_CREATE_QUERY_ON_DISK_ID](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5c977939-1d8f-4774-9111-21e9195f3aca)
      class CreateQueryOnDiskIdResponse < BinData::Record
        NAME = CREATE_QUERY_ON_DISK_ID

        endian :little
        uint64   :disk_file_id, label: 'Disk File Id', initial_value: 0xffffffffffffffff
        uint64   :volume_id,    label: 'Volume Id'
        string   :reserved,     label: 'Reserved', length: 16
      end

      class CreateContextResponse < CreateContext
        delayed_io :data, read_abs_offset: -> { abs_offset + data_offset } do
          choice  :data, selection: -> { name.snapshot } do
            create_durable_handle_response       CREATE_DURABLE_HANDLE,       length: :data_length
            create_durable_handle_v2_response    CREATE_DURABLE_HANDLE_V2,    length: :data_length
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
