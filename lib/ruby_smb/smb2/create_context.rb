module RubySMB
  module SMB2
    module CreateContext
      # Create name constants. Requests and responses have a shared name but some have different structures. Names are
      # normalized to remove the request/response portion.
      # [2.2.13.2 SMB2_CREATE_CONTEXT Request Values](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/75364667-3a93-4e2c-b771-592d8d5e876d)
      CREATE_EA_BUFFER = 'ExtA'.freeze
      CREATE_SD_BUFFER = 'SecD'.freeze
      CREATE_DURABLE_HANDLE = 'DHnQ'.freeze
      CREATE_DURABLE_HANDLE_RECONNECT = 'DHnC'.freeze
      CREATE_ALLOCATION_SIZE = 'AISi'.freeze
      CREATE_QUERY_MAXIMAL_ACCESS = 'MxAc'.freeze
      CREATE_TIMEWARP_TOKEN = 'TWrp'.freeze
      CREATE_QUERY_ON_DISK_ID = 'QFid'.freeze
      CREATE_LEASE = 'RqLs'.freeze
      CREATE_LEASE_V2 = 'RqLs'.freeze
      CREATE_DURABLE_HANDLE_V2 = 'DH2Q'.freeze
      CREATE_DURABLE_HANDLE_RECONNECT_v2 = 'DH2C'.freeze
      CREATE_APP_INSTANCE_ID = "\x45\xBC\xA6\x6A\xEF\xA7\xF7\x4A\x90\x08\xFA\x46\x2E\x14\x4D\x74".b.freeze
      CREATE_APP_INSTANCE_VERSION = "\xB9\x82\xD0\xB7\x3B\x56\x07\x4F\xA0\x7B\x52\x4A\x81\x16\xA0\x10".b.freeze
      SVHDX_OPEN_DEVICE_CONTEXT = "\x9C\xCB\xCF\x9E\x04\xC1\xE6\x43\x98\x0E\x15\x8D\xA1\xF6\xEC\x83".b.freeze

      # An SMB2_CREATE_CONTEXT struct as defined in
      # [2.2.13.2 SMB2_CREATE_CONTEXT Request Values](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/75364667-3a93-4e2c-b771-592d8d5e876d?redirectedfrom=MSDN)
      class CreateContext < BinData::Record
        unregister_self

        endian  :little
        uint32  :next_offset, label: 'Offset to next Context'
        uint16  :name_offset, label: 'Offset to Name/Tag',      initial_value: -> { buffer.rel_offset }
        uint16  :name_length, label: 'Length of Name/Tag',      initial_value: -> { name.num_bytes }
        uint16  :reserved,    label: 'Reserved Space'
        uint16  :data_offset, label: 'Offset to data',          initial_value: -> { calc_data_offset }
        uint32  :data_length, label: 'Length of data',          initial_value: -> { data.num_bytes }
        string  :buffer,      label: 'Buffer',                  initial_value: -> { build_buffer }, read_length: -> { calc_buffer_size }

        delayed_io :name, read_abs_offset: -> { abs_offset + name_offset } do
          string   :name, label: 'Name', read_length: :name_length
        end

        private

        def build_buffer
          buf = name.dup.tap { |obj| obj.abs_offset = 0 }.to_binary_s { |obj| obj.write_now! }
          buf << "\x00".b * (7 - (buf.length + 7) % 8)
          buf << data.dup.tap { |obj| obj.abs_offset = 0 }.to_binary_s { |obj| obj.write_now! }
          buf << "\x00".b * (7 - (buf.length + 7) % 8)
        end

        def calc_buffer_size
          size = 0
          size += name_length + (7 - (name_length + 7) % 8)
          size += data_length + (7 - (data_length + 7) % 8)
          size
        end

        def calc_data_offset
          if data.num_bytes == 0
            0
          else
            buffer.rel_offset + (name_length + 7 - (name_length + 7) % 8)
          end
        end
      end

      class CreateContextArray < BinData::Array
        unregister_self

        default_parameters read_until: -> { element&.next_offset == 0 }
        endian :little
      end
    end
  end
end

require 'ruby_smb/smb2/bit_field'
require 'ruby_smb/smb2/create_context/request'
require 'ruby_smb/smb2/create_context/response'
