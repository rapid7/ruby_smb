module RubySMB
  module Dcerpc
    module Srvsvc

      # [2.2.1.1 SRVSVC_HANDLE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/5f8329ee-1965-4ea1-ad35-3b29fbb63232)
      class SrvsvcHandle < Ndr::NdrWideStringzPtr; end

      # [2.2.4.23 SHARE_INFO_1](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/fc69f110-998d-4c16-9667-514e22fdd80b)
      class ShareInfo1Element < Ndr::NdrStruct
        default_parameters byte_align: 4

        ndr_wide_stringz_ptr :shi1_netname
        ndr_uint32           :shi1_type
        ndr_wide_stringz_ptr :shi1_remark
      end

      class ShareInfo1 < Ndr::NdrConfArray
        default_parameters type: :share_info1_element
      end

      class LpshareInfo1 < ShareInfo1
        default_parameters byte_align: 4
        arg_processor :ndr_pointer
        extend Ndr::PointerClassPlugin
        def initialize_shared_instance
          super
          extend Ndr::PointerPlugin
        end
      end

      # [2.2.4.33 SHARE_INFO_1_CONTAINER](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/919abd5d-87d9-4ffa-b4b1-632a66053bc6)
      class ShareInfo1Container < Ndr::NdrStruct
        default_parameters byte_align: 4

        ndr_uint32    :entries_read
        lpshare_info1 :buffer
      end

      class LpshareInfo1Container < ShareInfo1Container
        default_parameters byte_align: 4
        arg_processor :ndr_pointer
        extend Ndr::PointerClassPlugin
        def initialize_shared_instance
          super
          extend Ndr::PointerPlugin
        end
      end

      # [2.2.4.38 SHARE_ENUM_STRUCT](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/79ee052e-e16b-4ec5-b4b7-e99777c26eca)
      class LpshareEnumStruct < Ndr::NdrStruct
        hide :switch_value
        default_parameters byte_align: 4

        ndr_uint32 :level, initial_value: 1
        ndr_uint32 :switch_value, initial_value: :level
        choice :share_info, selection: :level, byte_align: 4 do
          lpshare_info1_container 1, initial_value: { entries_read: 0, buffer: :null }
        end
      end

      # [3.1.4.8 NetrShareEnum (Opnum 15)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/c4a98e7b-d416-439c-97bd-4d9f52f8ba52)
      class NetShareEnumAllRequest < BinData::Record
        attr_reader :opnum

        endian :little

        srvsvc_handle       :server_name
        lpshare_enum_struct :info_struct
        ndr_uint32          :prefered_maximum_length, initial_value: 0xFFFFFFFF
        ndr_uint32_ptr      :resume_handle, initial_value: 0

        def initialize_instance
          super
          @opnum = NET_SHARE_ENUM_ALL
        end
      end

      class NetShareEnumAllResponse < BinData::Record
        attr_reader :opnum

        endian :little

        lpshare_enum_struct :info_struct
        ndr_uint32          :total_entries
        ndr_uint32_ptr      :resume_handle
        ndr_uint32          :error_status

        def initialize_instance
          super
          @opnum = NET_SHARE_ENUM_ALL
        end

        def list_shares
        end
      end
    end
  end
end
