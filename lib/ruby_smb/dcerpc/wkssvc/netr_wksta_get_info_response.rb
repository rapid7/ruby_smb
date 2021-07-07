module RubySMB
  module Dcerpc
    module Wkssvc


      # [2.2.5.3 WKSTA_INFO_102](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/49c75566-2d4f-481a-bf32-7eb5627cb4ea)
      class WkstaInfo102 < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32           :wki102_platform_id
        ndr_wide_stringz_ptr :wki102_computername
        ndr_wide_stringz_ptr :wki102_langroup
        ndr_uint32           :wki102_ver_major
        ndr_uint32           :wki102_ver_minor
        ndr_wide_stringz_ptr :wki102_lanroot
        ndr_uint32           :wki102_logged_on_users
      end

      class PwkstaInfo102 < WkstaInfo102
        extend Ndr::PointerClassPlugin
      end

      # [2.2.5.2 WKSTA_INFO_101](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/98876691-3684-4b0c-bb43-3a8ac4705149)
      class WkstaInfo101 < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32           :wki101_platform_id
        ndr_wide_stringz_ptr :wki101_computername
        ndr_wide_stringz_ptr :wki101_langroup
        ndr_uint32           :wki101_ver_major
        ndr_uint32           :wki101_ver_minor
        ndr_wide_stringz_ptr :wki101_lanroot
      end

      class PwkstaInfo101 < WkstaInfo101
        extend Ndr::PointerClassPlugin
      end

      # [2.2.5.1 WKSTA_INFO_100](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/23275f4a-4e51-49d6-bdb5-f58519a3ea8a)
      class WkstaInfo100 < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32           :wki100_platform_id
        ndr_wide_stringz_ptr :wki100_computername
        ndr_wide_stringz_ptr :wki100_langroup
        ndr_uint32           :wki100_ver_major
        ndr_uint32           :wki100_ver_minor
      end

      class PwkstaInfo100 < WkstaInfo100
        extend Ndr::PointerClassPlugin
      end

      class LpwkstaInfo < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32 :level
        choice     :info, selection: :level, byte_align: 4 do
          pwksta_info100 WKSTA_INFO_100
          pwksta_info101 WKSTA_INFO_101
          pwksta_info102 WKSTA_INFO_102
          #TODO: pwksta_info_502 0x000001F6
        end
      end

      # [3.2.4.1 NetrWkstaGetInfo (Opnum 0)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/4af41d6f-b800-4de1-af5b-0b15a85f8e04)
      class NetrWkstaGetInfoResponse < BinData::Record
        attr_reader :opnum

        endian :little

        lpwksta_info :wksta_info
        ndr_uint32   :error_status

        def initialize_instance
          super
          @opnum = NETR_WKSTA_GET_INFO
        end
      end

    end
  end
end

