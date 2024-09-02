module RubySMB
  module Dcerpc
    module Wkssvc

      UUID = '6BFFD098-A112-3610-9833-46C3F87E345A'
      VER_MAJOR = 1
      VER_MINOR = 0

      # Operation numbers
      NETR_WKSTA_GET_INFO  = 0x0000
      NETR_WKSTA_USER_ENUM = 0x0002

      PLATFORM_ID = {
        0x0000012C => "DOS",
        0x00000190 => "OS2",
        0x000001F4 => "Win",
        0x00000258 => "OSF",
        0x000002BC => "VMS"
      }

      # Information Level
      WKSTA_INFO_100 = 0x00000064
      WKSTA_INFO_101 = 0x00000065
      WKSTA_INFO_102 = 0x00000066
      #TODO: WKSTA_INFO_502 = 0x000001F6

      # User Enum Information Level
      WKSTA_USER_INFO_0 = 0x00000000
      WKSTA_USER_INFO_1 = 0x00000001

      # [2.2.2.1 WKSSVC_IDENTIFY_HANDLE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/9ef94a11-0e5c-49d7-9ac7-68d6f03565de)
      class WkssvcIdentifyHandle < Ndr::NdrWideStringPtr; end

      # [2.2.5.9 WKSTA_USER_INFO_0](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/b7c53c6f-8b92-4e5d-9a2e-6462cb4ef1ac)
      class UserInfo0 < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_wide_stringz_ptr :wkui0_username
      end

      class WkstaUserInfo0 < Ndr::NdrConfArray
        default_parameter type: :user_info0
      end

      class PwkstaUserInfo0 < WkstaUserInfo0
        extend Ndr::PointerClassPlugin
      end

      # [2.2.5.12 WKSTA_USER_INFO_0_CONTAINER](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/0b0cff8f-09bc-43a8-b0d3-88f0bf7e3664)
      class WkstaUserInfo0Container < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32        :wkui0_entries_read
        pwksta_user_info0 :wkui0_buffer
      end

      class PwkstaUserInfo0Container < WkstaUserInfo0Container
        extend Ndr::PointerClassPlugin
      end

      # [2.2.5.10 WKSTA_USER_INFO_1](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/c37b9606-866f-40ac-9490-57b8334968e2)
      class UserInfo1 < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_wide_stringz_ptr :wkui1_username
        ndr_wide_stringz_ptr :wkui1_logon_domain
        ndr_wide_stringz_ptr :wkui1_oth_domains
        ndr_wide_stringz_ptr :wkui1_logon_server
      end
      
      class WkstaUserInfo1 < Ndr::NdrConfArray
        default_parameter type: :user_info1
      end

      class PwkstaUserInfo1 < WkstaUserInfo1
        extend Ndr::PointerClassPlugin
      end
      
      # [2.2.5.13 WKSTA_USER_INFO_1_CONTAINER](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/22a813e4-fc7d-4fe3-a6d6-78debfd2c0c9)
      class WkstaUserInfo1Container < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32        :wkui1_entries_read
        pwksta_user_info1 :wkui1_buffer
      end

      class PwkstaUserInfo1Container < WkstaUserInfo1Container
        extend Ndr::PointerClassPlugin
      end

      # [2.2.5.14 WKSTA_USER_ENUM_STRUCT](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wkst/4041455a-52be-4389-a4fc-82fea3cb3160)
      class LpwkssvcUserEnumStructure < Ndr::NdrStruct
        default_parameter byte_align: 4
        endian :little

        ndr_uint32 :level
        ndr_uint32 :tag, value: -> { self.level }
        choice     :info, selection: :level, byte_align: 4 do
          pwksta_user_info0_container WKSTA_USER_INFO_0
          pwksta_user_info1_container WKSTA_USER_INFO_1
        end
      end

      require 'ruby_smb/dcerpc/wkssvc/netr_wksta_get_info_request'
      require 'ruby_smb/dcerpc/wkssvc/netr_wksta_get_info_response'
      require 'ruby_smb/dcerpc/wkssvc/netr_wksta_user_enum_request'
      require 'ruby_smb/dcerpc/wkssvc/netr_wksta_user_enum_response'

      # Returns details about a computer environment, including
      # platform-specific information, the names of the domain and local
      # computer, and the operating system version.
      #
      # @param server_name [optional, String] String that identifies the server (optional
      #   since it is ignored by the server)
      # @param level [optional, Integer] The information level of the data (default: WKSTA_INFO_100)
      # @return [RubySMB::Dcerpc::Wkssvc::WkstaInfo100, RubySMB::Dcerpc::Wkssvc::WkstaInfo101,
      #   RubySMB::Dcerpc::Wkssvc::WkstaInfo102] The structure containing the requested information
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a
      #   NetrWkstaGetInfoResponse packet
      # @raise [RubySMB::Dcerpc::Error::WkssvcError] if the response error status
      #   is not STATUS_SUCCESS
      def netr_wksta_get_info(server_name: "\x00", level: WKSTA_INFO_100)
        wkst_netr_wksta_get_info_request = NetrWkstaGetInfoRequest.new(
          server_name: server_name,
          level: level
        )
        response = dcerpc_request(wkst_netr_wksta_get_info_request)
        begin
          wkst_netr_wksta_get_info_response = NetrWkstaGetInfoResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading WkstNetrWkstaGetInfoResponse'
        end
        unless wkst_netr_wksta_get_info_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::WkssvcError,
            "Error returned with netr_wksta_get_info: "\
            "#{WindowsError::NTStatus.find_by_retval(wkst_netr_wksta_get_info_response.error_status.value).join(',')}"
        end
        wkst_netr_wksta_get_info_response.wksta_info.info
      end

      # Returns details about users who are currently active on a remote computer.
      #
      # @param server_name [optional, String] String that identifies the server (optional
      #   since it is ignored by the server)
      # @param level [optional, Integer] The information level of the data (default: WKSTA_USER_INFO_0)
      # @return [RubySMB::Dcerpc::Wkssvc::WkstaUserInfo0, RubySMB::Dcerpc::Wkssvc::WkstaUserInfo1] 
      # The structure containing the requested information
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a
      #   NetrWkstaGetInfoResponse packet
      # @raise [RubySMB::Dcerpc::Error::WkssvcError] if the response error status
      #   is not STATUS_SUCCESS
      def netr_wksta_user_enum(server_name: "\x00", level: WKSTA_USER_INFO_0)
        wkst_netr_wksta_enum_user_request = NetrWkstaUserEnumRequest.new(
          server_name: server_name,
          user_info: {
            level: level,
            tag: level,
            info: {
              wkui0_entries_read: 0,
            },
          },
          preferred_max_length: 0xFFFFFFFF,
          result_handle: 0
        )
        response = dcerpc_request(wkst_netr_wksta_enum_user_request)
        begin
          wkst_netr_wksta_enum_user_response = NetrWkstaUserEnumResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading WkstNetrWkstaUserEnumResponse'
        end
        unless wkst_netr_wksta_enum_user_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::WkssvcError,
            "Error returned with netr_wksta_enum_user: #{wkst_netr_wksta_enum_user_response.error_status.value} - "\
            "#{WindowsError::NTStatus.find_by_retval(wkst_netr_wksta_enum_user_response.error_status.value).join(',')}"
        end
        wkst_netr_wksta_enum_user_response.user_info.info
      end

    end
  end
end

