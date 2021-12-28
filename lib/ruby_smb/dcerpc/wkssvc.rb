module RubySMB
  module Dcerpc
    module Wkssvc

      UUID = '6BFFD098-A112-3610-9833-46C3F87E345A'
      VER_MAJOR = 1
      VER_MINOR = 0

      # Operation numbers
      NETR_WKSTA_GET_INFO = 0x0000

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


      require 'ruby_smb/dcerpc/wkssvc/netr_wksta_get_info_request'
      require 'ruby_smb/dcerpc/wkssvc/netr_wksta_get_info_response'

      # Returns details about a computer environment, including
      # platform-specific information, the names of the domain and local
      # computer, and the operating system version.
      #
      # @param server_name [optional, String] String that identifies the server (optional
      #   since it is ignored by the server)
      # @param server_name [optional, Integer] The information level of the data (default: WKSTA_INFO_100)
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

    end
  end
end

