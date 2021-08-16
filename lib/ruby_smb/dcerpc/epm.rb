module RubySMB
  module Dcerpc
    module Epm

      UUID = 'E1AF8308-5D1F-11C9-91A4-08002B14A0FA'
      VER_MAJOR = 3
      VER_MINOR = 0

      # Operation numbers
      EPT_MAP = 0x0003

      require 'ruby_smb/dcerpc/epm/epm_twrt'
      require 'ruby_smb/dcerpc/epm/epm_ept_map_request'
      require 'ruby_smb/dcerpc/epm/epm_ept_map_response'

      # Retrieve the service port number given a DCERPC interface UUID
      # See:
      # [2.2.1.2.5 ept_map Method](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/ab744583-430e-4055-8901-3c6bc007e791)
      # [https://pubs.opengroup.org/onlinepubs/9629399/apdxo.htm](https://pubs.opengroup.org/onlinepubs/9629399/apdxo.htm)
      #
      # @param uuid [String] The interface UUID
      # @param maj_ver [Integer] The interface Major version
      # @param min_ver [Integer] The interface Minor version
      # @param max_towers [Integer] The maximum number of elements to be returned
      # @return [Hash] A hash with the host and port
      # @raise [RubySMB::Dcerpc::Error::InvalidPacket] if the response is not a
      #   EpmEptMap packet
      # @raise [RubySMB::Dcerpc::Error::SamrError] if the response error status
      #   is not STATUS_SUCCESS
      def get_host_port_from_ept_mapper(uuid:, maj_ver:, min_ver:, max_towers: 1)
        decoded_tower = EpmDecodedTowerOctetString.new(
          interface_identifier: {
            interface: uuid,
            major_version: maj_ver,
            minor_version: min_ver
          },
          data_representation: {
            interface: Ndr::UUID,
            major_version: Ndr::VER_MAJOR,
            minor_version: Ndr::VER_MINOR
          }
        )
        tower = EpmTwrt.new(decoded_tower)
        ept_map_request = EpmEptMapRequest.new(
          obj: Uuid.new,
          map_tower: tower,
          entry_handle: Ndr::NdrContextHandle.new,
          max_towers: max_towers
        )
        response = dcerpc_request(ept_map_request)
        begin
          ept_map_response = EpmEptMapResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading EptMapResponse'
        end
        unless ept_map_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::SamrError,
            "Error returned with ept_map: "\
            "#{WindowsError::NTStatus.find_by_retval(ept_map_response.error_status.value).join(',')}"
        end
        tower_binary = ept_map_response.towers[0].tower_octet_string.to_binary_s
        begin
          decoded_tower = EpmDecodedTowerOctetString.read(tower_binary)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading EpmDecodedTowerOctetString'
        end
        {
          port: decoded_tower.pipe_or_port.pipe_or_port.to_i,
          host: decoded_tower.host_or_addr.host_or_addr.to_i
        }
      end
    end
  end
end

