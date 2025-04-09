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

      def ept_map(uuid:, maj_ver:, min_ver:, max_towers: 1, protocol: :ncacn_ip_tcp)
        interface_identifier = {
          interface: uuid,
          major_version: maj_ver,
          minor_version: min_ver
        }
        data_representation = {
          interface: Ndr::UUID,
          major_version: Ndr::VER_MAJOR,
          minor_version: Ndr::VER_MINOR
        }

        case protocol
        when :ncacn_ip_tcp
          decoded_tower = EpmDecodedTowerOctetString.new(
            interface_identifier: interface_identifier,
            data_representation: data_representation,
            pipe_or_port: {
              identifier: 7, # 0x07: DOD TCP port
              pipe_or_port: 0
            },
            host_or_addr: {
              identifier: 9, # 0x09: DOD IP v4 address (big-endian)
              host_or_addr: 0
            }
          )

          process_tower = lambda do |tower|
            port = tower.pipe_or_port.pipe_or_port.value
            address = IPAddr.new(tower.host_or_addr.host_or_addr.value, Socket::AF_INET)
            {
              port: port,
              address: address,
              # https://learn.microsoft.com/en-us/windows/win32/midl/ncacn-ip-tcp
              endpoint: "ncacn_ip_tcp:#{address}[#{port}]"
            }
          end
        when :ncacn_np
          decoded_tower = EpmDecodedTowerOctetString.new(
            interface_identifier: interface_identifier,
            data_representation: data_representation,
            pipe_or_port: {
              identifier: 0x0f, # 0x0f: NetBIOS pipe name
              pipe_or_port: [0]
            },
            host_or_addr: {
              identifier: 0x11, # 0x11: MS NetBIOS host name
              host_or_addr: [0]
            }
          )

          process_tower = lambda do |tower|
            pipe = tower.pipe_or_port.pipe_or_port[...-1].pack('C*')
            host = tower.host_or_addr.host_or_addr[...-1].pack('C*')
            {
              pipe: pipe,
              host: host,
              # https://learn.microsoft.com/en-us/windows/win32/midl/ncacn-nb-nb
              endpoint: "ncacn_np:#{host}[#{pipe}]"
            }
          end
        else
          raise NotImplementedError, "Unsupported protocol: #{protocol}"
        end

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
          raise RubySMB::Dcerpc::Error::EpmError,
            "Error returned with ept_map: "\
            "#{WindowsError::NTStatus.find_by_retval(ept_map_response.error_status.value).join(',')}"
        end

        ept_map_response.towers.map do |tower|
          tower_binary = tower.tower_octet_string.to_binary_s
          begin
            decoded_tower = EpmDecodedTowerOctetString.read(tower_binary)
          rescue IOError
            raise RubySMB::Dcerpc::Error::InvalidPacket, 'Error reading EpmDecodedTowerOctetString'
          end

          process_tower.(decoded_tower)
        end
      end

      def ept_map_endpoint(endpoint, **kwargs)
        ept_map(uuid: endpoint::UUID, maj_ver: endpoint::VER_MAJOR, min_ver: endpoint::VER_MINOR, **kwargs)
      end
    end
  end
end

