module RubySMB
  module Dcerpc
    module Epm

      # [Protocol Tower Encoding](https://pubs.opengroup.org/onlinepubs/9629399/apdxl.htm)
      # [Protocol Identifiers](https://pubs.opengroup.org/onlinepubs/9629399/apdxi.htm#tagcjh_28)

      class EpmFloorInterfaceOrDataIdentifier < Ndr::NdrStruct
        default_parameters byte_align: 1
        endian :little

        uint16 :lhs_bytecount, byte_align: 1, initial_value: -> {identifier.num_bytes + interface.num_bytes + major_version.num_bytes}
        uint8  :identifier, byte_align: 1, initial_value: 0x0d
        choice :interface, selection: :identifier, byte_align: 1 do
          # TODO
          #oid 0
          uuid :default
        end
        uint16 :major_version, byte_align: 1
        uint16 :rhs_bytecount, byte_align: 1, initial_value: 2
        uint16 :minor_version, byte_align: 1
      end

      class EpmFloorProtocolIdentifier < Ndr::NdrStruct
        default_parameters byte_align: 1
        endian :little

        uint16 :lhs_bytecount, byte_align: 1, initial_value: -> {prot_identifier.num_bytes}
        # Protocol Identifiers:
		# 0x00: "OSI Object Identifier [OID]"
		# 0x02: "DNA Session Control Phase 4"
		# 0x03: "DNA Session Control V3 Phase 5"
		# 0x04: "DNA NSP Transport"
		# 0x05: "OSI TP4 [T-Selector]"
		# 0x06: "OSI CLNS [NSAP]"
		# 0x07: "DOD TCP port"
		# 0x08: "DOD UDP port"
		# 0x09: "DOD IP v4 big-endian"
		# 0x0a: "RPC Connectionless v4"
		# 0x0b: "RPC Connection-oriented v5"
		# 0x0c: "MS Named Pipes"
		# 0x0d: "UUID"
		# 0x0e: "ncadg_ipx"
		# 0x0f: "NetBIOS Named Pipes"
		# 0x10: "MS Named Pipe Name" or "Local InterProcess Communication (LRPC)")
		# 0x11: "MS NetBIOS"
		# 0x12: "MS NetBEUI"
		# 0x13: "Netware SPX"
		# 0x14: "Netware IPX"
		# 0x15: "NMP_TOWER_ID"
		# 0x16: "Appletalk Stream [endpoint]"
		# 0x17: "Appletalk Datagram [endpoint]"
		# 0x18: "Appletalk [NBP-style Name]"
		# 0x19: "NetBIOS [CL on all protocols]"
		# 0x1a: "VINES SPP"
		# 0x1b: "VINES IPC"
		# 0x1c: "StreetTalk [name]"
		# 0x1d: "MSMQ"
		# 0x1f: "MS IIS (http)"
		# 0x20: "Unix Domain socket [pathname]"
		# 0x21: "null"
		# 0x22: "NetBIOS name"
        uint8  :prot_identifier, byte_align: 1, initial_value: 0x0b
        uint16 :rhs_bytecount, byte_align: 1, initial_value: 2
        uint16 :minor_version, byte_align: 1
      end

      class EpmFloorPipeOrHost < Ndr::NdrStruct
        default_parameters byte_align: 1
        endian :little

        uint16           :lhs_bytecount, byte_align: 1, initial_value: -> {identifier.num_bytes}
        # :identifier defines what :name is
        # 0x10: MS Named pipe name
        # 0x0c: ncalrpc pipe name (local interprocess communication)
        # 0x0f: NetBIOS pipe name
        # default: Host name
        uint8            :identifier, byte_align: 1
        uint16           :rhs_bytecount, byte_align: 1, initial_value: -> { name.length }
        ndr_fixed_byte_array :name, initial_length: :rhs_bytecount
      end

      class EpmFloorPipeOrPort < Ndr::NdrStruct
        default_parameters byte_align: 1
        endian :little

        uint16 :lhs_bytecount, byte_align: 1, initial_value: -> {identifier.num_bytes}
        # :identifier defines what :pipe_or_port is
        # 0x10: MS Named pipe name
        # 0x0c: ncalrpc pipe name (local interprocess communication)
        # 0x0f: NetBIOS pipe name
        # 0x07: DOD TCP port
        # 0x08: DOD UCP port
        # 0x13: Netware SPX port
        # 0x14: Netware IPX port
        # 0x1a: VINES SPP port
        # 0x1b: VINES IPC port
        # 0x1f: Default port
        # default: Default port
        uint8  :identifier, byte_align: 1, initial_value: 0x07
        uint16 :rhs_bytecount, byte_align: 1, initial_value: -> { pipe_or_port.num_bytes }
        choice :pipe_or_port, selection: :identifier, byte_align: 1 do
          ndr_fixed_byte_array 0x10, initial_length: :rhs_bytecount
          ndr_fixed_byte_array 0x0c, initial_length: :rhs_bytecount
          ndr_fixed_byte_array 0x0f, initial_length: :rhs_bytecount
          uint16be             0x07
          uint16be             0x08
          uint16be             0x13
          uint16be             0x14
          uint16be             0x1a
          uint16be             0x1b
          uint16be             0x1f
          ndr_fixed_byte_array :default, initial_length: :rhs_bytecount
        end
      end

      class EpmIpv4Address < BinData::Uint32be
        default_parameters byte_align: 1
      end

      class EpmIpxSpxAddress < Ndr::NdrStruct
        default_parameters byte_align: 1
        endian :little

        int32 :net, byte_align: 1
        int48 :node, byte_align: 1
      end

      class EpmFloorHostOrAddr < Ndr::NdrStruct
        default_parameters byte_align: 1
        endian :little

        uint16 :lhs_bytecount, byte_align: 1, initial_value: -> {identifier.num_bytes}
        # :identifier defines what :host_or_addr is
        # 0x11: MS NetBIOS host name
        # 0x12: MS NetBEUI host name
        # 0x22: NetBIOS name
        # 0x09: DOD IP v4 address (big-endian)
        # 0x13: Netware SPX address
        # 0x14: Netware IPX address
        # 0x00: IP v6 address
        # default: Default address
        uint8  :identifier, byte_align: 1, initial_value: 0x09
        uint16 :rhs_bytecount, byte_align: 1, initial_value: -> { host_or_addr.num_bytes }
        choice :host_or_addr, selection: :identifier, byte_align: 1 do
          ndr_fixed_byte_array 0x11, initial_length: :rhs_bytecount
          ndr_fixed_byte_array 0x12, initial_length: :rhs_bytecount
          ndr_fixed_byte_array 0x22, initial_length: :rhs_bytecount
          epm_ipv4_address     0x09
          epm_ipx_spx_address  0x13
          epm_ipx_spx_address  0x14
          choice               0x00, selection: -> {rhs_bytecount.num_bytes} do
            ndr_fixed_byte_array 16, initial_length: 16
            ndr_fixed_byte_array :default, initial_length: :rhs_bytecount
          end
          ndr_fixed_byte_array :default, initial_length: :rhs_bytecount
        end
      end

      class EpmDecodedTowerOctetString < Ndr::NdrStruct
        default_parameters byte_align: 1
        endian :little

        uint16                                 :floor_count, byte_align: 1, initial_value: 5
        epm_floor_interface_or_data_identifier :interface_identifier
        epm_floor_interface_or_data_identifier :data_representation
        epm_floor_protocol_identifier          :protocol_identifier
        epm_floor_pipe_or_host                 :pipe_or_host, onlyif: -> {self.floor_count == 4}
        epm_floor_pipe_or_port                 :pipe_or_port, onlyif: -> {self.floor_count == 5}
        epm_floor_host_or_addr                 :host_or_addr, onlyif: -> {self.floor_count == 5}
        # TODO:
        #epm_floor4_decnet                      :session_ctrl, only_if: -> {self.floor_count == 6}
        #epm_floor5_decnet                      :nsp_transport, only_if: -> {self.floor_count == 6}
        #epm_floor6_decnet                      :nsap_routing, only_if: -> {self.floor_count == 6}
      end

      class EpmTowerOctetString < Ndr::NdrConfArray
        default_parameters type: :ndr_uint8
      end

      # [2.2.1.2.2 twr_t Type](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/7888714d-0c2a-48a0-b39a-6062ee3fd1d7)
      class EpmTwrt < Ndr::NdrStruct
        default_parameters byte_align: 4
        endian :little

        ndr_uint32             :tower_length, initial_value: -> { self.tower_octet_string.num_bytes }
        epm_tower_octet_string :tower_octet_string

        def assign(val)
          case val
          when String
            self.tower_octet_string.assign(val.bytes)
          when Array
            self.tower_octet_string.assign(val.to_ary)
          when EpmDecodedTowerOctetString
            self.tower_octet_string.assign(val.to_binary_s.bytes)
          else
            super
          end
        end
      end

      class EpmTwrpt < EpmTwrt
        default_parameters referent_byte_align: 4
        extend Ndr::PointerClassPlugin
      end

    end
  end
end

