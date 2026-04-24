module RubySMB
  module Nbss
    # Single entry in the NODE_NAME_ARRAY of a Node Status Response,
    # as defined in [RFC 1002 4.2.18](https://tools.ietf.org/html/rfc1002#section-4.2.18).
    # Fixed 18-byte layout (15-byte name, 1-byte suffix, 16-bit flags).
    class NodeStatusName < BinData::Record
      # NAME_FLAGS bits (RFC 1002 4.2.18).
      GROUP_BIT = 0x8000   # 1 = group name, 0 = unique name
      ACTIVE_BIT = 0x0400  # 1 = name registered

      endian :big

      string :netbios_name, label: 'NetBIOS Name', length: 15
      uint8  :suffix,       label: 'Suffix'
      uint16 :name_flags,   label: 'Name Flags'

      def group?
        (name_flags & GROUP_BIT) != 0
      end

      def unique?
        !group?
      end

      def active?
        (name_flags & ACTIVE_BIT) != 0
      end
    end

    # NetBIOS Name Service (NBNS) Node Status Response packet, as defined in
    # [RFC 1002 4.2.18](https://tools.ietf.org/html/rfc1002#section-4.2.18).
    # Received over UDP from port 137 in reply to a {NodeStatusRequest}.
    # Does not decode the trailing STATISTICS field; callers only need the
    # name table.
    class NodeStatusResponse < BinData::Record
      endian :big

      # 12-byte NBNS header.
      uint16 :transaction_id, label: 'Transaction ID'
      uint16 :flags,          label: 'Flags'
      uint16 :qdcount,        label: 'QDCount'
      uint16 :ancount,        label: 'ANCount'
      uint16 :nscount,        label: 'NSCount'
      uint16 :arcount,        label: 'ARCount'

      # Answer section. Microsoft's implementation omits the question-echo,
      # so the owner name appears directly after the header.
      netbios_name :owner_name, label: 'Owner Name'
      uint16 :rr_type,          label: 'RR Type'
      uint16 :rr_class,         label: 'RR Class'
      uint32 :ttl,              label: 'TTL'
      uint16 :rdlength,         label: 'RDLENGTH'

      # RDATA begins here. NODE_NAME_ARRAY is preceded by an 8-bit count.
      uint8  :num_names,        label: 'Number of Names'
      array  :node_names, type: :node_status_name, initial_length: :num_names

      # Returns the unique (non-group) file-server name (suffix 0x20) if one
      # is present in the name table, else nil.
      def file_server_name
        entry = node_names.find { |n| n.suffix == 0x20 && n.unique? }
        entry&.netbios_name&.to_s&.rstrip
      end
    end
  end
end
