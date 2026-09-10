require 'socket'
require 'ipaddr'
require 'securerandom'

module RubySMB
  module Nbss
    # Pure-Ruby implementation of `nmblookup -A <ip>`: sends an NBNS Node
    # Status Request (RFC 1002 4.2.17) over UDP/137 and returns the
    # server's name table.
    #
    # No external binaries are invoked. Compare to Samba's `nmblookup`,
    # which shells out and requires the `samba-common-bin` package to be
    # installed.
    module NodeStatus
      NBNS_PORT = 137

      # Default per-attempt receive timeout, in seconds.
      DEFAULT_TIMEOUT = 2.0

      # Default number of attempts before giving up.
      DEFAULT_RETRIES = 3

      # One entry in the returned name table.
      #
      # @!attribute [rw] name [String] the NetBIOS name (trimmed)
      # @!attribute [rw] suffix [Integer] 1-byte NetBIOS suffix
      # @!attribute [rw] group [Boolean] true for a group name, false for unique
      # @!attribute [rw] active [Boolean] true if the name is registered
      Entry = Struct.new(:name, :suffix, :group, :active) do
        def unique?
          !group
        end

        # Human-readable form like `WIN95            <20> UNIQUE ACTIVE`.
        def to_s
          flags = [group ? 'GROUP' : 'UNIQUE', active ? 'ACTIVE' : 'INACTIVE'].join(' ')
          format('%-16s <%02X> %s', name, suffix, flags)
        end
      end

      # Query a host for its NetBIOS name table.
      #
      # NBNS is IPv4-only and this is a unicast query, so `host` must be a
      # numeric IPv4 address (e.g. `10.0.0.1`). A hostname is rejected because
      # replies are matched against the numeric peer address returned by
      # `recvfrom`, which a hostname would never equal.
      #
      # @param host [String] target IPv4 address (unicast — no broadcast)
      # @param port [Integer] destination UDP port (default 137)
      # @param timeout [Numeric] per-attempt receive timeout in seconds
      # @param retries [Integer] total number of attempts
      # @param udp_socket [UDPSocket, Rex::Socket::Udp] caller-owned UDP socket.
      #   The caller is responsible for binding and closing it. It must
      #   implement `#send(mesg, flags, host, port)` and `#recvfrom(maxlen)`,
      #   and leave `do_not_reverse_lookup` at its default so `recvfrom` does
      #   not perform a reverse DNS lookup per datagram.
      # @return [Array<Entry>, nil] the name table, or nil on timeout/parse failure
      # @raise [ArgumentError] if `host` is not a numeric IPv4 address
      def self.query(host, port: NBNS_PORT, timeout: DEFAULT_TIMEOUT,
                     retries: DEFAULT_RETRIES, udp_socket:)
        expected_address = begin
          IPAddr.new(host).native
        rescue IPAddr::InvalidAddressError
          raise ArgumentError, "host must be an IPv4 address, got #{host.inspect}"
        end
        raise ArgumentError, "NBNS is IPv4-only, got #{host.inspect}" unless expected_address.ipv4?

        request = NodeStatusRequest.new(transaction_id: SecureRandom.random_number(0x10000))
        bytes = request.to_binary_s

        retries.times do
          begin
            udp_socket.send(bytes, 0, host, port)
            next unless IO.select([udp_socket], nil, nil, timeout)

            data, addr = udp_socket.recvfrom(4096)
            next if data.nil? || data.empty?
            next unless source_matches?(addr, expected_address)

            response = NodeStatusResponse.read(data)
            # Reject anything that isn't the response to our own query.
            next unless response.transaction_id.to_i == request.transaction_id.to_i
            next unless response.opcode.response.to_i == 1
            next unless response.rr_type.to_i == NodeStatusRequest::QUESTION_TYPE_NBSTAT

            return entries_from(response)
          rescue IOError, EOFError, SystemCallError
            next
          end
        end
        nil
      end

      # Return the unique file-server name (suffix 0x20) from a host, or nil
      # if the name table doesn't contain one. Convenience helper for the
      # common case of "give me this host's file-server name."
      #
      # @param host [String] target IPv4 address
      # @param kwargs [Hash] forwarded to {.query}
      # @return [String, nil]
      def self.file_server_name(host, **kwargs)
        entries = query(host, **kwargs) or return nil
        entry = entries.find { |e| e.suffix == 0x20 && e.unique? }
        entry&.name
      end

      def self.entries_from(response)
        response.node_names.map do |n|
          Entry.new(
            n.netbios_name.to_s.rstrip,
            n.suffix.to_i,
            n.group?,
            n.active?
          )
        end
      end
      private_class_method :entries_from

      # Accept a reply only when it comes from the queried address. `recvfrom`
      # returns the numeric peer address, which is compared against the
      # normalized target. A nil/unknown source (e.g. a mock socket) is allowed.
      def self.source_matches?(addr, expected_address)
        source = addr.is_a?(Array) ? addr[3] : nil
        return true if source.nil?

        source_address = begin
          IPAddr.new(source).native
        rescue IPAddr::InvalidAddressError
          return false
        end
        source_address == expected_address
      end
      private_class_method :source_matches?
    end
  end
end
