require 'socket'

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
      # @!attribute [r] name [String] the NetBIOS name (trimmed)
      # @!attribute [r] suffix [Integer] 1-byte NetBIOS suffix
      # @!attribute [r] group [Boolean] true for a group name, false for unique
      # @!attribute [r] active [Boolean] true if the name is registered
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
      # @param host [String] target IP address (unicast — no broadcast)
      # @param port [Integer] destination UDP port (default 137)
      # @param timeout [Numeric] per-attempt receive timeout in seconds
      # @param retries [Integer] total number of attempts
      # @param udp_socket_factory [#call] callable returning a UDP-like socket.
      #   Default uses stdlib `UDPSocket.new`. Metasploit callers can inject
      #   `Rex::Socket::Udp.create`-based factories to pivot over a session.
      # @return [Array<Entry>, nil] the name table, or nil on timeout/parse failure
      def self.query(host, port: NBNS_PORT, timeout: DEFAULT_TIMEOUT,
                     retries: DEFAULT_RETRIES,
                     udp_socket_factory: -> { UDPSocket.new })
        request = NodeStatusRequest.new(transaction_id: rand(0xFFFF))
        request.question_name.set('*'.ljust(16, "\x00"))
        bytes = request.to_binary_s

        sock = udp_socket_factory.call
        begin
          # Windows 9x ignores the client's source port and replies to
          # destination port 137 (RFC 1002's default), so the kernel will
          # drop responses on an ephemeral-port socket. Try to bind locally
          # to 137 — same trick Samba's nmblookup uses. Bind may fail when
          # we don't have CAP_NET_BIND_SERVICE / root, or when another
          # process already holds the port; either way we fall through and
          # keep the ephemeral port, which still works against servers
          # that honor the request's source port.
          bind_local(sock, port)

          retries.times do
            send_datagram(sock, bytes, host, port)
            data = recv_datagram(sock, 4096, timeout)
            next if data.nil? || data.empty?

            response = NodeStatusResponse.read(data)
            return entries_from(response)
          end
          nil
        rescue IOError, EOFError
          nil
        ensure
          sock.close if sock.respond_to?(:close)
        end
      end

      # Return the unique file-server name (suffix 0x20) from a host, or nil
      # if the name table doesn't contain one. Convenience helper for the
      # common case of "give me this host's file-server name."
      #
      # @param host [String] target IP address
      # @param kwargs [Hash] forwarded to {.query}
      # @return [String, nil]
      def self.file_server_name(host, **kwargs)
        entries = query(host, **kwargs) or return nil
        entry = entries.find { |e| e.suffix == 0x20 && e.unique? }
        entry&.name
      end

      # @!visibility private
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

      # Best-effort bind of a UDP socket's local port to `port` (default
      # 137). Required for Win9x NBNS replies, which ignore the client's
      # source port and always answer to destination port 137. Silently
      # swallows EACCES (unprivileged) and EADDRINUSE (another listener)
      # so the caller keeps the ephemeral bind.
      #
      # @!visibility private
      def self.bind_local(sock, port)
        return unless sock.respond_to?(:bind)
        sock.bind('0.0.0.0', port)
      rescue Errno::EACCES, Errno::EADDRINUSE, SystemCallError
        # keep whatever source port the factory already assigned
      end

      # Send `bytes` to `host:port` over `sock`. stdlib `UDPSocket#send`
      # takes (mesg, flags, host, port); Rex::Socket::Udp's socket inherits
      # `send(mesg, flags, [sockaddr])` from Socket and exposes the 4-arg
      # form as `sendto(mesg, host, port)`. Prefer `sendto` when available.
      #
      # @!visibility private
      def self.send_datagram(sock, bytes, host, port)
        if sock.respond_to?(:sendto)
          sock.sendto(bytes, host, port)
        else
          sock.send(bytes, 0, host, port)
        end
      end

      # Read a datagram from `sock` with a timeout, picking the pattern
      # appropriate for the socket. Rex::Socket::Udp#recvfrom takes a
      # built-in timeout as the 2nd argument and selects on its internal
      # fd (IO.select([sock]) can miss wakeups on wrapped sockets). stdlib
      # UDPSocket#recvfrom has no timeout, so wrap it in IO.select.
      #
      # @!visibility private
      def self.recv_datagram(sock, length, timeout)
        if sock.respond_to?(:sendto)
          data, = sock.recvfrom(length, timeout)
          data
        else
          return nil unless IO.select([sock], nil, nil, timeout)
          data, = sock.recvfrom(length)
          data
        end
      end
    end
  end
end
