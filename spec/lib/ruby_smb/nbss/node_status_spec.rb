require 'spec_helper'

RSpec.describe RubySMB::Nbss::NodeStatus do
  let(:udp_sock) { double('UDPSocket') }
  let(:factory)  { -> { udp_sock } }

  def build_response(names)
    data = ''.b
    data << [0x1234].pack('n')               # transaction_id
    data << [0x8400].pack('n')               # flags
    data << [0].pack('n') << [1].pack('n')   # qdcount, ancount
    data << [0].pack('n') << [0].pack('n')   # nscount, arcount
    data << [0x20].pack('C') << ('A' * 32) << "\x00".b  # owner name
    data << [0x0021].pack('n') << [0x0001].pack('n')
    data << [0].pack('N')                    # TTL
    data << [1 + names.length * 18 + 46].pack('n')
    data << [names.length].pack('C')
    names.each do |name, suffix, flags|
      data << name.to_s.ljust(15, ' ') << [suffix].pack('C') << [flags].pack('n')
    end
    data << ("\x00".b * 46)
    data
  end

  describe '.query' do
    it 'uses stdlib UDPSocket#send(mesg, flags, host, port) when sendto is not available' do
      response_bytes = build_response([
        ['WIN95', 0x00, 0x0400],
        ['WIN95', 0x20, 0x0400],
        ['WORKGROUP', 0x00, 0x8400]
      ])

      # Pure test double doesn't respond to :sendto unless we stub it, so
      # NodeStatus.query falls through to the stdlib 4-arg #send path.
      expect(udp_sock).to receive(:send) do |bytes, flags, host, port|
        expect(flags).to eq(0)
        expect(host).to eq('10.0.0.2')
        expect(port).to eq(137)
        expect(bytes.bytesize).to eq(50)
      end
      expect(IO).to receive(:select).and_return([udp_sock])
      expect(udp_sock).to receive(:recvfrom).and_return([response_bytes, nil])
      expect(udp_sock).to receive(:close)

      entries = described_class.query('10.0.0.2', udp_socket_factory: factory)
      expect(entries.size).to eq(3)
      expect(entries[1].name).to eq('WIN95')
      expect(entries[1].suffix).to eq(0x20)
      expect(entries[1].unique?).to be true
      expect(entries[2].group).to be true
    end

    it 'uses sendto(mesg, host, port) when the socket provides it (Rex::Socket::Udp style)' do
      response_bytes = build_response([['WIN95', 0x20, 0x0400]])
      expect(udp_sock).to receive(:sendto) do |bytes, host, port|
        expect(host).to eq('10.0.0.2')
        expect(port).to eq(137)
        expect(bytes.bytesize).to eq(50)
      end
      allow(IO).to receive(:select).and_return([udp_sock])
      allow(udp_sock).to receive(:recvfrom).and_return([response_bytes, nil])
      allow(udp_sock).to receive(:close)

      entries = described_class.query('10.0.0.2', udp_socket_factory: factory)
      expect(entries.first.name).to eq('WIN95')
    end

    it 'retries up to the configured limit before giving up' do
      call_count = 0
      allow(udp_sock).to receive(:send) { call_count += 1 }
      allow(IO).to receive(:select).and_return(nil) # always time out
      allow(udp_sock).to receive(:close)

      expect(described_class.query('10.0.0.2', retries: 4, timeout: 0.01, udp_socket_factory: factory)).to be_nil
      expect(call_count).to eq(4)
    end

    it 'returns nil when the response can not be parsed' do
      expect(udp_sock).to receive(:send)
      expect(IO).to receive(:select).and_return([udp_sock])
      expect(udp_sock).to receive(:recvfrom).and_return(["\xff\xff".b, nil])
      expect(udp_sock).to receive(:close)
      expect(described_class.query('10.0.0.2', retries: 1, timeout: 0.01, udp_socket_factory: factory)).to be_nil
    end

    it 'closes the socket even on exception' do
      allow(udp_sock).to receive(:send).and_raise(IOError, 'boom')
      expect(udp_sock).to receive(:close)
      expect(described_class.query('10.0.0.2', retries: 1, udp_socket_factory: factory)).to be_nil
    end
  end

  describe '.file_server_name' do
    it 'returns the unique 0x20 entry' do
      response_bytes = build_response([
        ['WORKGROUP', 0x00, 0x8400],
        ['FILESERVER', 0x20, 0x0400]
      ])
      allow(udp_sock).to receive(:send)
      allow(IO).to receive(:select).and_return([udp_sock])
      allow(udp_sock).to receive(:recvfrom).and_return([response_bytes, nil])
      allow(udp_sock).to receive(:close)

      expect(described_class.file_server_name('10.0.0.2', udp_socket_factory: factory)).to eq('FILESERVER')
    end

    it 'returns nil when no unique 0x20 entry is present' do
      response_bytes = build_response([['HOST', 0x00, 0x0400]])
      allow(udp_sock).to receive(:send)
      allow(IO).to receive(:select).and_return([udp_sock])
      allow(udp_sock).to receive(:recvfrom).and_return([response_bytes, nil])
      allow(udp_sock).to receive(:close)

      expect(described_class.file_server_name('10.0.0.2', udp_socket_factory: factory)).to be_nil
    end
  end

  describe RubySMB::Nbss::NodeStatus::Entry do
    it '#to_s formats like nmblookup output' do
      entry = described_class.new('WIN95', 0x20, false, true)
      expect(entry.to_s).to include('WIN95')
      expect(entry.to_s).to include('<20>')
      expect(entry.to_s).to include('UNIQUE')
      expect(entry.to_s).to include('ACTIVE')
    end
  end
end
