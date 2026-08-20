require 'spec_helper'

RSpec.describe RubySMB::Nbss::NodeStatus do
  let(:udp_sock) { double('UDPSocket') }

  # Node Status requests carry a random transaction ID; the response is only
  # accepted when it echoes that ID back. Pin it so the fixtures match.
  before { allow(described_class).to receive(:rand).and_return(0x1234) }

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
    it 'sends the request with #send(mesg, flags, host, port) and reads via recvfrom(maxlen)' do
      response_bytes = build_response([
        ['WIN95', 0x00, 0x0400],
        ['WIN95', 0x20, 0x0400],
        ['WORKGROUP', 0x00, 0x8400]
      ])

      expect(udp_sock).to receive(:send) do |bytes, flags, host, port|
        expect(flags).to eq(0)
        expect(host).to eq('10.0.0.2')
        expect(port).to eq(137)
        expect(bytes.bytesize).to eq(50)
      end
      expect(IO).to receive(:select).and_return([udp_sock])
      expect(udp_sock).to receive(:recvfrom).with(4096).and_return([response_bytes, nil])

      entries = described_class.query('10.0.0.2', udp_socket: udp_sock)
      expect(entries.size).to eq(3)
      expect(entries[1].name).to eq('WIN95')
      expect(entries[1].suffix).to eq(0x20)
      expect(entries[1].unique?).to be true
      expect(entries[2].group).to be true
    end

    it 'retries up to the configured limit before giving up' do
      call_count = 0
      allow(udp_sock).to receive(:send) { call_count += 1 }
      allow(IO).to receive(:select).and_return(nil) # always time out

      expect(described_class.query('10.0.0.2', retries: 4, timeout: 0.01, udp_socket: udp_sock)).to be_nil
      expect(call_count).to eq(4)
    end

    it 'returns nil when the response can not be parsed' do
      expect(udp_sock).to receive(:send)
      expect(IO).to receive(:select).and_return([udp_sock])
      expect(udp_sock).to receive(:recvfrom).and_return(["\xff\xff".b, nil])
      expect(described_class.query('10.0.0.2', retries: 1, timeout: 0.01, udp_socket: udp_sock)).to be_nil
    end

    it 'rejects a reply whose transaction ID does not match the request' do
      allow(described_class).to receive(:rand).and_return(0x1234)
      mismatched = build_response([['WIN95', 0x20, 0x0400]])
      mismatched[0, 2] = [0x9999].pack('n') # overwrite transaction_id
      expect(udp_sock).to receive(:send)
      expect(IO).to receive(:select).and_return([udp_sock])
      expect(udp_sock).to receive(:recvfrom).and_return([mismatched, nil])
      expect(described_class.query('10.0.0.2', retries: 1, timeout: 0.01, udp_socket: udp_sock)).to be_nil
    end

    it 'rejects a reply from an unexpected source address' do
      spoofed = build_response([['WIN95', 0x20, 0x0400]])
      expect(udp_sock).to receive(:send)
      expect(IO).to receive(:select).and_return([udp_sock])
      expect(udp_sock).to receive(:recvfrom).and_return([spoofed, ['AF_INET', 137, '10.0.0.9', '10.0.0.9']])
      expect(described_class.query('10.0.0.2', retries: 1, timeout: 0.01, udp_socket: udp_sock)).to be_nil
    end

    it 'returns nil on IOError and does not close the socket' do
      allow(udp_sock).to receive(:send).and_raise(IOError, 'boom')
      expect(udp_sock).not_to receive(:close)
      expect(described_class.query('10.0.0.2', retries: 1, udp_socket: udp_sock)).to be_nil
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

      expect(described_class.file_server_name('10.0.0.2', udp_socket: udp_sock)).to eq('FILESERVER')
    end

    it 'returns nil when no unique 0x20 entry is present' do
      response_bytes = build_response([['HOST', 0x00, 0x0400]])
      allow(udp_sock).to receive(:send)
      allow(IO).to receive(:select).and_return([udp_sock])
      allow(udp_sock).to receive(:recvfrom).and_return([response_bytes, nil])

      expect(described_class.file_server_name('10.0.0.2', udp_socket: udp_sock)).to be_nil
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
