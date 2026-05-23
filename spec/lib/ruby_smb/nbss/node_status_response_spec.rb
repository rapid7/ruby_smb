require 'spec_helper'

RSpec.describe RubySMB::Nbss::NodeStatusResponse do
  def build_response(names)
    data = ''.b
    data << [0x1234].pack('n')         # transaction_id
    data << [0x8400].pack('n')         # flags: response, authoritative
    data << [0].pack('n')              # qdcount
    data << [1].pack('n')              # ancount
    data << [0].pack('n') << [0].pack('n')  # nscount, arcount
    data << [0x20].pack('C') << ('A' * 32) << "\x00".b  # owner name L1
    data << [0x0021].pack('n')         # RR type NBSTAT
    data << [0x0001].pack('n')         # RR class IN
    data << [0].pack('N')              # TTL
    data << [1 + names.length * 18 + 46].pack('n')  # rdlength
    data << [names.length].pack('C')
    names.each do |name, suffix, flags|
      data << name.to_s.ljust(15, ' ') << [suffix].pack('C') << [flags].pack('n')
    end
    data << ("\x00".b * 46)  # statistics (unused)
    data
  end

  describe 'parsing' do
    it 'decodes the name table' do
      response = described_class.read(build_response([
        ['WIN95', 0x00, 0x0400],
        ['WIN95', 0x20, 0x0400],
        ['WORKGROUP', 0x00, 0x8400]
      ]))
      expect(response.num_names).to eq(3)
      expect(response.node_names[0].netbios_name.to_s.rstrip).to eq('WIN95')
      expect(response.node_names[0].suffix).to eq(0x00)
      expect(response.node_names[1].suffix).to eq(0x20)
      expect(response.node_names[2].group?).to be true
    end
  end

  describe '#file_server_name' do
    it 'returns the name with suffix 0x20 and the unique bit clear' do
      response = described_class.read(build_response([
        ['FILESERVER', 0x20, 0x0400],
        ['WORKGROUP', 0x00, 0x8400]
      ]))
      expect(response.file_server_name).to eq('FILESERVER')
    end

    it 'ignores group names even when the suffix matches' do
      response = described_class.read(build_response([
        ['OTHER', 0x20, 0x8400] # group bit set — should be skipped
      ]))
      expect(response.file_server_name).to be_nil
    end

    it 'returns nil when no file-server name is present' do
      response = described_class.read(build_response([
        ['HOST', 0x00, 0x0400]
      ]))
      expect(response.file_server_name).to be_nil
    end
  end
end
