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
      expect(response.opcode.response.to_i).to eq(1)
      expect(response.nm_flags.authoritative_answer.to_i).to eq(1)
    end
  end

  describe 'flags' do
    it 'decodes the header OPCODE and NM_FLAGS fields from the second word' do
      response = described_class.read(build_response([['WIN95', 0x20, 0x0400]]))

      expect(response.opcode.response.to_i).to eq(1)          # high bit of 0x8400
      expect(response.nm_flags.authoritative_answer.to_i).to eq(1)
    end

    it 'defines NODE_NAME flags in RFC bit order' do
      flags = RubySMB::Nbss::NodeStatusNameFlags.new
      flags.group = 1
      flags.active = 1

      expect(flags.to_binary_s.unpack1('n')).to eq(0x8400)
      expect(flags.group.to_i).to eq(1)
      expect(flags.active.to_i).to eq(1)
    end

    it 'exposes parsed NODE_NAME flags as named fields' do
      response = described_class.read(build_response([
        ['WORKGROUP', 0x00, 0x8400],
        ['FILESERVER', 0x20, 0x0400]
      ]))

      group_entry = response.node_names[0]
      unique_entry = response.node_names[1]

      expect(group_entry.name_flags.group.to_i).to eq(1)
      expect(group_entry.name_flags.active.to_i).to eq(1)
      expect(group_entry.group?).to be true
      expect(unique_entry.name_flags.group.to_i).to eq(0)
      expect(unique_entry.unique?).to be true
    end
  end
end
