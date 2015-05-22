require 'smb2'
require 'support/shared/examples/request'

RSpec.describe Smb2::Packet::TreeConnectRequest do
  subject(:packet) do
    described_class.new(data)
  end

  context 'with IPC$' do
    let(:data) do
      [
        "fe534d4240000100000000000300010000000000000000000300000000000000" \
        "fffe000000000000190000000004000000000000000000000000000000000000" \
        "0900000048002c005c005c003100390032002e003100360038002e0031003000" \
        "30002e003100340030005c004900500043002400"
      ].pack('H*')
    end

    it_behaves_like "packet"
    it_behaves_like "request", Smb2::COMMANDS[:TREE_CONNECT]

    specify 'body' do
      expect(packet.struct_size).to eq(9)
      expect(packet.tree).to eq(
        [
          # "\\\\192.168.100.140\\IPC$" in unicode
          "5c005c003100390032002e003100360038002e003100300030002e0031003400" \
          "30005c004900500043002400"
        ].pack("H*")
      )
      expect(packet.tree_offset).to eq(0x48) # 72
      expect(packet.tree_length).to eq(44)
    end

  end

end
