require 'smb2'

describe Smb2::Packet::CreateResponse do
  subject(:packet) do
    described_class.new(data)
  end

  context 'with srvsvc' do
    let(:data) do
      [
        "fe534d4240000100000000000500010001000000000000000500000000000000" \
        "fffe000001000000190000000004000000000000000000000000000000000000" \
        "5900000001000000000000000000000000000000000000000000000000000000" \
        "0000000000000000001000000000000000000000000000008000000076007300" \
        "250000000000000001000000ffffffff0000000000000000"
      ].pack('H*')
    end

    specify 'header' do
      expect(packet.header.magic).to eq("\xfeSMB".force_encoding("binary"))
      expect(packet.header.signature).to eq(("\x00"*16).force_encoding("binary"))
      expect(packet.header.command).to eq(Smb2::Commands::CREATE)
    end

    specify 'body' do
      expect(packet.struct_size).to eq(0x59)
      expect(packet.oplock).to eq(0)
      expect(packet.create_action).to eq(1)
      expect(packet.creation_time).to eq(0)
      expect(packet.last_action_time).to eq(0)
      expect(packet.last_write_time).to eq(0)
      expect(packet.change_time).to eq(0)
      expect(packet.allocation_size).to eq(4096)
      expect(packet.end_of_file).to eq(0)
      expect(packet.file_attributes).to eq(0x0000_0080)

      #expect(packet.reserved2).to eq(0)
      expect(packet.file_id).to eq(["250000000000000001000000ffffffff"].pack('H*'))
    end

  end

end


