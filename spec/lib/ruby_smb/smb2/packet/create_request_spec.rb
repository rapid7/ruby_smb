require 'ruby_smb/smb2'
require 'support/shared/examples/request'

RSpec.describe RubySMB::Smb2::Packet::CreateRequest do
  subject(:packet) do
    described_class.new(data)
  end

  context 'with srvsvc' do
    let(:data) do
      [
        "fe534d4240000100000000000500010000000000000000000500000000000000" \
        "fffe000001000000190000000004000000000000000000000000000000000000" \
        "3900000002000000000000000000000000000000000000009f01120000000000" \
        "07000000010000004000400078000c0000000000000000007300720076007300" \
        "76006300"
      ].pack('H*')
    end

    it_behaves_like "packet"
    it_behaves_like "request", RubySMB::Smb2::COMMANDS[:CREATE]

    specify 'body' do
      expect(packet.struct_size).to eq(57)
      expect(packet.oplock).to eq(0)
      expect(packet.security_flags).to eq(0)
      expect(packet.impersonation).to eq(2)
      expect(packet.create_flags).to eq(0)

      expect(packet.reserved).to eq(0)

      # 0x100000 = SYNCHRONIZE
      # 0x20000 = READ_CONTROL
      # 0x100 = FILE_WRITE_ATTRIBUTES
      # 0x90 = FILE_WRITE_EA | FILE_READ_ATTRIBUTES
      # 0xf = FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_EA
      expect(packet.desired_access).to eq(0x0012_019f)
      expect(packet.file_attributes).to eq(0)
      # SHARE_DELETE | SHARE_WRITE | SHARE_READ
      expect(packet.share_access).to eq(7)
      expect(packet.disposition).to eq(1)
      expect(packet.create_options).to eq(0x0040_0040)

      expect(packet.filename.force_encoding('UTF-16le')).to eq("srvsvc".encode('UTF-16le'))
    end

  end

end
