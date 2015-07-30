require 'ruby_smb/smb2'

RSpec.describe RubySMB::SMB2::Packet::QueryInfoResponse do
  subject(:packet) do
    described_class.new(data)
  end

  context 'with packet bytes' do
    let(:data) do
      [
        "fe534d4240000100000000001000010001000000000000000600000000000000" \
        "fffe000001000000190000000004000000000000000000000000000000000000" \
        "0900480018000000001000000000000000000000000000000100000001000000"
      ].pack('H*')
    end

    it_behaves_like "packet"

    context 'body' do
      specify 'struct_size' do
        expect(packet.struct_size).to eq(9)
      end
      specify 'output_buffer_offset' do
        expect(packet.output_buffer_offset).to eq(0x48)
      end
      specify 'output_buffer_length' do
        expect(packet.output_buffer_length).to eq(24)
      end
      specify 'output_buffer' do
        expect(packet.output_buffer).to eq(
          [
            "001000000000000000000000000000000100000001000000"
          ].pack("H*")
        )
      end
    end

  end

end
