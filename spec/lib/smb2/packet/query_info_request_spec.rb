require 'smb2'
require 'support/shared/examples/request'

describe Smb2::Packet::QueryInfoRequest do
  subject(:packet) do
    described_class.new(data)
  end

  context 'with packet bytes' do
    let(:data) do
      [
        "fe534d4240000100000000001000010000000000000000000600000000000000" \
        "fffe000001000000190000000004000000000000000000000000000000000000" \
        "2900010518000000680000000000000000000000000000002500000000000000" \
        "01000000ffffffff"
      ].pack('H*')
    end

    it_behaves_like "request", Smb2::Commands::QUERY_INFO

    context 'body' do
      specify 'struct_size' do
        expect(packet.struct_size).to eq(41)
      end
      specify 'info_type' do
        expect(packet.info_type).to eq(Smb2::Packet::QUERY_INFO_TYPES[:FILE])
      end
      specify 'file_info_class' do
        expect(packet.file_info_class).to eq(5)
      end
      specify 'output_buffer_length' do
        expect(packet.output_buffer_length).to eq(24)
      end

      specify 'file_id' do
        expect(packet.file_id).to eq(["250000000000000001000000ffffffff"].pack("H*"))
      end
    end

  end

end
