require 'ruby_smb/smb2'
require 'support/shared/examples/request'

RSpec.describe RubySMB::SMB2::Packet::QueryDirectoryRequest do
  subject(:packet) do
    described_class.new(data)
  end

  context 'with packet bytes' do
    let(:data) do
      [
        "fe534d4240000100000000000e00811f0000000000000000df00000000000000" \
        "0000000005000000110000000004000000000000000000000000000000000000" \
        "21002500000000002d00000010000000dd000000ffffffff60000200ffff0000" \
        "2a00"
      ].pack('H*')
    end

    it_behaves_like "packet"
    it_behaves_like "request", RubySMB::SMB2::COMMANDS[:QUERY_DIRECTORY]

    context 'body' do
      specify 'struct_size' do
        expect(packet.struct_size).to eq(33)
      end
      specify 'file_info_class' do
        expect(packet.file_info_class).to eq(
          RubySMB::SMB2::Packet::FILE_INFORMATION_CLASSES[:FileIdBothDirectoryInformation]
        )
      end
      specify 'flags' do
        expect(packet.flags).to eq(0)
      end
      specify 'file_index' do
        expect(packet.file_index).to eq(0)
      end
      specify 'file_id' do
        expect(packet.file_id).to eq(["2d00000010000000dd000000ffffffff"].pack("H*"))
      end

      specify 'file_name' do
        expect(packet.file_name_length).to eq(2)
        expect(packet.file_name_offset).to eq(0x60)
        expect(packet.file_name).to eq(["2a00"].pack("H*"))
      end

      specify 'output_buffer_length' do
        expect(packet.output_buffer_length).to eq(65_535)
      end
    end

  end

end
