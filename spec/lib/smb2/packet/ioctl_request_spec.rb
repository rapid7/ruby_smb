require 'smb2'
require 'support/shared/examples/request'

describe Smb2::Packet::IoctlRequest do
  subject(:packet) do
    described_class.new(data)
  end

  context 'with FSCTL_VALIDATE_NEGOTIATE_INFO request' do
    let(:data) do
      [
        "fe534d4240000100000000000b00010008000000000000000400000000000000" \
        "fffe000001000000190000000004000037e7a996b56f566226e6fc6aec1204fd" \
        "3900000004021400ffffffffffffffffffffffffffffffff7800000020000000" \
        "0000000078000000000000001800000001000000000000007f000000ec1cb173" \
        "f176e411af9e000c293f25dc010003000202100200030000"
      ].pack('H*')
    end

    it_behaves_like "request", Smb2::Commands::IOCTL

    specify 'struct_size' do
      expect(packet.struct_size).to eq(57)
    end

    specify 'ctrl_code' do
      expect(packet.ctl_code).to eq(0x0014_0204)
    end

    specify 'file_id' do
      expect(packet.file_id).to eq(["ffffffffffffffffffffffffffffffff"].pack('H*'))
    end

    specify 'input_data_offset' do
      expect(packet.input_data_offset).to eq(0x78)
    end

    specify 'input_data_length' do
      expect(packet.input_data_length).to eq(32)
    end

    specify 'input_data' do
      expect(packet.input_data).to eq([
        "7f000000ec1cb173f176e411af9e000c293f25dc010003000202100200030000"
      ].pack("H*"))
    end

    specify 'max_input_response' do
      expect(packet.max_input_response).to eq(0)
    end

    specify 'output_data_offset' do
      expect(packet.output_data_offset).to eq(0x78)
    end

    specify 'output_data_length' do
      expect(packet.output_data_length).to eq(0)
    end

    specify 'max_output_response' do
      expect(packet.max_output_response).to eq(24)
    end

    specify 'flags' do
      expect(packet.flags).to eq(described_class::FLAGS[:SMB2_0_IOCTL_IS_FSCTL])
    end

    specify 'reserved2' do
      expect(packet.reserved2).to eq(0)
    end

  end

end

