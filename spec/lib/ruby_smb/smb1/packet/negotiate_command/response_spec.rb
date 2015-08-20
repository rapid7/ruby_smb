RSpec.describe RubySMB::SMB1::Packet::NegotiateCommand::Response do

  subject(:negotiate_response) { described_class.new }

  it_behaves_like 'smb1_packet'

  describe '#parse' do
    context 'core dialect' do
      let(:input) do
        "\xFF\x53\x4d\x42\x72\x00\x00\x00" \
        "\x00\x18\x01H\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\xFF\xFF\x00\x00\x00\x00\x00\x00" \
        "\x01\x00\x01\x00\x00"
      end

      it 'returns a response instance with prepopulated values' do
        response = RubySMB::SMB1::Packet::NegotiateCommand::Response.parse(input)

        expect(response.smb_header.protocol).to eq(RubySMB::SMB1::SMB_PROTOCOL_ID)
        expect(response.smb_header.command).to eq(RubySMB::SMB1::COMMANDS[:SMB_COM_NEGOTIATE])
        expect(response.smb_parameter_block.word_count).to eq(1)
        expect(response.smb_parameter_block.words).to eq("\x00\x01")
      end
    end

    context 'nt lm dialect' do
      let(:input) do
        "\xFF\x53\x4d\x42\x72\x00\x00\x00" \
        "\x00\x18\x01H\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\xFF\xFF\x00\x00\x00\x00\x00\x00" \
        "\x11\x00\x02\x01\x00\x06\x00\x07" \
        "\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00\x00" \
        "\x00\x00\x00\x00\x00\x00\x00"
      end

      it 'returns a response instance with prepopulated values' do
        response = RubySMB::SMB1::Packet::NegotiateCommand::Response.parse(input)

        expect(response.smb_header.protocol).to eq(RubySMB::SMB1::SMB_PROTOCOL_ID)
        expect(response.smb_header.command).to eq(RubySMB::SMB1::COMMANDS[:SMB_COM_NEGOTIATE])
        expect(response.smb_parameter_block.word_count).to eq(17)
        expect(response.nt_lm_response_block.security_mode).to eq(1)
        expect(response.nt_lm_response_block.max_mpx_count).to eq(6)
        expect(response.nt_lm_response_block.max_number_vcs).to eq(7)
      end
    end
  end

  describe '#valid' do
    it 'is is valid if word count or byte count is set' do
      expect(negotiate_response.valid?).to be false
      negotiate_response.smb_parameter_block.words = 'dialects?'
      expect(negotiate_response.valid?).to be true
    end
  end
end