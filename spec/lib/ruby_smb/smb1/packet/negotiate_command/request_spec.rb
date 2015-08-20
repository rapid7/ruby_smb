RSpec.describe RubySMB::SMB1::Packet::NegotiateCommand::Request do

  subject(:negotiate_request) { described_class.new }

  it_behaves_like 'smb1_packet'

  before do
    subject.initialize_command
  end

  it 'sets the Command field to SMB_COM_NEGOTIATE' do
    expect(negotiate_request.smb_header.command).to eq RubySMB::SMB1::COMMANDS[:SMB_COM_NEGOTIATE]
  end

  describe '#set_dialects' do

    it 'raises an ArgumentError if passed a non-Enumerable parameter' do
      expect{ negotiate_request.set_dialects('foo') }.to raise_error ArgumentError, 'Must be an Array of Dialects'
    end
  end
end