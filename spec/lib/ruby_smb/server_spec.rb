RSpec.describe RubySMB::Server do
  before(:each) do
    allow(::TCPServer).to receive(:new).and_return(::TCPServer.new(0))
  end

  it { is_expected.to respond_to :gss_provider }
  it { is_expected.to respond_to :server_guid }

  describe '#initialize' do
    it 'should bind to TCP port 445 by default' do
      expect(::TCPServer).to receive(:new).with(445).and_return(::TCPServer.new(0))
      described_class.new
    end

    it 'should create a new NTLM GSS provider by default' do
      expect(RubySMB::Gss::Provider::NTLM).to receive(:new).and_call_original
      described_class.new
    end

    it 'should generate a random 16-byte GUID' do
      server_guid = described_class.new.server_guid
      expect(server_guid).to be_a String
      expect(server_guid.length).to eq 16
      expect(server_guid).to_not eq described_class.new.server_guid
    end
  end
end
