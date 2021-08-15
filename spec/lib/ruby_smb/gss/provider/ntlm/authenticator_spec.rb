RSpec.describe RubySMB::Gss::Provider::NTLM::Authenticator do
  let(:username) { 'RubySMB' }
  let(:domain) { 'WORKGROUP' }
  let(:provider) { RubySMB::Gss::Provider::NTLM.new.tap { |provider| provider.put_account(username, 'password', domain: domain) } }
  let(:authenticator) { described_class.new(provider, nil) }
  let(:type1_msg) do
    Net::NTLM::Message::Type1.new.tap do |msg|
      msg.domain = domain
    end
  end
  let(:type3_msg) do
    Net::NTLM::Message::Type2.new.response(user: username, password: '', domain: domain)
  end

  describe '#initialize' do
    it 'defaults to a null session key' do
      expect(authenticator.session_key).to be_nil
    end

    it 'defaults to a null server challenge' do
      expect(authenticator.server_challenge).to be_nil
    end
  end

  describe '#process' do
    it 'should handle an empty GSS buffer' do
      result = authenticator.process
      expect(result).to be_a RubySMB::Gss::Provider::Result
      expect(result.nt_status).to eq WindowsError::NTStatus::STATUS_SUCCESS
      expect(result.buffer).to_not be_empty
      expect(result.identity).to be_nil
    end

    it 'should handle an embedded NTLM type 1 message' do
      expect(authenticator).to receive(:process_ntlm_type1).and_call_original
      result = authenticator.process(RubySMB::Gss.gss_type1(type1_msg.serialize))
      expect(result).to be_a RubySMB::Gss::Provider::Result
      expect(result.nt_status).to eq WindowsError::NTStatus::STATUS_MORE_PROCESSING_REQUIRED
      expect(result.buffer).to_not be_empty
      expect(result.identity).to be_nil
      expect(authenticator.session_key).to be_nil
    end

    it 'should handle an embedded NTLM type 3 message' do
      authenticator.server_challenge = Random.new.bytes(8)
      expect(authenticator).to receive(:process_ntlm_type3).and_call_original
      result = authenticator.process(RubySMB::Gss.gss_type3(type3_msg.serialize))
      expect(result).to be_a RubySMB::Gss::Provider::Result
      expect(result.nt_status).to eq WindowsError::NTStatus::STATUS_LOGON_FAILURE
      expect(result.buffer).to be_nil
      expect(result.identity).to be_nil
      expect(authenticator.session_key).to be_nil
    end
  end

  describe '#process_ntlm_type1' do
    it 'should process a NTLM type 1 message and return a type2 message' do
      expect(authenticator.process_ntlm_type1(type1_msg)).to be_a Net::NTLM::Message::Type2
    end
  end

  describe '#process_ntlm_type3' do
    it 'should process a NTLM type 3 message and return an error code' do
      expect(authenticator.process_ntlm_type3(type3_msg)).to be_a WindowsError::ErrorCode
    end
  end
end
