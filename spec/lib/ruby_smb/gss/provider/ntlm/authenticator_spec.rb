RSpec.describe RubySMB::Gss::Provider::NTLM::Authenticator do
  let(:username) { 'RubySMB' }
  let(:domain) { 'WORKGROUP' }
  let(:password) { 'password' }
  let(:provider) { RubySMB::Gss::Provider::NTLM.new.tap { |provider| provider.put_account(username, password, domain: domain) } }
  let(:authenticator) { described_class.new(provider, nil) }
  let(:type1_msg) do
    Net::NTLM::Message::Type1.new.tap do |msg|
      msg.domain = domain
    end
  end
  let(:type2_msg) do
    Net::NTLM::Message::Type2.new
  end
  let(:type3_msg) do
    type2_msg.response({user: username, password: password, domain: domain}, {ntlmv2: true})
  end

  before(:each) do
    allow(authenticator).to receive(:logger).and_return(Logger.new(IO::NULL))
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
    context 'when the message is anonymous' do
      let(:type3_msg) do
        type2_msg.response({user: '', password: ''}, {ntlmv2: true})
      end

      context 'when anonymous access is disabled' do
        before(:each) do
          expect(provider).to_not receive(:allow_guests)
          expect(provider).to receive(:allow_anonymous).and_return(false)
        end

        it 'should process a NTLM type 3 message and return STATUS_LOGON_FAILURE' do
          status = authenticator.process_ntlm_type3(type3_msg)
          expect(status).to be_a WindowsError::ErrorCode
          expect(status).to eq WindowsError::NTStatus::STATUS_LOGON_FAILURE
        end

        after(:each) do
          expect(authenticator.session_key).to be_nil
        end
      end

      context 'when anonymous access is enabled' do
        before(:each) do
          expect(provider).to_not receive(:allow_guests)
          expect(provider).to receive(:allow_anonymous).and_return(true)
        end

        it 'should process a NTLM type 3 message and return STATUS_SUCCESS' do
          status = authenticator.process_ntlm_type3(type3_msg)
          expect(status).to be_a WindowsError::ErrorCode
          expect(status).to eq WindowsError::NTStatus::STATUS_SUCCESS
        end

        after(:each) do
          expect(authenticator.session_key).to eq "\x00".b * 16
        end
      end
    end

    context 'when the message is a guest' do
      let(:type3_msg) do
        type2_msg.response({user: 'Spencer', password: password}, {ntlmv2: true})
      end

      context 'when guest access is disabled' do
        before(:each) do
          expect(provider).to_not receive(:allow_anonymous)
          expect(provider).to receive(:allow_guests).and_return(false)
        end

        it 'should process a NTLM type 3 message and return STATUS_LOGON_FAILURE' do
          status = authenticator.process_ntlm_type3(type3_msg)
          expect(status).to be_a WindowsError::ErrorCode
          expect(status).to eq WindowsError::NTStatus::STATUS_LOGON_FAILURE
        end

        after(:each) do
          expect(authenticator.session_key).to be_nil
        end
      end

      context 'when guest access is enabled' do
        before(:each) do
          expect(provider).to_not receive(:allow_anonymous)
          expect(provider).to receive(:allow_guests).and_return(true)
        end

        it 'should process a NTLM type 3 message and return STATUS_SUCCESS' do
          status = authenticator.process_ntlm_type3(type3_msg)
          expect(status).to be_a WindowsError::ErrorCode
          expect(status).to eq WindowsError::NTStatus::STATUS_SUCCESS
        end

        after(:each) do
          expect(authenticator.session_key).to eq "\x00".b * 16
        end
      end
    end

    context 'when the message is a known user' do
      before(:each) do
        authenticator.instance_variable_set(:@server_challenge, type2_msg[:challenge].serialize)
      end

      context 'when the password is correct' do
        it 'should process a NTLM type 3 message and return STATUS_SUCCESS' do
          status = authenticator.process_ntlm_type3(type3_msg)
          expect(status).to be_a WindowsError::ErrorCode
          expect(status).to eq WindowsError::NTStatus::STATUS_SUCCESS
        end

        after(:each) do
          expect(authenticator.session_key).to be_a String
          expect(authenticator.session_key.length).to eq 16
        end
      end

      context 'when the password is wrong' do
        let(:type3_msg) do
          type2_msg.response({user: username, password: 'Wrong' + password, domain: domain}, {ntlmv2: true})
        end

        it 'should process a NTLM type 3 message and return STATUS_LOGON_FAILURE' do
          status = authenticator.process_ntlm_type3(type3_msg)
          expect(status).to be_a WindowsError::ErrorCode
          expect(status).to eq WindowsError::NTStatus::STATUS_LOGON_FAILURE
        end

        after(:each) do
          expect(authenticator.session_key).to be nil
        end
      end
    end
  end

  describe '#reset!' do
    it 'should clear the server challenge' do
      authenticator.instance_variable_set(:@server_challenge, Random.new.bytes(8))
      authenticator.reset!
      expect(authenticator.instance_variable_get(:@server_challenge)).to be_nil
    end

    it 'should clear the session key' do
      authenticator.instance_variable_set(:@session_key, Random.new.bytes(16))
      authenticator.reset!
      expect(authenticator.instance_variable_get(:@session_key)).to be_nil
    end
  end

  describe 'a full Net-NTLMv2 authentication exchange' do
    let(:type2_msg) { authenticator.process_ntlm_type1(type1_msg)}

    it 'should respond to a correct password with STATUS_SUCCESS' do
      type3_msg = type2_msg.response({user: username, domain: domain, password: password}, ntlmv2: true)
      type3_msg.user.force_encoding('UTF-16LE')
      type3_msg.domain.force_encoding('UTF-16LE')
      expect(authenticator.process_ntlm_type3(type3_msg)).to eq WindowsError::NTStatus::STATUS_SUCCESS
    end

    it 'should respond to an incorrect password with STATUS_LOGON_FAILURE' do
      type3_msg = type2_msg.response({user: username, domain: domain, password: password + rand(0x41..0x5b).chr}, ntlmv2: true)
      type3_msg.user.force_encoding('UTF-16LE')
      type3_msg.domain.force_encoding('UTF-16LE')
      expect(authenticator.process_ntlm_type3(type3_msg)).to eq WindowsError::NTStatus::STATUS_LOGON_FAILURE
    end
  end
end
