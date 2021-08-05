require 'spec_helper'

RSpec.describe RubySMB::Gss::Provider::NTLM do
  let(:provider) { described_class.new }

  it { is_expected.to respond_to :allow_anonymous }
  it { is_expected.to respond_to :default_domain }

  describe '#initialize' do
    it 'defaults to false for allowing anonymous access' do
      expect(provider.allow_anonymous).to be false
    end

    it 'defaults to a default domain of WORKGROUP' do
      expect(provider.default_domain).to eq 'WORKGROUP'
    end

    it 'defaults to a random challenge generator' do
      expect(provider.generate_server_challenge).to_not eq provider.generate_server_challenge
    end
  end

  describe '#generate_server_challenge' do
    it 'generates a valid 8-byte challenge' do
      challenge = provider.generate_server_challenge
      expect(challenge).to be_a String
      expect(challenge.length).to eq 8
    end

    it 'should take a generator block' do
      random_challenge = Random.bytes(8)
      provider.generate_server_challenge do
        random_challenge
      end
      expect(provider.generate_server_challenge).to eq random_challenge
    end
  end

  describe '#get_account' do
    let(:username) { 'RubySMB' }
    let(:password) { 'password' }
    let(:domain) { 'WORKGROUP' }

    context 'when getting accounts' do
     before(:each) do
       provider.put_account(username, password)
     end

     it 'should return nil for an unknown account' do
       account = provider.get_account('Spencer')
       expect(account).to be_nil
     end

     it 'should work with a case sensitive name' do
       account = provider.get_account(username)
       expect(account).to be_a RubySMB::Gss::Provider::NTLM::Account
       expect(account.username).to eq username
     end

     it 'should work with a case insensitive name' do
       account = provider.get_account(username.downcase)
       expect(account).to be_a RubySMB::Gss::Provider::NTLM::Account
       expect(account.username).to eq username
     end

     it 'should work with a case sensitive domain' do
       account = provider.get_account(username, domain: domain)
       expect(account).to be_a RubySMB::Gss::Provider::NTLM::Account
       expect(account.domain).to eq domain
     end

     it 'should work with a case insensitive domain' do
       account = provider.get_account(username, domain: domain.downcase)
       expect(account).to be_a RubySMB::Gss::Provider::NTLM::Account
       expect(account.domain).to eq domain
     end

     it 'should work with the special . domain' do
       account = provider.get_account(username, domain: '.')
       expect(account).to be_a RubySMB::Gss::Provider::NTLM::Account
       expect(account.domain).to eq domain
     end

     # UTF-16LE is optionally used for encoding some Net-NTLM message fields, the #get_account method should handle it
     # transparently
     it 'should work with a UTF16-LE name' do
       account = provider.get_account(username.encode('UTF-16LE'))
       expect(account).to be_a RubySMB::Gss::Provider::NTLM::Account
       expect(account.username).to eq username
     end

     it 'should work with a UTF16-LE domain' do
       account = provider.get_account(username, domain: domain.encode('UTF-16LE'))
       expect(account).to be_a RubySMB::Gss::Provider::NTLM::Account
       expect(account.domain).to eq domain
     end
    end

    context 'when putting accounts' do
     it 'should accept new accounts with the default domain' do
       provider.put_account(username, password)
     end

     after(:each) do
       account = provider.get_account(username, domain: domain)
       expect(account).to be_a RubySMB::Gss::Provider::NTLM::Account
       expect(account.username).to eq username
       expect(account.password).to eq password
       expect(account.domain).to eq domain
     end
    end
  end
end

RSpec.describe RubySMB::Gss::Provider::NTLM::Account do
  let(:username) { 'RubySMB' }
  let(:password) { 'password' }
  let(:domain) { 'WORKGROUP' }
  subject(:account) { RubySMB::Gss::Provider::NTLM::Account.new(username, password, domain) }

  it { is_expected.to respond_to :username }
  it { is_expected.to respond_to :password }
  it { is_expected.to respond_to :domain }

  it 'sets the username correct' do
    expect(account.username).to eq username
  end

  it 'sets the password correctly' do
    expect(account.password).to eq password
  end

  it 'sets the domain correctly' do
    expect(account.domain).to eq domain
  end

  describe '#to_s' do
    it 'converts to a string' do
      expect(account.to_s).to be_a String
    end

    it 'formats the username and domain correctly' do
      expect(account.to_s).to eq "#{domain}\\#{username}"
    end
  end
end

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
      authenticator.server_challenge = Random.bytes(8)
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
