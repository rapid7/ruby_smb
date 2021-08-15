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
      random_challenge = Random.new.bytes(8)
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
