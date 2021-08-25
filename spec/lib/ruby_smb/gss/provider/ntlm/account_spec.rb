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
