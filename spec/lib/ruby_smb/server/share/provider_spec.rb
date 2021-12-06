RSpec.describe RubySMB::Server::Share::Provider::Base do
  let(:name) { 'share' }
  subject(:share_provider) { described_class.new(name) }

  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to :type }

  describe '#initialize' do
    it 'sets the name' do
      expect(share_provider.name).to eq name
    end
  end
end
