RSpec.describe RubySMB::Server::Share::Provider::Pipe do
  let(:name) { 'share' }
  subject(:share_provider) { described_class.new(name) }

  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to :type }

  describe '#TYPE' do
    it 'is TYPE_PIPE' do
      expect(described_class::TYPE).to eq RubySMB::Server::Share::TYPE_PIPE
    end
  end

  describe '#initialize' do
    it 'sets the name' do
      expect(share_provider.name).to eq name
    end

    it 'sets the type correctly' do
      expect(share_provider.type).to eq RubySMB::Server::Share::TYPE_PIPE
    end
  end
end

RSpec.describe RubySMB::Server::Share::Provider::Pipe::Processor do
  let(:session) { RubySMB::Server::Session.new(rand(0xffffffff)) }
  let(:share_provider) { RubySMB::Server::Share::Provider::Pipe.new('share') }
  subject(:share_processor) { described_class.new(share_provider, nil, session) }

  it { is_expected.to respond_to :provider }
end
