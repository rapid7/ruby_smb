RSpec.describe RubySMB::Server::Share::Provider::Disk do
  let(:name) { 'share' }
  let(:path) { Dir.getwd }
  subject(:share_provider) { described_class.new(name, path) }

  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to :path }
  it { is_expected.to respond_to :type }

  describe '#TYPE' do
    it 'is TYPE_DISK' do
      expect(described_class::TYPE).to eq RubySMB::Server::Share::TYPE_DISK
    end
  end

  describe '#initialize' do
    it 'sets the name' do
      expect(share_provider.name).to eq name
    end

    it 'sets the path' do
      expect(share_provider.path).to be_a Pathname
      expect(share_provider.path).to eq Pathname.new(path)
    end

    it 'sets the type correctly' do
      expect(share_provider.type).to eq RubySMB::Server::Share::TYPE_DISK
    end

    it 'raises an ArgumentError for an invalid path' do
      # __FILE__ is not a directory so it's invalid
      expect { described_class.new(name, __FILE__) }.to raise_error(ArgumentError)
    end
  end
end

RSpec.describe RubySMB::Server::Share::Provider::Disk::Processor do
  let(:session) { RubySMB::Server::Session.new(rand(0xffffffff)) }
  let(:share_provider) { RubySMB::Server::Share::Provider::Disk.new('share', Dir.getwd) }
  subject(:share_processor) { described_class.new(share_provider, nil, session) }

  it { is_expected.to respond_to :provider }

  describe '#maximal_access' do
    # no path specified should be the root of the share
    context 'with no path specified' do
      let(:maximal_access) { share_processor.maximal_access }
      it 'is a FileAccessMask' do
        expect(maximal_access).to be_a RubySMB::SMB2::BitField::FileAccessMask
      end

      it 'marks the data as readable' do
        expect(maximal_access.read_data).to eq 1
      end

      it 'marks the data attributes as readable' do
        expect(maximal_access.read_attr).to eq 1
      end
    end
  end
end
