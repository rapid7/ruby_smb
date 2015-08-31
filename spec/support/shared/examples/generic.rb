RSpec.shared_examples 'smb generic packet' do |visualizations|

  it { is_expected.to respond_to :smb_header }

  describe 'smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::Packet::SMBHeader
    end

  end

  describe '#display' do
    it 'displays a formatted representation of the packet contents' do
      expect(packet.display).to eq visualizations[:display]
    end
  end

  describe '#describe' do
    it 'displays a formatted representation of the packet structure' do
      expect(described_class.describe).to eq visualizations[:description]
    end
  end

end