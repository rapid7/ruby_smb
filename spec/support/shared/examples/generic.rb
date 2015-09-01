RSpec.shared_examples 'smb generic packet' do

  it { is_expected.to respond_to :smb_header }

  describe 'smb_header' do
    subject(:header) { packet.smb_header }

    it 'is a standard SMB Header' do
      expect(header).to be_a RubySMB::SMB1::SMBHeader
    end

  end


end