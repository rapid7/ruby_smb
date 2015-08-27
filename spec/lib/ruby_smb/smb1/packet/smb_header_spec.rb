RSpec.describe RubySMB::SMB1::Packet::SMBHeader do

  subject(:header) { described_class.new }

  it_behaves_like 'smb header'

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@endian)).to eq :little
  end
end