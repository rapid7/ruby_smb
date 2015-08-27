RSpec.describe RubySMB::SMB1::Packet::ParameterBlock do

  subject(:parameter_block) { described_class.new }

  it_behaves_like 'smb parameter block'

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@endian)).to eq :little
  end

end