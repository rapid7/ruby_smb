RSpec.describe RubySMB::SMB1::Packet::Generic do

  subject(:packet) { described_class.new }

  it_behaves_like 'smb generic packet'

end