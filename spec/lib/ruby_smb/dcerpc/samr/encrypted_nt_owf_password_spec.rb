RSpec.describe RubySMB::Dcerpc::Samr::EncryptedNtOwfPassword do
  it 'Creates output key' do
    expect(described_class.to_output_key('ABCDEFG')).to eq ["40a09068442A188E"].pack('H*')
    expect(described_class.to_output_key('AAAAAAA')).to eq ["40A05028140A0482"].pack('H*')
  end

  it 'Encrypts a hash' do
    expect(described_class.encrypt_hash(hash: 'AAAAAAAAAAAAAAAA', key: 'BBBBBBBBBBBBBB')).to eq ["8cd90c3de08ecda28cd90c3de08ecda2"].pack('H*')
  end
end
