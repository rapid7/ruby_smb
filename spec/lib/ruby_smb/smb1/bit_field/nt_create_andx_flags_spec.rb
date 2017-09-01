RSpec.describe RubySMB::SMB1::BitField::NtCreateAndxFlags do
  subject(:options) { described_class.new }

  it { is_expected.to respond_to :request_extended_response }
  it { is_expected.to respond_to :open_target_dir }
  it { is_expected.to respond_to :request_opbatch }
  it { is_expected.to respond_to :request_oplock }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#request_extended_response' do
    it 'is a 1-bit flag' do
      expect(options.request_extended_response).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :request_extended_response, 'V', 0x00000010
  end

  describe '#open_target_dir' do
    it 'is a 1-bit flag' do
      expect(options.open_target_dir).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :open_target_dir, 'V', 0x00000008
  end

  describe '#request_opbatch' do
    it 'is a 1-bit flag' do
      expect(options.request_opbatch).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :request_opbatch, 'V', 0x00000004
  end

  describe '#request_oplock' do
    it 'is a 1-bit flag' do
      expect(options.request_oplock).to be_a BinData::Bit1
    end

    it_behaves_like 'bit field with one flag set', :request_oplock, 'V', 0x00000002
  end

end


