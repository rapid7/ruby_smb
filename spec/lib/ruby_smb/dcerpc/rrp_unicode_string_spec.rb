RSpec.describe RubySMB::Dcerpc::RrpUnicodeString do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :buffer_length }
  it { is_expected.to respond_to :maximum_length }
  it { is_expected.to respond_to :buffer }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#buffer_length' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.buffer_length).to be_a BinData::Uint16le
    end

    it 'is set to 0 when #buffer in empty' do
      expect(packet.buffer_length).to eq(0)
    end
  end

  describe '#maximum_length' do
    it 'should be a 16-bit unsigned integer' do
      expect(packet.maximum_length).to be_a BinData::Uint16le
    end
  end

  describe '#buffer' do
    it 'should be a NdrLpStr' do
      expect(packet.buffer).to be_a RubySMB::Dcerpc::Ndr::NdrLpStr
    end
  end

  describe '#get' do
    it 'returns #buffer' do
      packet.buffer = 'spec_test'
      expect(packet.get).to eq(RubySMB::Dcerpc::Ndr::NdrLpStr.new('spec_test'))
    end
  end

  describe '#set' do
    it 'sets #buffer to the expected value' do
      packet.set('spec_test')
      expect(packet.buffer).to eq(RubySMB::Dcerpc::Ndr::NdrLpStr.new('spec_test'))
    end

    it 'sets #buffer_length to the expected value' do
      packet.set('spec_test')
      expect(packet.buffer_length).to eq(('spec_test'.size + 1) * 2)
    end

    it 'sets #maximum_length to the expected value' do
      packet.set('spec_test')
      expect(packet.maximum_length).to eq(('spec_test'.size + 1) * 2)
    end

    context 'when the value is 0' do
      it 'sets #buffer_length to 0' do
        packet.set(0)
        expect(packet.buffer_length).to eq(0)
      end

      it 'sets #maximum_length to 0' do
        packet.set(0)
        expect(packet.maximum_length).to eq(0)
      end
    end
  end
end

RSpec.describe RubySMB::Dcerpc::PrrpUnicodeString do
  it 'is NdrTopLevelFullPointer subclass' do
    expect(described_class).to be < RubySMB::Dcerpc::Ndr::NdrTopLevelFullPointer
  end

  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :referent }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#referent' do
    it 'is a RrpUnicodeString' do
      expect(packet.referent).to be_a RubySMB::Dcerpc::RrpUnicodeString
    end

    it 'exists if superclass #referent_identifier is not zero' do
      expect(packet.referent?).to be true
    end

    it 'does not exist if superclass #referent_identifier is zero' do
      packet.referent_identifier = 0
      expect(packet.referent?).to be false
    end
  end
end
