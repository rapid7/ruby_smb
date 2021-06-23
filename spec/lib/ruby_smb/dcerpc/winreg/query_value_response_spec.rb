RSpec.describe RubySMB::Dcerpc::Winreg::QueryValueResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :lp_type }
  it { is_expected.to respond_to :lp_data }
  it { is_expected.to respond_to :pad }
  it { is_expected.to respond_to :lpcb_data }
  it { is_expected.to respond_to :lpcb_len }
  it { is_expected.to respond_to :error_status }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end

  describe '#lp_type' do
    it 'is a Ndr::NdrUint32Ptr structure' do
      expect(packet.lp_type).to be_a RubySMB::Dcerpc::Ndr::NdrUint32Ptr
    end
  end

  describe '#lp_data' do
    it 'is a NdrNdrByteArrayPtr structure' do
      expect(packet.lp_data).to be_a RubySMB::Dcerpc::Ndr::NdrByteArrayPtr
    end
  end

  describe '#pad' do
    it 'is a string' do
      expect(packet.pad).to be_a BinData::String
    end

    it 'should keep #lpcb_data 4-byte aligned' do
      packet.lp_data = 'spec_test'.bytes
      expect(packet.lpcb_data.abs_offset % 4).to eq 0
    end
  end

  describe '#lpcb_data' do
    it 'is a Ndr::NdrUint32Ptr structure' do
      expect(packet.lpcb_data).to be_a RubySMB::Dcerpc::Ndr::NdrUint32Ptr
    end
  end

  describe '#lpcb_len' do
    it 'is a Ndr::NdrUint32Ptr structure' do
      expect(packet.lpcb_len).to be_a RubySMB::Dcerpc::Ndr::NdrUint32Ptr
    end
  end

  describe '#error_status' do
    it 'is a 32-bit unsigned integer' do
      expect(packet.error_status).to be_a BinData::Uint32le
    end
  end

  describe '#initialize_instance' do
    it 'sets #opnum to REG_QUERY_VALUE constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Winreg::REG_QUERY_VALUE)
    end
  end

  describe '#data' do
    context 'when #lp_type is 1 (unicode null-terminated string)' do
      it 'returns the expected value' do
        str = 'spec test string'.encode('utf-16le')
        packet.lp_type = 1
        packet.lp_data = str.bytes
        expect(packet.data).to eq(str)
      end
    end

    context 'when #lp_type is 2 (unicode null-terminated string with unexpanded references to environment variables)' do
      it 'returns the expected value' do
        str = '/%PATH%/foo'.encode('utf-16le')
        packet.lp_type = 2
        packet.lp_data = str.bytes
        expect(packet.data).to eq(str)
      end
    end

    context 'when #lp_type is 3 (binary data)' do
      it 'returns the expected value' do
        bytes = [0xFF, 0xEE, 0xDD, 0xCC].pack('C*')
        packet.lp_type = 3
        packet.lp_data = bytes.bytes
        expect(packet.data).to eq(bytes)
      end
    end

    context 'when #lp_type is 4 (a 32-bit number in little-endian format)' do
      it 'returns the expected value' do
        number = 12345
        packet.lp_type = 4
        packet.lp_data = [number].pack('V').bytes
        expect(packet.data).to eq(number)
      end
    end

    context 'when #lp_type is 5 (a 32-bit number in big-endian format)' do
      it 'returns the expected value' do
        number = 12345
        packet.lp_type = 5
        packet.lp_data = [number].pack('N').bytes
        expect(packet.data).to eq(number)
      end
    end

    context 'when #lp_type is 7 (a sequence of unicode null-terminated strings, terminated by an empty string)' do
      it 'returns the expected value' do
        str_array = ['String1', 'String2', 'String3', 'LastString'].map {|v| v.encode('utf-16le')}
        null_byte = "\0".encode('utf-16le')
        str = (str_array + [null_byte]).join(null_byte)
        packet.lp_type = 7
        packet.lp_data = str.bytes
        expect(packet.data).to eq(str_array)
      end
    end

    context 'when #lp_type is 11 (a 64-bit number in little-endian format)' do
      it 'returns the expected value' do
        number = 0x1234567812345678
        packet.lp_type = 11
        packet.lp_data = [number].pack('Q<').bytes
        expect(packet.data).to eq(number)
      end
    end

    context 'when #lp_type is an unknown value' do
      it 'returns an empty string' do
        str = 'test'
        packet.lp_type = 6
        packet.lp_data = str.bytes
        expect(packet.data).to eq('')
      end
    end
  end
end
