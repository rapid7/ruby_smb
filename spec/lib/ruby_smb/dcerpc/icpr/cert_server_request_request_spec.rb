RSpec.describe RubySMB::Dcerpc::Icpr::CertServerRequestRequest do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :dw_flags }
  it { is_expected.to respond_to :pwsz_authority }
  it { is_expected.to respond_to :pdw_request_id }
  it { is_expected.to respond_to :pctb_attribs }
  it { is_expected.to respond_to :pctb_request }
  it { is_expected.to respond_to :opnum }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end
  describe '#dw_flags' do
    it 'is a NdrUint32 structure' do
      expect(packet.dw_flags).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#pwsz_authority' do
    it 'is a NdrWideStringzPtr structure' do
      expect(packet.pwsz_authority).to be_a RubySMB::Dcerpc::Ndr::NdrWideStringzPtr
    end
  end
  describe '#pdw_request_id' do
    it 'is a NdrUint32 structure' do
      expect(packet.pdw_request_id).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#pctb_attribs' do
    it 'is a CertTransBlob structure' do
      expect(packet.pctb_attribs).to be_a RubySMB::Dcerpc::Icpr::CertTransBlob
    end
  end
  describe '#pctb_request' do
    it 'is a CertTransBlob structure' do
      expect(packet.pctb_request).to be_a RubySMB::Dcerpc::Icpr::CertTransBlob
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to CERT_SERVER_REQUEST constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Icpr::CERT_SERVER_REQUEST)
    end
  end
  it 'reads itself' do
    new_packet = described_class.new({
      dw_flags: 0,
      pwsz_authority: 'DC-CA',
      pdw_request_id: 1,
      pctb_attribs: { pb: 'ATTRIBUTES'.bytes },
      pctb_request: { pb: 'REQUEST'.bytes }
    })
    expected_output = {
      dw_flags: 0,
      pwsz_authority: 'DC-CA'.encode('utf-16le'),
      pdw_request_id: 1,
      pctb_attribs: { cb: 10, pb: 'ATTRIBUTES'.bytes },
      pctb_request: { cb: 7, pb: 'REQUEST'.bytes }
    }
    expect(packet.read(new_packet.to_binary_s)).to eq(expected_output)
  end
end
