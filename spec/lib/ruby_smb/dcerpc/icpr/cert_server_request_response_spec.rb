RSpec.describe RubySMB::Dcerpc::Icpr::CertServerRequestResponse do
  subject(:packet) { described_class.new }

  it { is_expected.to respond_to :pdw_request_id }
  it { is_expected.to respond_to :pdw_disposition }
  it { is_expected.to respond_to :pctb_cert }
  it { is_expected.to respond_to :pctb_encoded_cert }
  it { is_expected.to respond_to :pctb_disposition_message }
  it { is_expected.to respond_to :error_status }

  it 'is little endian' do
    expect(described_class.fields.instance_variable_get(:@hints)[:endian]).to eq :little
  end
  it 'is a BinData::Record' do
    expect(packet).to be_a(BinData::Record)
  end
  describe '#pdw_request_id' do
    it 'is a NdrUint32 structure' do
      expect(packet.pdw_request_id).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#pdw_disposition' do
    it 'is a NdrUint32 structure' do
      expect(packet.pdw_disposition).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#pctb_cert' do
    it 'is a CertTransBlob structure' do
      expect(packet.pctb_cert).to be_a RubySMB::Dcerpc::Icpr::CertTransBlob
    end
  end
  describe '#pctb_encoded_cert' do
    it 'is a CertTransBlob structure' do
      expect(packet.pctb_encoded_cert).to be_a RubySMB::Dcerpc::Icpr::CertTransBlob
    end
  end
  describe '#pctb_disposition_message' do
    it 'is a CertTransBlob structure' do
      expect(packet.pctb_disposition_message).to be_a RubySMB::Dcerpc::Icpr::CertTransBlob
    end
  end
  describe '#error_status' do
    it 'is a NdrUint32 structure' do
      expect(packet.error_status).to be_a RubySMB::Dcerpc::Ndr::NdrUint32
    end
  end
  describe '#initialize_instance' do
    it 'sets #opnum to CERT_SERVER_REQUEST constant' do
      expect(packet.opnum).to eq(RubySMB::Dcerpc::Icpr::CERT_SERVER_REQUEST)
    end
  end
  it 'reads itself' do
    new_packet = described_class.new({
      pdw_request_id: 1,
      pdw_disposition: 0,
      pctb_cert: { pb: 'CERT'.bytes },
      pctb_encoded_cert: { pb: 'ENCODED_CERT'.bytes },
      pctb_disposition_message: { pb: 'DISPOSITION_MESSAGE'.bytes },
      error_status: 0
    })
    expected_output = {
      pdw_request_id: 1,
      pdw_disposition: 0,
      pctb_cert: { cb: 4, pb: 'CERT'.bytes },
      pctb_encoded_cert: { cb: 12, pb: 'ENCODED_CERT'.bytes },
      pctb_disposition_message: { cb: 19, pb: 'DISPOSITION_MESSAGE'.bytes },
      error_status: 0
    }
    expect(packet.read(new_packet.to_binary_s)).to eq(expected_output)
  end
end
