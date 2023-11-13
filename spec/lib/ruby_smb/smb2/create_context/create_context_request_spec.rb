require 'spec_helper'

RSpec.describe RubySMB::SMB2::CreateContext::CreateContextRequest do
  subject(:struct) { described_class.new }

  it { is_expected.to respond_to :next_offset }
  it { is_expected.to respond_to :name_offset }
  it { is_expected.to respond_to :name_length }
  it { is_expected.to respond_to :data_offset }
  it { is_expected.to respond_to :data_length }
  it { is_expected.to respond_to :buffer }
  it { is_expected.to respond_to :name }
  it { is_expected.to respond_to :data }

  describe '#name_length' do
    it 'stores the length of the name field' do
      expect(struct.name_length).to eq struct.name.length
    end
  end

  describe '#name_offset' do
    it 'stores the relative offset of the name field' do
      expect(struct.name_offset).to eq struct.name.rel_offset
    end
  end

  describe '#data_length' do
    it 'stores the length of the data field' do
      expect(struct.data_length).to eq struct.data.length
    end
  end

  describe '#data_offset' do
    it 'stores the relative offset of the data field' do
      struct.data = 'Hello'
      expect(struct.data_offset).to eq struct.data.rel_offset
    end

    it 'returns 0 if the data field is empty' do
      expect(struct.data_offset).to eq 0
    end
  end

  context 'when reading a packet with extra padding' do
    # :name_offset=>120,
    # :name_length=>14,
    # :contexts_offset=>136,
    # :contexts_length=>60,
    # :bytes_remaining=>76,
    # :buffer=> "t\x00e\x00s\x00t\x00.\x00r\x00b\x00\x00\x00\x00\x00\x00[...SNIP...]"
    let(:raw_data) {
      "\x00\x00\x00\x00\x10\x00\x04\x00\x00\x00\x18\x00\x24\x00\x00\x00\x44\x48\x32\x43\x00\x00"\
      "\x00\x00\x04\xfa\xb6\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd7\x43\xe0\x35"\
      "\x5c\x6e\xee\x11\xb8\xbb\x00\x0c\x29\xc1\x13\xd0\x00\x00\x00\x00".b
    }

    it 'reads without error' do
      expect { described_class.read(raw_data) }.to_not raise_error
    end

    context 'when getting #name and #data' do
      let(:create_request_packet) { described_class.read(raw_data) }

      it 'gets the expected #name value' do
        create_request_packet.name.read_now!
        expect(create_request_packet.name).to eq 'DH2C'
      end

      it 'gets the expected #data value' do
        create_request_packet.data.read_now!
        expected_data = "\x04\xfa\xb6\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd7\x43"\
                        "\xe0\x35\x5c\x6e\xee\x11\xb8\xbb\x00\x0c\x29\xc1\x13\xd0\x00\x00\x00\x00".b
        expect(create_request_packet.data).to eq expected_data
      end
    end
  end
end
