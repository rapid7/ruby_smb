require 'smb2'

RSpec.describe Smb2::Packet do
  subject(:packet) do
    klass = Class.new(described_class)
    klass.instance_eval do
      nest :header, Smb2::Packet::RequestHeader
      # struct_size is part of the API and must be present
      # 2 bytes for struct_size itself, 2 for data_offset, 4 for data_length
      unsigned :struct_size, 16, default: 2 + 2 + 4
      data_buffer :data, 32
      rest :buffer
    end
    klass.new
  end

  it { is_expected.to respond_to(:recalculate) }
  it { is_expected.to respond_to(:data) }
  it { is_expected.to respond_to(:data_offset) }
  it { is_expected.to respond_to(:data_length) }

  describe '#data_buffer_fields' do
    specify do
      expect(packet.data_buffer_fields).to eq( [ :data ] )
    end
  end

  describe '#<data buffer>=' do
    specify do
      expect(packet).to receive(:recalculate).once
      expect { packet.data = 'asdf' }.not_to raise_error
    end
  end

  describe '#recalculate' do

    context 'with ascii-8bit field' do
      let(:value) { "omg data".encode("utf-16le") }
      before do
        packet.data = value
      end

      specify do
        # length of header (64) +
        # length of struct_size (2) +
        # length of data offset (2) +
        # length data length (4)
        expect(packet.data_offset).to eq(64 + 2 + 2 + 4)
      end

      specify do
        expect(packet.data_length).to eq(value.bytesize)
      end

      specify do
        expect(packet.data).to eq(value.force_encoding("binary"))
      end

    end

    context 'with ascii-8bit field' do
      let(:value) { "omg data".encode("ascii-8bit") }
      before do
        packet.data = value
      end

      specify do
        # length of header (64) +
        # length of struct_size (2) +
        # length of data offset (2) +
        # length data length (4)
        expect(packet.data_offset).to eq(64 + 2 + 2 + 4)
      end

      specify do
        expect(packet.data_length).to eq(value.bytesize)
      end

      specify do
        expect(packet.data).to eq(value.force_encoding("binary"))
      end

    end
  end
end
