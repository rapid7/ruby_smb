require 'spec_helper'

RSpec.describe RubySMB::Compression::LZNT1 do
  describe '.compress' do
    it 'generates an empty blob when provided an empty blob' do
      expected = "".b
      expect(described_class.compress('')).to eq(expected)
    end

    it 'generates a compressed blob when provided a string with non-reoccurring characters' do
      expect(described_class.compress('RubySMB')).to eq("\x060RubySMB".b)
    end

    it 'generates a compressed blob when provided a string of reoccurring characters' do
      expect(described_class.compress("\x01" * 0x200)).to eq("\x03\xB0\x02\x01\xFC\x01".b)
    end
  end

  describe '.decompress' do
    it 'generates a decompressed blob for a string with non-reoccurring characters' do
      expect(described_class.decompress("\x060RubySMB".b)).to eq('RubySMB')
    end

    it 'generates a decompressed blob for a string of reoccurring characters' do
      expect(described_class.decompress("\x03\xB0\x02\x01\xFC\x01".b)).to eq("\x01" * 0x200)
    end

    it 'raises an EncodingError when the length is invalid' do
      expect { described_class.decompress("\x010".b) }.to raise_error(EncodingError)
    end
  end
end
