require 'spec_helper'

RSpec.describe RubySMB::GenericPacket do

  class TestPacket < RubySMB::GenericPacket
    endian :little
    uint8  :first_value,  initial_value: 0x01
    uint16 :second_value, initial_value: 0x02
    array  :array_value,  type: :dialect, read_until: :eof
  end

  class ParentTestPacket <  RubySMB::GenericPacket
    endian :little
    uint8  :header
    test_packet :test_packet
  end

  subject(:test_packet) { TestPacket.new(first_value: 16, second_value: 4056, array_value: [RubySMB::SMB1::Dialect.new(dialect_string: 'test')]) }
  let(:parent_packet) { ParentTestPacket.new }

  describe '#describe class method' do
    it 'outputs a string representing the structure of the packet' do
      str = "\nFirst_value                   (Uint8)    \n"+
      "Second_value                  (Uint16le) \n"+
      "Array_value                   (Array)    "
      expect(TestPacket.describe).to eq str
    end

    it 'handles nested record structures as well' do
      str = "\nHeader                        (Uint8)    \n"+
        "TEST_PACKET                              \n"+
        "\tFirst_value                  (Uint8)    \n"+
        "\tSecond_value                 (Uint16le) \n"+
        "\tArray_value                  (Array)    "
      expect(ParentTestPacket.describe).to eq str
    end
  end

  describe '#display' do
    it 'shows the actual contents of the packet fields' do
      str = "\nFIRST_VALUE                   16\n" +
      "SECOND_VALUE                  4056\n" +
      "ARRAY_VALUE\n" +
      "\tBuffer Format ID             2\n" +
      "\tDialect Name                 test"
      expect(test_packet.display).to eq str
    end

    it 'handles nested record structures as well' do
      str = "\nHEADER                        0\n" +
      "TEST_PACKET\n" +
      "\tFirst_value                  1\n" +
      "\tSecond_value                 2\n" +
      "\tARRAY_VALUE"
      expect(parent_packet.display).to eq str
    end
  end
end