RSpec.describe RubySMB::Dcerpc::Samr::UserProperties do
  describe '#read' do
    context 'when reading a structure with no user properties' do
      let(:binary) { [ 0, 0x63, 0, 0, 0x50, 0].pack('L<L<S<S<x96<SC') }
      let(:subject) { described_class.read(binary) }

      it 'does not include the property_count' do
        expect(subject.property_count?).to be_falsey
        expect(subject.snapshot).to_not include(:property_count)
      end

      it 'does not include the user_properties' do
        expect(subject.user_properties?).to be_falsey
        expect(subject.snapshot).to_not include(:user_properties)
      end

      it 'serializes to the value that was read' do
        expect(subject.to_binary_s).to eq(binary)
      end
    end

    context 'when reading a structure with two user properties' do
      let(:user_property1) { RubySMB::Dcerpc::Samr::UserProperty.new(property_name: 'key1', property_value: 'value1') }
      let(:user_property2) { RubySMB::Dcerpc::Samr::UserProperty.new(property_name: 'key2', property_value: 'value2') }
      let(:user_properties) { user_property1.to_binary_s + user_property2.to_binary_s }
      let(:binary) { [ 0, 0x63 + 2 + user_properties.length, 0, 0, 0x50, 2].pack('L<L<S<S<x96<S<S') + user_properties + "\x00".b }
      let(:subject) { described_class.read(binary) }

      it 'includes the property_count' do
        expect(subject.property_count?).to be_truthy
        expect(subject.property_count).to eq(2)
        expect(subject.snapshot).to include(:property_count)
      end

      it 'includes the user_properties' do
        expect(subject.user_properties?).to be_truthy
        expect(subject.user_properties).to eq([user_property1, user_property2])
        expect(subject.snapshot).to include(:user_properties)
      end

      it 'serializes to the value that was read' do
        expect(subject.to_binary_s).to eq(binary)
      end

      context 'when #user_properties is cleared' do
        before(:each) { subject.user_properties.clear }

        it 'does not include the property_count' do
          expect(subject.property_count?).to be_falsey
          expect(subject.snapshot).to_not include(:property_count)
        end

        it 'does not include the user_properties' do
          expect(subject.user_properties?).to be_falsey
          expect(subject.snapshot).to_not include(:user_properties)
        end
      end
    end
  end

  describe '#initialize' do
    let(:subject) { described_class.new }

    it 'initializes #struct_length to 0x63' do
      expect(subject.struct_length).to eq(0x63)
    end

    it 'initializes #property_signature to 0x50' do
      expect(subject.property_signature).to eq(0x50)
    end

    it 'does not include user_properties' do
      expect(subject.user_properties).to be_empty
    end
  end
end