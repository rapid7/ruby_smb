RSpec.describe 'SPNEGO negotiation tokens' do
  let(:mech_types) do
    [RubySMB::Gss::OID_KERBEROS_5, RubySMB::Gss::OID_MICROSOFT_KERBEROS_5, RubySMB::Gss::OID_NTLMSSP]
  end

  describe RubySMB::Gss::SpnegoNegTokenInit do
    describe '.build' do
      subject(:token) { described_class.build(mech_types) }

      # the exact bytes a server advertised before this was modelled with RASN1, kept so the wire format does not
      # drift: the SPNEGO OID, the three mechanisms, and the Microsoft negHints placeholder
      let(:legacy_der) do
        [
          '605e06062b0601050502a0543052a024302206092a864886f71201020206092a864882' \
          'f712010202060a2b06010401823702020aa32a3028a0261b246e6f745f646566696e65' \
          '645f696e5f5246433431373840706c656173655f69676e6f7265'
        ].pack('H*')
      end

      it 'is byte-identical to the token the hand-rolled builder produced' do
        expect(token).to eq(legacy_der)
      end

      # the exact NTLM-only advertisement a default server built before this change, when the NTLM provider
      # hardcoded a single OID_NTLMSSP. existing servers still emit this, so lock it against a wire regression.
      it 'is byte-identical to the NTLM-only advertisement a default server built before this change' do
        legacy_ntlm_der = [
          '604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa32a3028' \
          'a0261b246e6f745f646566696e65645f696e5f5246433431373840706c656173655f' \
          '69676e6f7265'
        ].pack('H*')
        expect(described_class.build([RubySMB::Gss::OID_NTLMSSP])).to eq(legacy_ntlm_der)
      end

      it 'advertises the mechanisms in order' do
        decoded = OpenSSL::ASN1.decode(token)
        mech_list = decoded.value[1].value[0].value[0].value[0].value
        expect(mech_list.map(&:oid)).to eq(mech_types.map(&:oid))
      end

      it 'carries the Microsoft negHints placeholder' do
        decoded = OpenSSL::ASN1.decode(token)
        hint = decoded.value[1].value[0].value[1].value[0].value[0].value[0].value
        expect(hint).to eq(RubySMB::Gss::SpnegoNegTokenInit::NEG_HINTS_NAME)
      end
    end

    describe '.parse' do
      # a SPNEGO NegTokenInit selecting Kerberos and carrying the given mechanism token
      def neg_token_init(token)
        inner = [OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::Sequence.new([RubySMB::Gss::OID_KERBEROS_5])], 0, :CONTEXT_SPECIFIC)]
        inner << OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::OctetString.new(token)], 2, :CONTEXT_SPECIFIC) unless token.nil?

        OpenSSL::ASN1::ASN1Data.new(
          [
            RubySMB::Gss::OID_SPNEGO,
            OpenSSL::ASN1::ASN1Data.new([OpenSSL::ASN1::Sequence.new(inner)], 0, :CONTEXT_SPECIFIC)
          ], 0, :APPLICATION
        ).to_der
      end

      it 'reads the mechanism token' do
        expect(described_class.parse(neg_token_init('a mechanism token')).mech_token).to eq('a mechanism token')
      end

      it 'is nil when the token carries no mechanism token' do
        expect(described_class.parse(neg_token_init(nil)).mech_token).to be_nil
      end
    end
  end

  describe RubySMB::Gss::SpnegoNegTokenTarg do
    describe '.parse' do
      it 'reads the response token from a continuation' do
        targ = described_class.parse(RubySMB::Gss.gss_type3('a continuation token'))
        expect(targ.response_token).to eq('a continuation token')
      end
    end
  end
end
