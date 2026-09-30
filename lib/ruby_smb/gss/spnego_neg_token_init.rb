require 'rasn1'

module RubySMB
  module Gss
    # The SPNEGO negotiation token an initiator sends first, and that a server sends to advertise the mechanisms it
    # supports. Modelled with RASN1 so the fields can be read and built by name rather than by walking a decoded
    # structure by hand.
    #
    # https://datatracker.ietf.org/doc/html/rfc4178#section-4.2.1
    class MechType < RASN1::Types::ObjectId
    end

    class MechTypeList < RASN1::Model
      sequence_of(:mech_type, MechType)
    end

    class ContextFlags < RASN1::Types::BitString
      def initialize(options = {})
        options[:bit_length] = 32
        super
      end
    end

    # RASN1 does not define a GeneralString type, and a SPNEGO negHints carries its hintName as one, so it is defined
    # here as an octet string tagged UNIVERSAL 27.
    class GeneralString < RASN1::Types::OctetString
      ID = 27

      def self.type
        'GeneralString'
      end
    end

    # NegHints, the optional field Microsoft servers place at [3] of a NegTokenInit2 in lieu of a mechListMIC. Windows
    # servers send a fixed placeholder hintName, so a client that expects the field still finds one.
    #
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/8e71cf53-e867-4b79-9df6-cc9edb7f8829
    class NegHints < RASN1::Model
      define_type_accel('general_string', GeneralString)

      sequence :neg_hints,
               content: [general_string(:hint_name, explicit: 0, class: :context, constructed: true, optional: true),
                         octet_string(:hint_address, explicit: 1, class: :context, constructed: true, optional: true)]
    end

    class NegTokenInit < RASN1::Model
      sequence :neg_token_init, explicit: 0, class: :context, constructed: true,
               content: [wrapper(model(:mech_type_list, MechTypeList), explicit: 0, constructed: true),
                         wrapper(model(:context_flags, ContextFlags), explicit: 1, constructed: true, optional: true),
                         octet_string(:mech_token, explicit: 2, constructed: true, optional: true),
                         wrapper(model(:neg_hints, NegHints), explicit: 3, constructed: true, optional: true)]
    end

    class SpnegoNegTokenInit < RASN1::Model
      # The placeholder hintName a Windows server sends, reproduced so the advertisement matches what a client expects.
      NEG_HINTS_NAME = 'not_defined_in_RFC4178@please_ignore'.freeze

      sequence :gssapi, implicit: 0, class: :application, constructed: true,
               content: [objectid(:oid),
                         model(:neg_token_init, NegTokenInit)]

      # Build the NegTokenInit a server sends to advertise the mechanisms it supports, including the Microsoft negHints
      # placeholder so the token is shaped as a Windows server's is.
      #
      # @param [Array<OpenSSL::ASN1::ObjectId>] mech_types the mechanisms to advertise, in preference order.
      # @return [String] the DER encoded token.
      def self.build(mech_types)
        token = new
        token[:gssapi][:oid].value = Gss::OID_SPNEGO.oid
        token[:gssapi][:neg_token_init][:mech_type_list][:mech_type] = mech_types.map { |mech| MechType.new(value: mech.oid) }
        token[:gssapi][:neg_token_init][:neg_hints][:hint_name] = NEG_HINTS_NAME
        token.to_der
      end

      # @return [String, nil] the mechanism token the initiator carried, or nil if it carried none.
      def mech_token
        self[:gssapi][:neg_token_init][:mech_token].value
      end
    end
  end
end
