require 'rasn1'

module RubySMB
  module Gss
    # The SPNEGO negotiation token exchanged after the first, carrying a continuation of the selected mechanism.
    # A client sends one to continue an exchange, so it is where a mechanism token arrives on any leg past the first.
    #
    # https://www.rfc-editor.org/rfc/rfc2478
    class SpnegoNegTokenTarg < RASN1::Model
      NEG_RESULTS = { 'accept-completed' => 0,
                      'accept-incomplete' => 1,
                      'reject' => 2,
                      'request-mic' => 3 }.freeze

      sequence :token, explicit: 1, class: :context, constructed: true,
               content: [enumerated(:neg_result, enum: NEG_RESULTS, explicit: 0, class: :context, constructed: true, optional: true),
                         objectid(:supported_mech, explicit: 1, class: :context, constructed: true, optional: true),
                         octet_string(:response_token, explicit: 2, class: :context, constructed: true, optional: true),
                         octet_string(:mech_list_mic, explicit: 3, class: :context, constructed: true, optional: true)]

      # @return [String, nil] the mechanism token the continuation carried, or nil if it carried none.
      def response_token
        self[:response_token].value
      end
    end
  end
end
