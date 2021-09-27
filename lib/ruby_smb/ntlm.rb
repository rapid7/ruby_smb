module RubySMB
  module NTLM
    # [[MS-NLMP] 2.2.2.5](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/99d90ff4-957f-4c8a-80e4-5bfe5a9a9832)
    NEGOTIATE_FLAGS = {
      :UNICODE                  => 1 << 0,
      :OEM                      => 1 << 1,
      :REQUEST_TARGET           => 1 << 2,
      :SIGN                     => 1 << 4,
      :SEAL                     => 1 << 5,
      :DATAGRAM                 => 1 << 6,
      :LAN_MANAGER_KEY          => 1 << 7,
      :NTLM                     => 1 << 9,
      :NT_ONLY                  => 1 << 10,
      :ANONYMOUS                => 1 << 11,
      :OEM_DOMAIN_SUPPLIED      => 1 << 12,
      :OEM_WORKSTATION_SUPPLIED => 1 << 13,
      :ALWAYS_SIGN              => 1 << 15,
      :TARGET_TYPE_DOMAIN       => 1 << 16,
      :TARGET_TYPE_SERVER       => 1 << 17,
      :TARGET_TYPE_SHARE        => 1 << 18,
      :EXTENDED_SECURITY        => 1 << 19,
      :IDENTIFY                 => 1 << 20,
      :NON_NT_SESSION           => 1 << 22,
      :TARGET_INFO              => 1 << 23,
      :VERSION_INFO             => 1 << 25,
      :KEY128                   => 1 << 29,
      :KEY_EXCHANGE             => 1 << 30,
      :KEY56                    => 1 << 31
    }.freeze

    DEFAULT_CLIENT_FLAGS =
      NEGOTIATE_FLAGS[:UNICODE] |
      NEGOTIATE_FLAGS[:SIGN] |
      NEGOTIATE_FLAGS[:SEAL] |
      NEGOTIATE_FLAGS[:REQUEST_TARGET] |
      NEGOTIATE_FLAGS[:NTLM] |
      NEGOTIATE_FLAGS[:ALWAYS_SIGN] |
      NEGOTIATE_FLAGS[:EXTENDED_SECURITY] |
      NEGOTIATE_FLAGS[:KEY128] |
      NEGOTIATE_FLAGS[:KEY_EXCHANGE] |
      NEGOTIATE_FLAGS[:KEY56] |
      NEGOTIATE_FLAGS[:TARGET_INFO] |
      NEGOTIATE_FLAGS[:VERSION_INFO]

    # [[MS-NLMP] 2.2.2.10 VERSION](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b1a6ceb2-f8ad-462b-b5af-f18527c48175)
    class OSVersion < BinData::Record
      endian :little

      uint8  :major
      uint8  :minor
      uint16 :build
      uint24 :reserved
      uint8  :ntlm_revision, initial_value: 15

      def to_s
        "Version #{major}.#{minor} (Build #{build}); NTLM Current Revision #{ntlm_revision}"
      end
    end
  end
end

