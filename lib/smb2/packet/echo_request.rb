class Smb2::Packet

  # [Section 2.2.28 SMB2 ECHO Request](https://msdn.microsoft.com/en-us/library/cc246540.aspx)
  class EchoRequest < Smb2::Packet

    # A key in {Smb2::COMMANDS}
    COMMAND = :ECHO

    nest :header, RequestHeader

    unsigned :structure_size, 16, default:4
    unsigned :reserved, 16

  end
end
