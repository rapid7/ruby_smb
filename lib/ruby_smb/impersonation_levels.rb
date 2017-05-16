module RubySMB
  # Contains constants for the various Impersonation levels as defined in
  # [2.2.4.64.1 Request](https://msdn.microsoft.com/en-us/library/ee442175.aspx)
  # See also [Impersonation Levels](https://msdn.microsoft.com/en-us/library/ms686632(v=vs.85).aspx)
  module ImpersonationLevels
    # The client is anonymous to the server. The server process can impersonate the client, but the impersonation
    # token does not contain any information about the client. This level is only supported over the local
    # interprocess communication transport. All other transports silently promote this level to identify.
    SEC_ANONYMOUS   = 0x00000000

    # The system default level. The server can obtain the client's identity,
    # and the server can impersonate the client to do ACL checks.
    SEC_IDENTIFY    = 0x00000001

    # The server can impersonate the client's security context while acting on behalf of the client.
    # The server can access local resources as the client. If the server is local, it can access
    # network resources as the client. If the server is remote, it can access only resources
    # that are on the same computer as the server.
    SEC_IMPERSONATE = 0x00000002

  end
end