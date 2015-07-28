module RubySmb::Error
  # Thrown when there is a problem with communication over NetBios Session Service
  # @see https://wiki.wireshark.org/NetBIOS/NBSS
  class NetBiosSessionService < Exception; end
end
