class NestHandler < YARD::Handlers::Ruby::Base
  handles method_call(:nest)
  namespace_only

  def process
    name  = statement.parameters[0].jump(:tstring_content, :ident).source
    klass = statement.parameters[1].jump(:var_ref, :const).source

    reader = YARD::CodeObjects::MethodObject.new(namespace, name)
    reader.dynamic = true
    if reader.docstring.blank?(false)
      reader.docstring = "A copy of the value in the `#{name}` field"
    end
    unless reader.docstring.include?("@return")
      reader.docstring += "\n@return [#{klass}]"
    end
    register(reader)

    writer = YARD::CodeObjects::MethodObject.new(namespace, "#{name}=")
    writer.signature = "def #{name}=(value)"
    writer.source = "def #{name}=(value)\n @#{name} = value\nend"
    writer.parameters = [['value', nil]]

    writer.dynamic = true
    if writer.docstring.blank?(false)
      writer.docstring = "Sets the attribute #{name}\n@param value [#{klass},String] the value to set the attribute #{name} to."
    end
    register(writer)

    namespace.attributes[scope][name] = SymbolHash[:read => reader, :write => writer]
  end
end
