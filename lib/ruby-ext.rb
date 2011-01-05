#
# Copyright (c) 2011 Jean-Michel Esnault. Released under the same license as Ruby
# 

class Object
  def to_shex(*args)
    self.respond_to?(:encode) ? self.encode(*args).unpack('H*')[0] : ""
  end
  alias to_s_hexlify to_shex
end

class Class
  def attr_checked(attribute, &validation)
    define_method "#{attribute}=" do |val|
      raise "Invalid attribute #{val.inspect}" unless validation.call(val)
      instance_variable_set("@#{attribute}", val)
    end
    define_method attribute do
      instance_variable_get "@#{attribute}"
    end
  end
  def attr_writer_delegate(*args)
    args.each do |name|
      define_method "#{name}=" do |value|
        instance_variable_set("@#{name}", self.class.const_get(name.to_s.to_camel.to_sym).new(value))
      end
    end
  end
end

class String
  def to_underscore
    gsub(/([A-Z]+|[A-Z][a-z])/) {|x| ' ' + x }.gsub(/[A-Z][a-z]+/) {|x| ' ' + x }.split.collect{|x| x.downcase}.join('_')
  end
  def to_camel
    split('_').collect {|x| x.capitalize}.join
  end
  def hexlify
    l,n,ls,s=0,0,[''],self.dup
    while s.size>0
      l = s.slice!(0,16)
      ls << format("0x%4.4x:  %s", n, l.unpack("n#{l.size/2}").collect { |x| format("%4.4x",x) }.join(' '))
      n+=1
    end
    if l.size%2 >0
      ns = l.size>1 ? 1 : 0
      ls.last << format("%s%2.2x",' '*ns,l[-1].pack('C')[0])
    end
    ls
  end
end

class Symbol
  def to_klass
    to_s.to_camel.to_sym
  end
  def to_setter
    (to_s + "=").to_sym
  end
end

module Args
  def set(h)
    for key in [ivars].flatten
      if h.has_key?(key) and ! h[key].nil?
        begin
          klassname = key.to_klass
          if self.class.const_defined?(klassname)
            instance_variable_set("@#{key.to_s}", self.class.const_get(klassname).new(h[key]))
          elsif self.respond_to?(key.to_setter)
            self.send key.to_setter, h[key]
          else
            instance_variable_set("@#{key.to_s}", h[key])
          end
        rescue ArgumentError => e
          raise
        ensure
          #h.delete(key)
        end
      else
      end
    end
  end

  def to_hash
    h = {}
    for key in [ivars].flatten
      ivar = instance_variable_get("@#{key.to_s}")
      if ivar.respond_to?(:to_hash)
        h.store(key,ivar.to_hash)
      elsif ivar.is_a?(Array)
        h.store(key, ivar.collect { |x| 
          if x.respond_to?(:to_hash)
            x.to_hash
          else
            # x.to_s
            nil
          end
        }
        )
      else
        h.store(key,ivar) unless ivar.nil?
      end
    end
    h
  end

  def ivars
    instance_variables.reject { |x| x =~ /^@_/ }.collect { |x| x[1..-1].to_sym }
  end
end
