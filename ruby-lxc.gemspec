require 'rubygems'
require File.expand_path("../lib/lxc/version", __FILE__)

Gem::Specification.new do |s|
  s.name       = 'ruby-lxc'
  s.version    = LXC::VERSION
  s.summary    = 'Ruby bindings for liblxc'
  s.author     = 'Andre Nathan'
  s.email      = 'andre@digirati.com.br'

  s.files      = Dir.glob('ext/**/*.{c,rb}') +
                 Dir.glob('lib/**/*.rb')
  s.extensions = 'ext/lxc/extconf.rb'
  s.has_rdoc   = true

  s.add_development_dependency "rake-compiler"

  s.description = <<-EOF
    Ruby-LXC is a Ruby binding for the liblxc library, allowing
    Ruby scripts to create and manage Linux containers.
  EOF
end
