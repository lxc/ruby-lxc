require 'mkmf'
if find_library('lxc', 'lxc_container_new') and have_header('lxc/lxc.h')
  $CFLAGS += " -Wall #{ENV['CFLAGS']}"
  create_makefile('lxc')
end
