require 'mkmf'

abort 'missing liblxc' unless find_library('lxc', 'lxc_container_new')
abort 'missing lxc/lxccontainer.h' unless have_header('lxc/lxccontainer.h')

$CFLAGS += " -Wall #{ENV['CFLAGS']}"
create_makefile('lxc/lxc')
