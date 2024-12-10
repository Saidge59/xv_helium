# SPDX-License-Identifier: BSD-3-Clause
# HPT makefile is derived from work by Luca Boccassi
# Copyright(c) 2018 Luca Boccassi <bluca@debian.org>

hpt_mkfile = custom_target('hpt_makefile',
	output: 'Makefile',
	command: ['touch', '@OUTPUT@'])

hpt_sources = files(
	'hpt_core.c',
	'hpt_net.c',
	'Kbuild')

custom_target('hpt',
	input: hpt_sources,
	output: 'hpt.ko',
	command: ['make', '-C', kernel_dir + '/build',
		'M=' + meson.current_build_dir(),
		'src=' + meson.current_source_dir(),
		'MODULE_CFLAGS=' +
		' -I' + meson.source_root() + '/lib/' +
		' -I /usr/include/' +
		'modules'],
	depends: hpt_mkfile,
	install: true,
	install_dir: kernel_dir + '/',
	build_by_default: true)
