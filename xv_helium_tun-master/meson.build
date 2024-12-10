project('HPT', 'C',
	version: '0.1',
	license: 'BSD',
	default_options: ['buildtype=release', 'default_library=static'],
	meson_version: '>= 0.47.1'
)

cc = meson.get_compiler('c')

if get_option('build_libs') == true
  message('Building libs')
  subdir('lib')
endif

if get_option('build_kernel') == true
  message('Building kernel modue')
  subdir('kernel')
endif
