libraries = ['hpt']

default_cflags = []

if target_machine.cpu_family() == 'x86_64'
  if cc.has_argument('-march=x86-64-v3')
    default_cflags += '-march=x86-64-v3'
  else
    # Haswell is the best analogue for x86-64-v3 on older compilers
    default_cflags += '-march=haswell'
  endif
endif

# Enable FORTIFY_SOURCE
default_cflags += '-D_FORTIFY_SOURCE=2'

if cc.has_argument('-Wno-format-truncation')
  default_cflags += '-Wno-format-truncation'
endif

enabled_libs = []

foreach l:libraries
  build = true
  reason = '<unknown reason>' # set if build == false to explain why
  name = l
  use_function_versioning = false
  sources = []
  headers = []
  indirect_headers = [] # public headers not directly included by apps
  includes = [include_directories('.')]
  cflags = default_cflags
  objs = [] # other object files to link against, used e.g. for
            # instruction-set optimized versions of code

  # use "deps" for internal DPDK dependencies, and "ext_deps" for
  # external package/library requirements
  ext_deps = []
  deps = []

  dir_name = l
  subdir(dir_name)

  if build
    shared_deps = ext_deps
    static_deps = ext_deps
    foreach d:deps
      if not is_variable('shared_' + d)
        error('Missing internal dependency "@0@" for @1@ [@2@]'
            .format(d, name, 'lib/' + dir_name))
      endif
      shared_deps += [get_variable('shared_' + d)]
      static_deps += [get_variable('static_' + d)]
    endforeach
  endif

  if not build
    dpdk_libs_disabled += name
    set_variable(name.underscorify() + '_disable_reason', reason)
  else
    enabled_libs += name
    install_headers(headers)
    install_headers(indirect_headers)

    libname = name
    includes += include_directories(dir_name)

    if sources.length() == 0
      # if no C files, just set a dependency on header path
      shared_dep = declare_dependency(include_directories: includes)
      static_dep = shared_dep
    else

      # first build static lib
      static_lib = static_library(libname,
          sources,
          objects: objs,
          c_args: cflags,
          dependencies: static_deps,
          include_directories: includes,
          install: true)

      static_dep = declare_dependency(
          include_directories: includes,
          dependencies: static_deps)

      lk_args = []
      lk_deps = []

      shared_lib = shared_library(libname,
          sources,
          objects: objs,
          c_args: cflags,
          dependencies: shared_deps,
          include_directories: includes,
          link_args: lk_args,
          link_depends: lk_deps,
          version: get_option('lib_version'),
          soversion: get_option('lib_version'),
          install: true)

      shared_dep = declare_dependency(link_with: shared_lib,
          include_directories: includes,
          dependencies: shared_deps)

      dpdk_libraries = [shared_lib]
      dpdk_static_libraries = [static_lib]
    endif # sources.length() > 0

    set_variable('shared_' + name, shared_dep)
    set_variable('static_' + name, static_dep)
    message('lib/@0@: Defining dependency "@1@"'.format(
        dir_name, name))
  endif
endforeach
