project(
    'netswitch', 'c',
    version : '1.0.0',
    meson_version : '> 0.53.0')

if meson.is_cross_build()
    eth_ifn = 'eth0'
    wan_ifn = 'wwan0'
else
    eth_ifn = 'br-ecb47c45ef18'
    wan_ifn = 'docker0'
endif

# Set config
# version_arr = meson.project_version().split('.')
conf_data = configuration_data()
conf_data.set('eth_ifn', eth_ifn)
conf_data.set('wan_ifn', wan_ifn)
conf_data.set('version', meson.project_version())
configure_file(
    input         : 'app.h.in',
    output        : 'app.h',
    configuration : conf_data
)

# Includes and sources
# inc = include_directories(['include', 'lib'])
src = [
      'src/app.c'
    , 'src/nlrequest.c'
]

# Dependencies
# deps = [
#     dependency('threads')
# ]

# Create executable
executable(
    meson.project_name()
    , sources : src
    # , dependencies : deps
    # , include_directories : inc
)
