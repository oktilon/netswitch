project(
    'netswitch', 'c',
    version : '1.0.0',
    meson_version : '> 0.53.0')

if meson.is_cross_build()
    eth_ifa = 'eth0'
    eth_con = 'Wired_connection_1'
    sim_ifa = 'wwan0'
    sim_con = 'telenor'
else
    eth_ifa = 'br-ecb47c45ef18'
    eth_con = 'br-ecb47c45ef18'
    sim_ifa = 'docker0'
    sim_con = 'docker0'
endif

# Set config
# version_arr = meson.project_version().split('.')
conf_data = configuration_data()
conf_data.set('eth_ifa', eth_ifa)
conf_data.set('eth_con', eth_con)
conf_data.set('sim_ifa', sim_ifa)
conf_data.set('sim_con', sim_con)
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
deps = [
    dependency('threads')
]

# Create executable
executable(
    meson.project_name()
    , sources : src
    , dependencies : deps
    # , include_directories : inc
)
