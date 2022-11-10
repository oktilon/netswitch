project(
    'netswitch', 'c',
    version : '1.0.0',
    meson_version : '> 0.53.0')

# Set config
# version_arr = meson.project_version().split('.')
# conf_data = configuration_data()
# conf_data.set('version_major', version_arr[0])
# conf_data.set('version_minor', version_arr[1])
# conf_data.set('version_rev',   version_arr[2])
# configure_file(
#     input         : 'main.h.in',
#     output        : 'main.h',
#     configuration : conf_data
# )

# Includes and sources
# inc = include_directories(['include', 'lib'])
src = [
      'src/app.c'
]

# Dependencies
# deps = [
#       dependency('libsystemd')
#     , dependency('threads')
#     , dependency('sqlite3')
# ]

# Create executable
executable(
    meson.project_name(),
    sources : src
    # include_directories : inc,
    # dependencies : deps
)
