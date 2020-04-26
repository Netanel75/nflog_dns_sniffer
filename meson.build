project('nflog_reader', 'c')
flags = ['-Wextra', '-Wno-unused-parameter', '-Wall','-Werror', '-D_GNU_SOURCE']
cc = meson.get_compiler('c')
nflog_includes = include_directories('/usr/include')
netfilter_log = cc.find_library('libnetfilter_log', version : '>=1.0.1')
resolv = cc.find_library('resolv')

srcs = [
    'main.c',
    'parse_dns.c'
]

ps_docker = executable('nflog_exe',
                        srcs,
                        c_args: flags,
                        include_directories: nflog_includes,
                        dependencies: [netfilter_log, resolv])
