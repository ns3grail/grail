# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
from waflib import Options, Utils, Tools

# def options(opt):
#     pass
def options(opt):                                                               
    opt.load("compiler_cxx")
 
def configure(conf):
    # todo: also check amd64/x86_64 dependency
    if not Utils.unversioned_sys_platform() in ['linux']:
        conf.report_optional_feature("Grail", "gRaIL protocol loader", False, "Linux/amd64 only is supported currently")
        conf.env['MODULES_NOT_BUILT'].append('grail-module')
        return

    conf.check_cfg(package='libnl-3.0', uselib_store='NL', mandatory=False)
    conf.check_cfg(package='libnl-3.0', uselib_store='NL', mandatory=False, args=['--cflags'], variables=['cflags'])
    conf.check_cfg(package='libnl-3.0', uselib_store='NL', mandatory=False, args=['--libs'], variables=['libs'])
    print(conf.env.HAVE_NL)
    print(conf.env.NL_cflags)
    print(conf.env.NL_libs)
    conf.report_optional_feature("Grail", "gRaIL protocol loader",
                                 conf.env.HAVE_NL,
                                 "needs pkg-config and libnl-3.0")
    if not conf.env.HAVE_NL:
        conf.env['MODULES_NOT_BUILT'].append('grail-module')

def build(bld):
    module = bld.create_ns3_module('grail', ['internet', 'wifi', 'point-to-point'])
    module.env.append_value('CXXFLAGS', bld.env.NL_cflags)
    module.env.append_value('LDFLAGS', bld.env.NL_libs)
    module.source = [
        'model/grail.cc',
        'model/netlink.cc',
        'model/route.cc',
        'helper/grail-helper.cc',
        ]

    module_test = bld.create_ns3_module_test_library('grail')
    module_test.source = [
        'test/grail-test-suite.cc',
        ]

    headers = bld(features='ns3header')
    headers.module = 'grail'
    headers.source = [
        'model/grail.h',
#        'helper/grail-helper.h',
        ]

    bld(features='c cshlib', source='novdso.c', target='novdso')

    if bld.env.ENABLE_EXAMPLES:
        bld.recurse('examples')

    # bld.ns3_python_bindings()
