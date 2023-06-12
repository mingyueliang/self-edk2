# -*- coding: utf-8 -*-
import pytest
import sys
import os
import re
import copy

from configparser import ConfigParser

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from VfrCompiler.YamlCompiler import VfrCompiler, YamlCompiler, CmdParser

workspace = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))).lower()

outputDirRe = re.compile('^OUTPUT_DIR =')
debugDirRe = re.compile('^DEBUG_DIR =')
incRe = re.compile('^INC =')
pyvfrRe = re.compile('\$\(PYVFR\)')
moduleNameRe = re.compile('^MODULE_NAME =')


# workspaceRe = re.compile(workspace, re.I)

# vfr_compiler_input_files = [
#     # {'InputFileName': r'VlanConfigDxe\VlanConfig.vfr',
#     #  'OutputDirectory': r'VlanConfigDxe\OUTPUT',
#     #  'ModuleName': 'VlanConfigDxe',
#     #  'IncludePaths': [
#     #      r'/Ic:\NetworkPkg\VlanConfigDxe',
#     #      r'/Ic:\VlanConfigDxe\DEBUG',
#     #      r'/Ic:\MdePkg',
#     #      r'/Ic:\MdePkg\Include',
#     #      r'/Ic:\MdePkg\Test\UnitTest\Include',
#     #      r'/Ic:\MdePkg\Include\X64',
#     #      r'/Ic:\MdeModulePkg',
#     #      r'/Ic:\MdeModulePkg\Include',
#     #      r'/Ic:\NetworkPkg',
#     #      r'/Ic:\NetworkPkg\Include'
#     #  ],
#     #  'LanuchVfrCompiler': True,
#     #  'LanuchYamlCompiler': False
#     #  },
#     # {'InputFileName': r'IScsiDxe\IScsiConfigVfr.vfr',
#     #  'OutputDirectory': r'IScsiDxe\OUTPUT',
#     #  'ModuleName': 'IScsiDxe',
#     #  'IncludePaths': [
#     #      r'/Ic:\NetworkPkg\IScsiDxe',
#     #      r'/Ic:\IScsiDxe\DEBUG',
#     #      r'/Ic:\MdePkg',
#     #      r'/Ic:\MdePkg\Include',
#     #      r'/Ic:\MdePkg\Test\UnitTest\Include',
#     #      r'/Ic:\MdePkg\Include\X64',
#     #      r'/Ic:\MdeModulePkg',
#     #      r'/Ic:\MdeModulePkg\Include',
#     #      r'/Ic:\CryptoPkg',
#     #      r'/Ic:\CryptoPkg\Include',
#     #      r'/Ic:\NetworkPkg',
#     #      r'/Ic:\NetworkPkg\Include'],
#     #  'LanuchVfrCompiler': True,
#     #  'LanuchYamlCompiler': False
#     #  }
# ]
# yaml_compiler_input_files = [
#     {'InputFileName': r'VlanConfigDxe\VlanConfig.vfr',
#      'OutputDirectory': r'VlanConfigDxe\OUTPUT',
#      'ModuleName': 'VlanConfigDxe',
#      'IncludePaths': [
#          r'/Ic:\NetworkPkg\VlanConfigDxe',
#          r'/Ic:\Build\OvmfX64\DEBUG_VS2015x86\X64\NetworkPkg\VlanConfigDxe\VlanConfigDxe\DEBUG',
#          r'/Ic:\MdePkg',
#          r'/Ic:\MdePkg\Include',
#          r'/Ic:\MdePkg\Test\UnitTest\Include',
#          r'/Ic:\MdePkg\Include\X64',
#          r'/Ic:\MdeModulePkg',
#          r'/Ic:\MdeModulePkg\Include',
#          r'/Ic:\NetworkPkg',
#          r'/Ic:\NetworkPkg\Include'
#      ],
#      'LanuchVfrCompiler': False,
#      'LanuchYamlCompiler': True
#      },
#     {'InputFileName': r'IScsiDxe\IScsiConfigVfr.vfr',
#      'OutputDirectory': r'IScsiDxe\OUTPUT',
#      'ModuleName': 'IScsiDxe',
#      'IncludePaths': [
#          r'/Ic:\NetworkPkg\IScsiDxe',
#          r'/Ic:\IScsiDxe\DEBUG',
#          r'/Ic:\MdePkg',
#          r'/Ic:\MdePkg\Include',
#          r'/Ic:\MdePkg\Test\UnitTest\Include',
#          r'/Ic:\MdePkg\Include\X64',
#          r'/Ic:\MdeModulePkg',
#          r'/Ic:\MdeModulePkg\Include',
#          r'/Ic:\CryptoPkg',
#          r'/Ic:\CryptoPkg\Include',
#          r'/Ic:\NetworkPkg',
#          r'/Ic:\NetworkPkg\Include'],
#      'LanuchVfrCompiler': False,
#      'LanuchYamlCompiler': True
#      }
# ]


def pytest_addoption(parser):
    parser.addoption("--InputFileName",
                     default='',
                     help="Input file of test."
                     )
    parser.addoption("--OutputDirectory",
                     default='',
                     help='Output dir.'
                     )

    parser.addoption("--ModuleName",
                     default='',
                     help='Module name.'
                     )

    parser.addoption("--IncludePaths",
                     default=[],
                     type=str,
                     help='Include paths.'
                     )
    parser.addoption("--vfr",
                     default=False,
                     action='store_true',
                     help='Lanuch vfr compiler.'
                     )
    parser.addoption("--yaml",
                     action='store_true',
                     default=False,
                     help='Lanuch yaml compiler.'
                     )


class Namespace:
    args_data = {
        'AutoDefault': None,
        'CPreprocessorOptions': None,
        'CheckDefault': None,
        'CreateIfrPkgFile': None,
        'CreateJsonFile': None,
        'CreateRecordListFile': None,
        'CreateYamlFile': None,
        'IncludePaths': None,
        'InputFileName': None,
        'LanuchVfrCompiler': True,
        'LanuchYamlCompiler': False,
        'ModuleName': '',
        'OldOutputDirectory': None,
        'OutputDirectory': None,
        'OverrideClassGuid': None,
        'SkipCPreprocessor': None,
        'StringFileName': None,
        'WarningAsError': None,
    }

    def __init__(self, **kwargs):
        ImP = list()
        for ip in kwargs['IncludePaths']:
            if workspace.split(':')[1] in ip:
                ImP.append(ip)
                continue
            ips = ip.split(':')
            ImP.append(ips[0] + ':' + workspace.split(':')[1] + ips[1])
        kwargs['IncludePaths'] = ImP
        self.args_data.update(kwargs)

    def get_argv(self):
        argv = 1
        for key in self.args_data.keys():
            self.__setattr__(key, self.args_data[key])
            if self.args_data[key]:
                argv += 1
        return argv


#
# Get cmdopt for config
#
@pytest.fixture()
def cmdopt(request, get_target_floder):
    if request.config.getoption("--vfr"):
        get_target_floder[0].append({'InputFileName': request.config.getoption("--InputFileName"),
                                     'OutputDirectory': request.config.getoption("--OutputDirectory"),
                                     'ModuleName': request.config.getoption("--ModuleName"),
                                     'IncludePaths': request.config.getoption('--IncludePaths').split(
                                         ' ') if request.config.getoption(
                                         '--IncludePaths') else request.config.getoption('--IncludePaths'),
                                     'LanuchVfrCompiler': request.config.getoption("--vfr"),
                                     'LanuchYamlCompiler': request.config.getoption("--yaml")
                                     })
    else:
        if request.config.getoption("--yaml"):
            get_target_floder[1].append({'InputFileName': request.config.getoption("--InputFileName"),
                                         'OutputDirectory': request.config.getoption("--OutputDirectory"),
                                         'ModuleName': request.config.getoption("--ModuleName"),
                                         'IncludePaths': request.config.getoption('--IncludePaths').split(
                                             ' ') if request.config.getoption(
                                             '--IncludePaths') else request.config.getoption('--IncludePaths'),
                                         'LanuchVfrCompiler': request.config.getoption("--vfr"),
                                         'LanuchYamlCompiler': request.config.getoption("--yaml")
                                         })

    return get_target_floder


@pytest.fixture()
def get_target_floder(request):
    conf = ConfigParser()
    conf.read(request.config.inifile)
    vars = conf.items('target_floder')
    vfr_compilers = list()
    yaml_compilers = list()
    for floder_path in vars[0][1].split(','):
        if not os.path.abspath(os.path.normpath(floder_path.replace('\n', ''))):
            floder_path = os.path.join(workspace, floder_path)
        if os.path.exists(os.path.join(os.path.normpath(floder_path.replace('\n', '')), 'makefile')):
            with open(os.path.join(os.path.normpath(floder_path.replace('\n', '')), 'makefile'), 'r') as file:
                makefile = file.readlines()
                flag = False
                scops = dict()
                incs = list()
                lanuch = ''
                for line in makefile:
                    if '#' in line:
                        continue
                    elif re.match(outputDirRe, line) or re.match(debugDirRe, line) or re.match(moduleNameRe, line):
                        lines = line.split('=')
                        scops[lines[0].strip()] = lines[1].strip()
                        flag = False
                    elif re.match(incRe, line):
                        flag = True
                        continue
                    elif '=' in line:
                        flag = False
                    elif re.search(pyvfrRe, line):
                        scops['InputFileName'] = line.split(' ')[1].strip()
                        lanuch = line.split(' ')[-1].strip()

                    else:
                        if flag:
                            incs.append(line.replace('\\\n', '').strip())

                # Deal scop
                scops['IncludePaths'] = list()
                for inc in incs:
                    if '$(DEBUG_DIR)' in inc:
                        scops['IncludePaths'].append(inc.replace('$(DEBUG_DIR)', scops['DEBUG_DIR']))
                    if '$(WORKSPACE)' in inc:
                        scops['IncludePaths'].append(inc.replace('$(WORKSPACE)', workspace))
                    if '$(OUTPUT_DIR)' in inc:
                        scops['IncludePaths'].append(inc.replace('$(OUTPUT_DIR)', scops['OUTPUT_DIR']))

                if lanuch == '--vfr':
                    scops['LanuchVfrCompiler'] = True
                    scops['LanuchYamlCompiler'] = False
                    vfr_compilers.append(scops)
                else:
                    scops['LanuchVfrCompiler'] = False
                    scops['LanuchYamlCompiler'] = True
                    yaml_compilers.append(scops)
        else:
            print('Please check path in ini file: ', os.path.normpath(floder_path.replace('\n', '')))

    return vfr_compilers, yaml_compilers


def preprocess_data_of_pytestini():
    conf = ConfigParser()
    conf.read(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'pytest.ini'))
    vars = conf.items('target_floder')

    vfr_compilers = list()
    yaml_compilers = list()
    makefiles = list()
    for floder_path in vars[0][1].split(','):
        if not os.path.isabs(floder_path.replace('\n', '')):
            floder_path = os.path.abspath(floder_path.replace('\n', ''))
        for root, dirs, files in os.walk(floder_path.replace('\n', '')):
            for file in files:
                file_path = os.path.join(root, file)
                if os.path.isfile(file_path) and os.path.basename(file_path) == 'Makefile':
                    makefiles.append(file_path)

    for makefile in makefiles:
        with open(makefile, 'r') as file:
            makefile = file.readlines()
            flag = False
            scops = dict()
            incs = list()
            lanuch = ''
            for line in makefile:
                if '#' in line:
                    continue
                elif re.match(outputDirRe, line) or re.match(debugDirRe, line) or re.match(moduleNameRe, line):
                    lines = line.split('=')
                    scops[lines[0].strip()] = lines[1].strip()
                    flag = False
                elif re.match(incRe, line):
                    flag = True
                    continue
                elif '=' in line:
                    flag = False
                elif re.search(pyvfrRe, line):
                    scops['InputFileName'] = line.split(' ')[1].strip()
                    lanuch = line.split(' ')[-1].strip()

                else:
                    if flag:
                        incs.append(line.replace('\\\n', '').strip())
            if scops.get('InputFileName'):
                # Deal scop
                scops['IncludePaths'] = list()
                for inc in incs:
                    if '$(DEBUG_DIR)' in inc:
                        scops['IncludePaths'].append(inc.replace('$(DEBUG_DIR)', scops['DEBUG_DIR']))
                    if '$(WORKSPACE)' in inc:
                        scops['IncludePaths'].append(inc.replace('$(WORKSPACE)', workspace))
                    if '$(OUTPUT_DIR)' in inc:
                        scops['IncludePaths'].append(inc.replace('$(OUTPUT_DIR)', scops['OUTPUT_DIR']))

                if lanuch == '--vfr' or lanuch == '--yaml':
                    scops['LanuchVfrCompiler'] = True
                    scops['LanuchYamlCompiler'] = False
                    vfr_compilers.append(scops)

                # else:
                    yaml_scops = copy.deepcopy(scops)
                    yaml_scops['LanuchVfrCompiler'] = False
                    yaml_scops['LanuchYamlCompiler'] = True
                    yaml_compilers.append(yaml_scops)

    return vfr_compilers, yaml_compilers


@pytest.fixture(scope='class', params=preprocess_data_of_pytestini()[0])
def vfr_compiler(request):
    # Type args
    compiler = None
    args = Namespace(
        InputFileName=request.param['InputFileName'],
        OutputDirectory=request.param['OutputDirectory'] if request.param.get('OutputDirectory') else request.param.get(
            'OUTPUT_DIR'),
        ModuleName=request.param['ModuleName'] if request.param.get('ModuleName') else request.param.get('MODULE_NAME'),
        IncludePaths=request.param['IncludePaths'],
        LanuchVfrCompiler=request.param['LanuchVfrCompiler'],
        LanuchYamlCompiler=request.param['LanuchYamlCompiler'],
    )
    argv = args.get_argv()
    cmd = CmdParser(args, argv)
    if request.param['LanuchVfrCompiler']:  # LanuchVfrCompiler
        compiler = VfrCompiler(cmd)
        request.cls.compiler = compiler
        yield
        if os.path.exists(compiler.Options.LanuchVfrCompiler):
            os.remove(compiler.Options.JsonFileName)
    if request.param['LanuchYamlCompiler']:  # LanuchYamlCompiler
        compiler = YamlCompiler(cmd)
        request.cls.compiler = compiler
        yield
    # remove output files
    if os.path.exists(compiler.Options.PkgOutputFileName):
        os.remove(compiler.Options.PkgOutputFileName)
    if os.path.exists(compiler.Options.RecordListFileName):
        os.remove(compiler.Options.RecordListFileName)
    if os.path.exists(compiler.Options.COutputFileName):
        os.remove(compiler.Options.COutputFileName)


@pytest.fixture(scope='class', params=preprocess_data_of_pytestini()[1])
def yaml_compiler(request):
    # Type args
    compiler = None
    args = Namespace(
        InputFileName=request.param['InputFileName'],
        OutputDirectory=request.param['OutputDirectory'] if request.param.get('OutputDirectory') else request.param.get(
            'OUTPUT_DIR'),
        ModuleName=request.param['ModuleName'] if request.param.get('ModuleName') else request.param.get('MODULE_NAME'),
        IncludePaths=request.param['IncludePaths'],
        LanuchVfrCompiler=request.param['LanuchVfrCompiler'],
        LanuchYamlCompiler=request.param['LanuchYamlCompiler'],
    )
    argv = args.get_argv()
    cmd = CmdParser(args, argv)
    if request.param['LanuchVfrCompiler']:  # LanuchVfrCompiler
        compiler = VfrCompiler(cmd)
        request.cls.compiler = compiler
        yield compiler
        if os.path.exists(compiler.Options.LanuchVfrCompiler):
            os.remove(compiler.Options.JsonFileName)
    if request.param['LanuchYamlCompiler']:  # LanuchYamlCompiler
        compiler = YamlCompiler(cmd)
        request.cls.compiler = compiler
        yield compiler
    # remove output files
    if os.path.exists(compiler.Options.PkgOutputFileName):
        os.remove(compiler.Options.PkgOutputFileName)
    if os.path.exists(compiler.Options.RecordListFileName):
        os.remove(compiler.Options.RecordListFileName)
    if os.path.exists(compiler.Options.COutputFileName):
        os.remove(compiler.Options.COutputFileName)
