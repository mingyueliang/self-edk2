import os
import pytest


@pytest.mark.usefixtures('yaml_compiler')
class TestYamlCompiler:
    def test_yaml_compiler_build_flow(self):
        self.compiler.PreProcess()
        self.compiler.Compile()
        self.compiler.ConsumeDLT()
        self.compiler.GenBinaryFiles()
        assert os.path.exists(self.compiler.Options.PkgOutputFileName)
        assert os.path.exists(self.compiler.Options.COutputFileName)
        assert os.path.exists(self.compiler.Options.RecordListFileName)

    def test_yaml_lst_file_content(self):
        with open(self.compiler.Options.RecordListFileName, 'r') as file:
            pyVfr_opcode_list = self.get_opcode_list(file)
        with open(os.path.join(os.path.dirname(self.compiler.Options.RecordListFileName),
                               os.path.basename(self.compiler.Options.RecordListFileName).split('_')[1]), 'r') as f:
            cVfr_opcode_list = self.get_opcode_list(f)

        for i, opcode in enumerate(pyVfr_opcode_list):
            assert opcode == cVfr_opcode_list[i]

    @classmethod
    def get_opcode_list(cls, file):
        all_opcode_record_list = list()
        start_opcode_flags = False
        for line in file.readline():
            if '#' in line or line == '\n':
                continue
            if 'All Opcode Record List' in line:
                start_opcode_flags = True
                continue
            if start_opcode_flags and '>' in line:
                all_opcode_record_list.append(line)
                continue
            if 'Total Size of all record' in line:
                break
        return all_opcode_record_list
