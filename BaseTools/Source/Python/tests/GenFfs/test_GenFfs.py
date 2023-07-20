import pytest
import os
import filecmp
import tempfile
import shutil


class TestGenFfs:
    def setup_class(self):
        self.tmpdir = tempfile.mkdtemp()

    def teardown_class(self):
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def compare_output_file(self, newfile, oldfile):
        try:
            if filecmp.cmp(newfile, oldfile):
                return True
            return False
        except Exception as e:
            print(e)

    def test_output_ffs(self):
        input_command_lines = [
            [
                "-t EFI_FV_FILETYPE_DRIVER",
                "-g 1A1E4886-9517-440e-9FDE-3BE44CEE2136",
                "-o %s" % os.path.join(self.tmpdir, "demo.ffs"),
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "CpuDxe\\1A1E4886-9517-440e-9FDE-3BE44CEE2136SEC1.1.dpx"),
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "CpuDxe\\1A1E4886-9517-440e-9FDE-3BE44CEE2136SEC2.1.pe32"),
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "CpuDxe\\1A1E4886-9517-440e-9FDE-3BE44CEE2136SEC3.ui"),
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "CpuDxe\\1A1E4886-9517-440e-9FDE-3BE44CEE2136SEC4.ver")
            ],
            [
                "-t EFI_FV_FILETYPE_DRIVER",
                "-g 9FB1A1F3-3B71-4324-B39A-745CBB015FFF",
                "-o %s" % os.path.join(self.tmpdir, "demo1.ffs"),
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "Ip4Dex\\9FB1A1F3-3B71-4324-B39A-745CBB015FFFSEC1.1.dpx"),
                "-oi %s" % os.path.join(os.path.dirname(__file__), "Ip4Dex\\Ip4DxeOffset.raw"),
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "Ip4Dex\\9FB1A1F3-3B71-4324-B39A-745CBB015FFFSEC2.1.pe32"),
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "Ip4Dex\\9FB1A1F3-3B71-4324-B39A-745CBB015FFFSEC3.ui"),
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "Ip4Dex\\9FB1A1F3-3B71-4324-B39A-745CBB015FFFSEC4.ver"),

            ],
        ]

        output_files = [
            {"oldffs": os.path.join(os.path.dirname(__file__), 'CpuDxe\\1A1E4886-9517-440e-9FDE-3BE44CEE2136.ffs'),
             "newffs": os.path.join(self.tmpdir, 'demo.ffs')},
            {"oldffs": os.path.join(os.path.dirname(__file__), 'Ip4Dex\\9FB1A1F3-3B71-4324-B39A-745CBB015FFF.ffs'),
             "newffs": os.path.join(self.tmpdir, 'demo1.ffs')},
        ]

        for index in range(len(input_command_lines)):
            cmd = 'py -3 '
            root_path = os.path.join(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
                                     'GenFfs\\GenFfs.py')
            cmd += root_path
            cmd += " "
            cmd += ' '.join(input_command_lines[index])
            os.system(cmd)

            assert os.path.exists(output_files[index]['newffs'])
            assert self.compare_output_file(output_files[index]['newffs'], output_files[index]['oldffs'])


if __name__ == '__main__':
    pytest.main(['-vs', 'test_GenFfs.py'])
