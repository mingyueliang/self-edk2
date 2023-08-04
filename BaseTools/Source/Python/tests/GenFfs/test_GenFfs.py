import pytest
import os
import filecmp
import tempfile
import shutil
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))




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
            # pe32: No -n
            [
                "-t EFI_FV_FILETYPE_DRIVER",
                "-g 1A1E4886-9517-440e-9FDE-3BE44CEE2136",
                "-o %s" % os.path.join(self.tmpdir, "CpuDxe.ffs"),
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "CpuDxe\\1A1E4886-9517-440e-9FDE-3BE44CEE2136SEC1.1.dpx"),
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "CpuDxe\\1A1E4886-9517-440e-9FDE-3BE44CEE2136SEC2.1.pe32"),
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "CpuDxe\\1A1E4886-9517-440e-9FDE-3BE44CEE2136SEC3.ui"),
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "CpuDxe\\1A1E4886-9517-440e-9FDE-3BE44CEE2136SEC4.ver")
            ],
            # pe32: -n 0
            [
                "-t EFI_FV_FILETYPE_PEI_CORE",
                "-g 52C05B14-0B98-496c-BC3B-04B50211D680",
                "-o %s" % os.path.join(self.tmpdir, "PeiCore.ffs"),
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "PeiCore\\52C05B14-0B98-496c-BC3B-04B50211D680SEC1.1.pe32"),
                "-n 0",
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "PeiCore\\52C05B14-0B98-496c-BC3B-04B50211D680SEC2.ui"),
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "PeiCore\\52C05B14-0B98-496c-BC3B-04B50211D680SEC3.ver"),
            ],
            # te:
            [
                "-t EFI_FV_FILETYPE_PEIM",
                "-g 1DDA5978-B29A-4EA7-AEFB-8B0BAA982E22",
                "-o %s" % os.path.join(self.tmpdir, "RouterPei.ffs"),
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "RouterPei\\1DDA5978-B29A-4EA7-AEFB-8B0BAA982E22SEC1.1.dpx"),
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "RouterPei\\1DDA5978-B29A-4EA7-AEFB-8B0BAA982E22SEC2.1.te"),
                "-n 32",
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "RouterPei\\1DDA5978-B29A-4EA7-AEFB-8B0BAA982E22SEC3.ui"),
                "-oi %s" % os.path.join(os.path.dirname(__file__),
                                        "RouterPei\\1DDA5978-B29A-4EA7-AEFB-8B0BAA982E22SEC4.ver"),
            ],
            # guided:
            [
                "-t EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE",
                "-g e4c65347-fd90-4143-8a41-113e1015fe07",
                "-o %s" % os.path.join(self.tmpdir, "FVBSP.ffs"),
                "-i %s" % os.path.join(os.path.dirname(__file__),
                                       "FVBSP\\e4c65347-fd90-4143-8a41-113e1015fe07SEC1.guided")
            ],

        ]

        output_files = [
            {"oldffs": os.path.join(os.path.dirname(__file__), 'CpuDxe\\1A1E4886-9517-440e-9FDE-3BE44CEE2136.ffs'),
             "newffs": os.path.join(self.tmpdir, 'CpuDxe.ffs')},
            {"oldffs": os.path.join(os.path.dirname(__file__), 'PeiCore\\52C05B14-0B98-496c-BC3B-04B50211D680.ffs'),
             "newffs": os.path.join(self.tmpdir, 'PeiCore.ffs')},
            {"oldffs": os.path.join(os.path.dirname(__file__), 'RouterPei\\1DDA5978-B29A-4EA7-AEFB-8B0BAA982E22.ffs'),
             "newffs": os.path.join(self.tmpdir, 'RouterPei.ffs')},
            {"oldffs": os.path.join(os.path.dirname(__file__), 'FVBSP\\e4c65347-fd90-4143-8a41-113e1015fe07.ffs'),
             "newffs": os.path.join(self.tmpdir, 'FVBSP.ffs')},
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
