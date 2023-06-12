# Unit testing of vfrcompiler

## Project Repo link
[edk2](https://github.com/yytshirley/edk2.git)

## Environmental 
- clone edk2 repo
- run build

## pytest
- install: pip install pytest

## Run test
- cd edk2\BaseTools\Source\Python\tests
- open pytest.ing and Modify the parameters that need to be used
```
[target_floder]
target_test_folders =
    #C:\Users\mliang2x\WorkSpace\edk2\Build\OvmfX64\DEBUG_VS2015x86\X64\NetworkPkg\IScsiDxe\IScsiDxe,
    #C:\Users\mliang2x\WorkSpace\edk2\Build\OvmfX64\DEBUG_VS2015x86\X64\NetworkPkg\VlanConfigDxe\VlanConfigDxe,
    #IScsiDxe,
    #VlanConfigDxe,
    C:\Users\mliang2x\WorkSpace\edk2\Build

This parameter is the output directory after building.
```
- run pytest in cmd