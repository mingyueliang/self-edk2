# GenFv

1. DumpCapsule - 100%

      1.Print capsule image header infomation

2. GenCapImage

   1. Parse Inf file
   2. Generate Cap image

3. GenFvImage

   1. Parse inf file

   2. Create Fv image

      1. Calculate Fv Size

      2. Create Fv header

      3. record FV size information into FvMap file.

      4. record FV size information to FvReportFile.

      5. Add PI FV extensize header

      6. Add files to FV

         1. For None PI Ffs file, directly add them into FvImage.
         2. Verify Ffs file
         3. Verify space exists to add the file
         4. Verify the input file is the duplicated file in this Fv image
         5. Update the file statue based on polarity of the FV.
         6. Check if alignment is required
         7. if we have a VTF file, add it at the top
            1. Rebase the PE or TE image in FileBuffer of FFS file for XIP Rebase for the debug genfvmap tool -> FfsRebase()
               1. GetChildFvFromFfs(): Get the base address of the FV section containing PE/TE in the ffs file and record it
               2. Rebase eah PE32 section
                  1. Find Pe Image and find Te Image-> GetSectionByType()
                  2. Get file Pdbpointer -> PeCoffLoaderGetPdbPointer()
                  3. PeCoffLoaderGetImageInfo()
                  4. PeCoffLoaderLoadImage()
                  5. Reloc Section
                     1. not exist: Next Pe32 section
                     2. exist: Load and Relocate Data
                        1. Load -> PeCoffLoaderLoadImage()
                        2. Copy Relocated data to raw image file.
               3. Copy VTF file image to Fv Image
               4. Write Ffs name and Vtf file base address to Fv report file.

         8. Add pad file if necessary
         9. Add other file in FV
            1. AdjustInternalFfsPadding()
            2. Ffs rebase follow step 7.1
            3. Copy ffs file image to FV image
            4. Write Ffs name and Vtf file base address to Fv report file.

         10. Make next file start at QWord Boundary

      7. If there is a VTF file, some special actions need to occur.

      8. Update Vector according to mArm, mRiscV and mLoongArch

         1. mArm: UpdateArmResetVectorIfNeeded()
         2. mRiscV: UpdateRiscvResetVectorIfNeeded()
         3. mLoongArch: UpdateLoongArchResetVectorIfNeeded()

      9. Update FV Alignment attribute to the largest alignment of all the FFS files in the FV

      10. If there are large FFS in FV, the file system GUID should set to system 3 GUID.
