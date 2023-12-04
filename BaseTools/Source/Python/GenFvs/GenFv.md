# GenFv

1. DumpCapsule - 100%
   - Print capsule image header infomation
2. GenCapImage
   1. Parse Inf file
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
                  1. Find Pe Image -> GetSectionByType()
                  2. Get file Pdbpointer -> PeCoffLoaderGetPdbPointer()
                  3. Get PeHeader pointer
                  4. PeCoffLoaderLoadImage()
                  5. Reloc Section
                     1. not exist: Next Pe32 section
                     2. exist: Load and Relocate Data
                        1. Load -> PeCoffLoaderLoadImage()
                        2. Copy Relocated data to raw image file.

