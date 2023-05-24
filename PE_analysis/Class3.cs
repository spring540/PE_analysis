using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PE_analysis
{
    public class PE_informaton
    {
        public int[] pe_location;//PE关键字段位置
        public string[] section;//节信息
        public int[] data_directory;//数据目录，16个结构体组成

        public PE_export export;//导出表
        public PE_import[] imports;//导入表，可能有多个
        

        //DOS头
        public string  magic;
        public string  lfanew ;

        //标准PE头
        public string  machine;
        public string  number_of_sections;
        public string  time_data_stamp;
        public string  pointer_to_symbol_table;
        public string  number_of_symbols;
        public string  size_of_optional_header;
        public string  characterastic;

        //可选PE头
        public string  optional_magic;
        public string  MajorLinkerVersion;
        public string  MinorLInkerVersion;
        public string  SizeofCode;
        public string  SizeOfInitializedData;
        public string  SizeOfUninitializedData;
        public string  AddressOfEntryPoint;
        public string  BaseOfCode;
        public string  BaseOfData;
        public string  ImageBase;
        public string  SectionAlignment;
        public string  FileAlignment;
        public string  MajorOperatingSystemVersion;
        public string  MinorOperatingSystemVersion;
        public string  MajorImageVersion;
        public string  MinorImageVersion;
        public string  MajorSubSystemVersion;
        public string  MinorSubSystemVersion;
        public string  Win32VersionValue;
        public string  SizeOfimage;
        public string  SizeOfHeaders;
        public string  CheckSum;
        public string  Subsystem;
        public string  DLLCharacteristics;
        public string  SizeOfStackReserve;
        public string  SizeOfStackCommit;
        public string  SizeOfHeapReserve;
        public string  SizeOfHeapCommit;
        public string  LoaderFlags;
        public string  NumberOfRvaAndSizes;

    }

    public class PE_export
    {
        public byte[] characterasic;

        public byte[] TimeDataStamp;

        public byte[] MajorVersion;

        public byte[] MinorVersion;

        public int Name;

        public int Base;

        public int NumberOfFunctions;

        public int NumberOfName;

        public int AddressOfFunctions;

        public int AddressOfNames;

        public int AddressOfNameOrdinals;

    }

    public class PE_import//用于存储导出表各个字段信息
    {
        public int OriginalFirstThunk;

        public int TimeDateStamp;

        public int ForwarderChain;

        public int Name;

        public int FirstThunk;
    }

}
