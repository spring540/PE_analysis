using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace PE_analysis
{
    public class analyzer
    {
        private string path;
        public analyzer(string file_path)
        {
            this.path = file_path;
        }

        //读取address_functions的内容，长度是number_of_functions，并将地址写入result[i*3+1]
        //未加载导入表导出表，按需加载
        public PE_informaton load_all_and_fill_in()
        {
            PE_informaton pe_info = new PE_informaton();
            data_process dp = new data_process();
            if (check_vaild())
            {
                string[] PE_headers = load();
                if (PE_headers[0] != "Format Failing")
                {
                    pe_info.magic = PE_headers[1];
                    pe_info.lfanew = PE_headers[2];

                    pe_info.machine = PE_headers[3];
                    pe_info.number_of_sections = PE_headers[4];
                    pe_info.time_data_stamp = PE_headers[5];
                    pe_info.pointer_to_symbol_table = PE_headers[6];
                    pe_info.number_of_symbols = PE_headers[7];
                    pe_info.size_of_optional_header = PE_headers[8];
                    pe_info.characterastic = PE_headers[9];

                    pe_info.optional_magic = PE_headers[10];
                    pe_info.MajorLinkerVersion = PE_headers[11];
                    pe_info.MinorLInkerVersion = PE_headers[12];
                    pe_info.SizeofCode = PE_headers[13];
                    pe_info.SizeOfInitializedData = PE_headers[14];
                    pe_info.SizeOfUninitializedData = PE_headers[15];
                    pe_info.AddressOfEntryPoint = PE_headers[16];
                    pe_info.BaseOfCode = PE_headers[17];
                    pe_info.BaseOfData = PE_headers[18];
                    pe_info.ImageBase = PE_headers[19];
                    pe_info.SectionAlignment = PE_headers[20];
                    pe_info.FileAlignment = PE_headers[21];
                    pe_info.MajorOperatingSystemVersion = PE_headers[22];
                    pe_info.MinorOperatingSystemVersion = PE_headers[23];
                    pe_info.MajorImageVersion = PE_headers[24];
                    pe_info.MinorImageVersion = PE_headers[25];
                    pe_info.MajorSubSystemVersion = PE_headers[26];
                    pe_info.MinorSubSystemVersion = PE_headers[27];
                    pe_info.Win32VersionValue = PE_headers[28];
                    pe_info.SizeOfimage = PE_headers[29];
                    pe_info.SizeOfHeaders = PE_headers[30];
                    pe_info.CheckSum = PE_headers[31];
                    pe_info.Subsystem = PE_headers[32];
                    pe_info.DLLCharacteristics = PE_headers[33];
                    pe_info.SizeOfStackReserve = PE_headers[34];
                    pe_info.SizeOfStackCommit = PE_headers[35];
                    pe_info.SizeOfHeapReserve = PE_headers[36];
                    pe_info.SizeOfHeapCommit = PE_headers[37];
                    pe_info.LoaderFlags = PE_headers[38];
                    pe_info.NumberOfRvaAndSizes = PE_headers[39];
                }
                pe_info.section = load_section();
                pe_info.pe_location = load_location(pe_info.lfanew, pe_info.size_of_optional_header);
                pe_info.data_directory = load_data_directory(pe_info.pe_location);
            }

            return pe_info;
        }

        public void load_and_write_ordinals_address(string[] result, int number_of_functions, int FOA_address_functions, int Base)
        {
            FileStream F = new FileStream(this.path, FileMode.Open, FileAccess.Read);
            data_process dp = new data_process();

            F.Position = FOA_address_functions;
            byte[] tool = new byte[4];
            int real_num_func = 0;

            for(int i = 0; i<number_of_functions; i++)
            {
                F.Read(tool, 0, 4);
                if(dp.byte_to_int(tool, 1, 4) != 0)
                {
                    result[real_num_func * 3 + 1] = dp.byte_to_str(tool, 1, 4);
                    result[real_num_func * 3 + 2] = Convert.ToString(Base + i);
                    result[real_num_func * 3 + 3] = "";
                    real_num_func++;
                }
            }
            result[0] = Convert.ToString(real_num_func);
            F.Close();
        }

        public void load_and_write_name(string[] result, int number_of_name, int FOA_address_name_ordinals, int FOA_address_names, int Base, PE_informaton pe_info)
        {
            FileStream F = new FileStream(this.path, FileMode.Open, FileAccess.Read);
            data_process dp = new data_process();
            

            
            byte[] tool = new byte[4];
            byte[] tool2 = new byte[2];

            for(int i = 0; i<number_of_name; i++)
            {
                F.Position = FOA_address_names + i * 4;
                F.Read(tool, 0, 4);
                string func_name = load_str(RVA_to_FOA(dp.byte_to_int(tool, 1, 4), pe_info) , F);

                F.Position = FOA_address_name_ordinals + i * 2;
                F.Read(tool2, 0, 2);
                int base_offset = dp.byte_to_int(tool2, 1, 2);
                for(int j = 0; j < int.Parse(result[0]); j++)
                {
                    if(int.Parse(result[j * 3 + 2]) - Base == base_offset)
                    {
                        result[j * 3 + 3] = String.Concat(result[j * 3 + 3], func_name);
                        break;
                    }
                }
            }
            return;
        }

        public string load_str(int FOA_str_address, FileStream F)
        {
            string result = "";
            F.Position = FOA_str_address;
            int tool;
            string part;
            tool = F.ReadByte();
            while(tool!=0)
            {
                part = ((char)tool).ToString();
                result = String.Concat(result, part);
                tool = F.ReadByte();
            }
            return result;
        }

        public void load_export(PE_informaton pe_info, int offset)
        {
            FileStream F = new FileStream(this.path, FileMode.Open, FileAccess.Read);
            PE_export result = new PE_export();
            data_process dp = new data_process();

            F.Position = offset;
            byte[] tool = new byte[4];

            F.Read(tool, 0, 4);
            result.characterasic = tool;

            F.Read(tool, 0, 4);
            result.TimeDataStamp = tool;

            F.Read(tool, 0, 2);
            result.MajorVersion = tool;

            F.Read(tool, 0, 2);
            result.MinorVersion = tool;

            F.Read(tool, 0, 4);
            result.Name = dp.byte_to_int(tool, 1, 4);

            F.Read(tool, 0, 4);
            result.Base = dp.byte_to_int(tool, 1, 4);

            F.Read(tool, 0, 4);
            result.NumberOfFunctions = dp.byte_to_int(tool, 1, 4);

            F.Read(tool, 0, 4);
            result.NumberOfName = dp.byte_to_int(tool, 1, 4);

            F.Read(tool, 0, 4);
            result.AddressOfFunctions = dp.byte_to_int(tool, 1, 4);

            F.Read(tool, 0, 4);
            result.AddressOfNames = dp.byte_to_int(tool, 1, 4);

            F.Read(tool, 0, 4);
            result.AddressOfNameOrdinals = dp.byte_to_int(tool, 1, 4);

            pe_info.export = result;
            F.Close();
            return; 
        }

        public void load_import(PE_informaton pe_info, int offset)
        {
            data_process dp = new data_process();
            analyzer PE_AN = new analyzer(this.path);
            FileStream F = new FileStream(this.path, FileMode.Open, FileAccess.Read);
            F.Position = offset;
            byte[] tool = new byte[4];
            int OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk;

            List<PE_import> import_table = new List<PE_import>();
            while(true)
            {
                PE_import cursor = new PE_import();
                F.Read(tool, 0, 4);
                OriginalFirstThunk = dp.byte_to_int(tool, 1, 4);

                F.Read(tool, 0, 4);
                TimeDateStamp = dp.byte_to_int(tool, 1, 4);

                F.Read(tool, 0, 4);
                ForwarderChain = dp.byte_to_int(tool, 1, 4);

                F.Read(tool, 0, 4);
                Name = dp.byte_to_int(tool, 1, 4);

                F.Read(tool, 0, 4);
                FirstThunk = dp.byte_to_int(tool, 1, 4);

                if(OriginalFirstThunk + TimeDateStamp + ForwarderChain + Name + FirstThunk == 0)
                {
                    break;
                }
                else
                {
                    cursor.OriginalFirstThunk = OriginalFirstThunk;
                    cursor.TimeDateStamp = TimeDateStamp;
                    cursor.ForwarderChain = ForwarderChain;
                    cursor.Name = Name;
                    cursor.FirstThunk = FirstThunk;
                    import_table.Add(cursor);
                }
            }
            pe_info.imports = import_table.ToArray();
            F.Close();
            return;

        }
        //检查文件是否存在
        public bool check_vaild()
        {
            FileInfo fInfo = new FileInfo(this.path);
            if (fInfo.Exists)
            {
                return true;
            }
            else return false;
        }

        //FOA = 对应PointerTORawdata + RVA - 对应VirtualAddress
        //对应的VirtualAddress获取方式：查看每一个节的VirtualAddress，对比RVA，若RVA>那个节且小于后一个节的Vir，那RVA就属于那个节
        public int RVA_to_FOA(int RVA, PE_informaton pe_info)
        {
            
            data_process dp = new data_process();
            if (RVA < dp.str16_to_int(pe_info.SizeOfHeaders))
            {
                return RVA;
            }
                //number_of_sec : pe_info.number_of_sections
            int number_of_sec = dp.str16_to_int(pe_info.number_of_sections);
            int locate_section = 1;
            for(int i = 0; i<number_of_sec; i++)
            {
                if(i == number_of_sec - 1)
                {
                    locate_section = i;
                    break;
                }
                if(RVA >= dp.str16_to_int(pe_info.section[i * 10 + 3]) && RVA < dp.str16_to_int(pe_info.section[i * 10 + 10 + 3]))
                {
                    locate_section = i;
                    break;
                }
            }
            int FOA = dp.str16_to_int(pe_info.section[locate_section * 10 + 5]) + RVA - dp.str16_to_int(pe_info.section[locate_section * 10 + 3]);
            return FOA;
        }

        //RVA = 对应节的VirtualAddress + FOA - 对应节的Pointer_to_raw_data
        public int FOA_to_RVA(int FOA, PE_informaton pe_info)
        {
            data_process dp = new data_process();
            int number_of_sec = dp.str16_to_int(pe_info.number_of_sections);
            int locate_section = 1;
            for(int i = 0; i<number_of_sec; i++)
            {
                if (i == number_of_sec - 1)
                {
                    locate_section = i;
                    break;
                }
                if (FOA >= dp.str16_to_int(pe_info.section[i * 10 + 5]) && FOA < dp.str16_to_int(pe_info.section[i * 10 + 10 + 5]))
                {
                    locate_section = i;
                    break;
                }
            }
            int RVA = dp.str16_to_int(pe_info.section[locate_section * 10 + 3]) + FOA - dp.str16_to_int(pe_info.section[locate_section * 10 + 5]);
            return RVA;
        }


        //加载exe文件头部各个字段的位置
        public int[] load_location(string lfanew, string size_of_optional_header)
        {
            data_process dp = new data_process();
            int[] result = new int[41];

            int int_lfanew = dp.str16_to_int(lfanew);
            int int_optional_header = dp.str16_to_int(size_of_optional_header);

            //DOS头
            result[0] = 0x00;//magic
            result[1] = 0x3c;//lfanew

            int cursor = int_lfanew + 4;
            //标准PE头
            int[] tool = { 0x00, 0x02, 0x04, 0x08, 0x0c, 0x10, 0x12 };
            for(int i = 2; i< 9; i++)
            {
                result[i] = cursor + tool[i - 2];
            }

            cursor = cursor + 0x14;
            //可选PE头
            int[] tool2 = { 0x00, 0x02, 0x03, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x38,
                            0x3c, 0x40, 0x44, 0x46, 0x48, 0x4c, 0x50, 0x54, 0x58, 0x5c ,0x60};
            for(int i = 9; i< 9+tool2.Length; i++)
            {
                result[i] = cursor + tool2[i-9];
            }
            result[40] = cursor + dp.str16_to_int(size_of_optional_header);//40:节表头部位置
            return result;
        }

        //加载exe文件节的信息
        public string[] load_section()
        {
            string[] result = new string[300];

            data_process dp = new data_process();
            byte[] tool = new byte[10];
            FileStream F = new FileStream(this.path, FileMode.Open, FileAccess.Read);
            F.Position += 0x3c;
            F.Read(tool, 0, 4);
            int e_lfanew = dp.byte_to_int(tool, 1, 4);

            F.Position = e_lfanew + 4;//跳转到标准PE头
            F.Position += 2;//跳转到number_of_sections
            F.Read(tool, 0, 2);
            int num_sec = dp.byte_to_int(tool, 1, 2);

            F.Position += 0x10 - 0x4;//跳转到size_of_optional_headers
            F.Read(tool, 0, 2);
            int size_opt = dp.byte_to_int(tool, 1, 2);

            F.Position += 2 + size_opt;//跳转到节表开头

            for(int i = 0; i<num_sec; i++)
            {
                F.Read(tool, 0, 8);
                result[i * 10 +1] = dp.byte_to_ascii(tool, 1, 8);//name字段，1

                F.Read(tool, 0, 4);
                result[i * 10 +2] = dp.byte_to_str(tool, 1, 4);//virtualsize,2

                F.Read(tool, 0, 4);
                result[i * 10 +3] = dp.byte_to_str(tool, 1, 4);//VirtualAddress,3

                F.Read(tool, 0, 4);
                result[i * 10 +4] = dp.byte_to_str(tool, 1, 4);//size_of_raw_data,4

                F.Read(tool, 0, 4);
                result[i * 10 +5] = dp.byte_to_str(tool, 1, 4);//pointer_to_raw_data,5

                F.Read(tool, 0, 4);
                result[i * 10 +6] = dp.byte_to_str(tool, 1, 4);//pointer_to_relocation,6

                F.Read(tool, 0, 4);
                result[i * 10 +7] = dp.byte_to_str(tool, 1, 4);//pointer_to_line_numbers,7

                F.Read(tool, 0, 2);
                result[i * 10 +8] = dp.byte_to_str(tool, 1, 2);//number_of_relocation,8

                F.Read(tool, 0, 2);
                result[i * 10 +9] = dp.byte_to_str(tool, 1, 2);//number_of_line_number,9

                F.Read(tool, 0, 4);
                result[i * 10 +10] = dp.byte_to_str(tool, 1, 4);//characterastic,10

            }
            F.Close();
            return result;

        }

        //读取data_directory字段
        public int[] load_data_directory(int[] pe_location)
        {
            data_process dp = new data_process();
            int[] result = new int[33];
            byte[] tool = new byte[4];
            FileStream F = new FileStream(this.path, FileMode.Open, FileAccess.Read);
            F.Position = pe_location[38] + 4;


            //16个结构体数组，使用result[1-32]存储，其中
            //IMAGE_DIRECTORY_ENTRY_EXPORT 导出表 1
            //IMAGE_DIRECTORY_ENTRY_IMPORT 导入表 2
            //IMAGE_DIRECTORY_ENTRY_RESOURCE 资源 3
            //IMAGE_DIRECTORY_ENTRY_EXCEPTION 异常 4
            //IMAGE_DIRECTORY_ENTRY_SECURITY 安全 5
            //IMAGE_DIRECTORY_ENTRY_BASERELOC  重定位   6
            //IMAGE_DIRECTORY_ENTRY_DEBUG  调试  7
            //IMAGE_DIRECTORY_ENTRY_COPYRIGHT 版权 8
            //IMAGE_DIRECTORY_ENTRY_GLOBALPTR 全局指针 9
            //IMAGE_DIRECTORY_ENTRY_TLS TLS表 10
            //IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 载入设置 11
            //IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 输入范围 12
            //IMAGE_DIRECTORY_ENTRY_IAT IAT表 13
            //IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 延迟输入 14
            //IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR COM 15
            //保留位置 16
            for (int i = 0; i<16; i++)
            {
                F.Read(tool, 0, 4);
                result[i * 2 + 1] = dp.byte_to_int(tool, 1, 4);
                F.Read(tool, 0, 4);
                result[i * 2 + 2] = dp.byte_to_int(tool, 1, 4);
            }
            F.Close();
            return result;

        }

        //针对某exe文件，生成一个image_buffer文件，方便分析
        public bool generate_image_buffer(int size_of_image, int size_of_headers, int[] section_info)//section_info[0]:有几个节，[1、3、5...]:virtual_address,
        {
            //读取四种对象：
            //1、标准PE头中的number_of_section。
            //2、可选PE头中的size_of_image。
            //3、各个节表中的virtual_address。
            //4、各个节表中的size_of_raw_data。
            //5、可选PE头中的size_of_headers。
            FileStream new_file = new FileStream("G:/code/PE_test/test2.exe", FileMode.OpenOrCreate, FileAccess.ReadWrite);
            FileStream file = new FileStream(this.path, FileMode.Open, FileAccess.Read);

            //复制size_of_headers长度的数据到新文件中
            for(int i = 0; i<size_of_headers; i++)
            {
                new_file.WriteByte((byte)file.ReadByte());
            }


            //从size_of_headers到第一个节的virtual_address中间的数据全部填0
            int first_section = section_info[1];
            for(int i = 0; i<first_section-size_of_headers; i++)
            {
                new_file.WriteByte((byte)0);
            }

            //按照节的个数，分别复制size_of_raw_data长度的数据到newfile。
            for(int i = 0; i<section_info[0]; i++)
            {
                for(int k = 0; k<section_info[2*i+2]; k++)//size_of_raw_data
                {
                    new_file.WriteByte((byte)file.ReadByte());
                }

                long ll = new_file.Position;//记录new_file位置，用0补全到下一个节中间的这些字节
                if (i == section_info[0] - 1)//如果是最后一个节，就用size_of_image代替下一个节的virtual_address
                {
                    for (int j = 0; j < size_of_image - ll; j++)//virtual_address
                    {
                        new_file.WriteByte((byte)0);
                    }
                }
                else
                {
                    for (int j = 0; j < section_info[2 * i + 3] - ll; j++)//virtual_address
                    {
                        new_file.WriteByte((byte)0);
                    }
                }

            }
            new_file.Close();
            file.Close();
            return true;
        }

        //读取标准PE头和可选PE头
        public string[] load()
        {
            string[] result = new string[100];
            FileStream F = new FileStream(this.path, FileMode.Open, FileAccess.Read);
            byte[] tool = {0,0,0,0};
            try
            {
                F.Read(tool, 0, 2);//magic_num
                data_process dp = new data_process();//引入数据处理类
                string v = dp.byte_to_str(tool, 1, 2);
                if(v != "5A4D")//魔数不对
                {
                    result[0] = "Format Failing";
                    return result;
                }
                result[1] = v;
                F.Position = 60;//F定位到头偏移处
                F.Read(tool, 0, 4);//读四个字节
                v = dp.byte_to_str(tool, 1, 4);//这四个字节转字符串
                result[2] = v;//写进结果数组
                int PE_Offset = dp.byte_to_int(tool, 1, 4);//这四个字节转十进制，方便后面写偏移

                //读取标准PE头前的四个字节
                F.Position = PE_Offset;
                F.Read(tool, 0, 4);//读四个字节，如果不是00 00 45 50，就不能解析
                v = dp.byte_to_str(tool, 1, 4);
                if(v != "00004550")
                {
                    result[0] = "Format Failing";
                    return result;
                }

                //读取标准PE头
                int[] cursor = { 2, 2, 4, 4, 4, 2, 2 };//共计20个字节
                for(int i=0; i<cursor.Length; i++)
                {
                    F.Read(tool, 0, cursor[i]);
                    v = dp.byte_to_str(tool, 1, cursor[i]);
                    result[i + 3] = v;
                }

                //读取可选PE头
                int[] cursor2 = { 2, 1, 1, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 2, 4, 4, 4, 4, 2, 2, 4, 4, 4, 4, 4, 4 };
                for(int i=0; i<cursor2.Length; i++)
                {
                    F.Read(tool, 0, cursor2[i]);
                    v = dp.byte_to_str(tool, 1, cursor2[i]);
                    result[i + 3 + cursor.Length] = v;
                }
            }
            catch(IOException)
            {
                Console.Write("Load Failed!");
            }
            finally
            {
                F.Close();
            }
            result[0] = "Success";
            return result;
        }

       

        //读取节信息，这里已经直接写到了Form3
        public string[] section_analyze()
        {

            string[] result = {"sdf" };
            return result;
        }
    }
}
