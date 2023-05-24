using System;
using System.IO;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Text.RegularExpressions;


namespace PE_analysis
{
    public partial class Form6 : Form
    {
        private string tb1_str = "长度限8以内，仅能是数字和英文字母以及某些符号的排列组合";
        private string path;
        private PE_informaton pe_info;
        public Form6(string path, PE_informaton pe_info)
        {
            InitializeComponent();
            this.path = path;
            this.pe_info = pe_info;
            SetDefaultText();

            label1.Text = this.path;

            textBox1.GotFocus += new EventHandler(text_Enter);
            textBox1.LostFocus += new EventHandler(text_Leave);

            textBox3.Text = "F:\\方班研讨厅33期4班";
        }

        private void SetDefaultText()
        {
            textBox1.Text = tb1_str;
            textBox1.ForeColor = Color.Gray;
        }

        private void text_Enter(object sender, EventArgs e)
        {
            if (textBox1.Text == tb1_str)
            {
                //清空文本框
                textBox1.Text = "";
                textBox1.ForeColor = Color.Black;
            }
        }

        private void text_Leave(object sender, EventArgs e)
        {
            if(String.IsNullOrEmpty(textBox1.Text))
            {
                SetDefaultText();
            }
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            FolderBrowserDialog dialog = new FolderBrowserDialog();
            dialog.Description = "选择输出文件路径";
            if (dialog.ShowDialog() == DialogResult.OK)
            {
                string foldpath = dialog.SelectedPath;
                textBox3.Text = foldpath;
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            this.Hide();
        }

        private void button2_Click(object sender, EventArgs e)//插入并生成
        {
            data_process dp = new data_process();
            if(String.IsNullOrEmpty(textBox1.Text)||Regex.Matches(textBox1.Text, @"^[\S]{1,8}$").Count == 0)
            {
                MessageBox.Show("请正确输入节名称");
                return;
            }
            if(!(Directory.Exists(textBox3.Text)))
            {
                MessageBox.Show("文件路径不存在，请重新选择");
                return;
            }

            List<byte> contenter = new List<byte>();
            if(!dp.str_to_muli_byte(textBox2.Text, contenter))
            {
                MessageBox.Show("输入的字节码有误，请检查格式。");
                return;
            }
            if(!dp.is_digit(textBox4.Text))
            {
                MessageBox.Show("输入的节大小格式不对，应为10进制整数。");
                return;
            }
            byte access = 0;
            if(checkBox1.Checked)
            {
                access = (byte)(access | (byte)1);
            }
            if (checkBox2.Checked)
            {
                access = (byte)(access | (byte)2);
            }
            if (checkBox3.Checked)
            {
                access = (byte)(access | (byte)4);
            }
            if (checkBox4.Checked)
            {
                access = (byte)(access | (byte)8);
            }
            string res = insert_new_section(this.pe_info, textBox1.Text, contenter, textBox3.Text, int.Parse(textBox4.Text), access);
            switch(res)
            {
                case "2":
                    MessageBox.Show("字节码长度超过节大小，无法生成。");
                    break;
                case "3":
                    MessageBox.Show("节表空间不够。");
                    break;
                default:
                    MessageBox.Show("插入成功");
                    break;
            }

        }

        private string del_dos_stub(PE_informaton pe_info, String des_path)
        {//获取lfanew，记节表尾处位置为tail，将从lfanew处开始直到tail的数据粘贴到0x40。此时节表尾部位置变为tail-sizeof(dos_stub)=new_tail，
         //从new_tail开始到tail全写0
            data_process dp = new data_process();
            int lfanew = dp.str16_to_int(pe_info.lfanew);
            int size_of_dos_stub = lfanew - 0x40;
            int tail = pe_info.pe_location[40] + 0x28 * dp.str16_to_int(pe_info.number_of_sections);
            string a = String.Concat(des_path, "\\tmp");

            File.Copy(this.path, a, true);
            FileStream F = new FileStream(a, FileMode.Open, FileAccess.ReadWrite);
            byte[] tool = new byte[tail-lfanew];
            F.Position = lfanew;
            F.Read(tool, 0, tail - lfanew);
            F.Position = 0x40;
            F.Write(tool, 0, tail - lfanew);//数据粘贴
            int new_tail = tail - size_of_dos_stub;
            F.Position = new_tail;
            for(int i = new_tail; i<tail; i++)
            {
                F.WriteByte(0);
            }
            F.Position = pe_info.pe_location[1];//定位到lfanew
            byte[] new_lfanew = BitConverter.GetBytes(0x40);

            F.Write(new_lfanew, 0, new_lfanew.Length);
            F.Close();
            return a;
        }

        public string insert_new_section(PE_informaton pe_info, String sec_name, List<byte>contenter ,String des_path ,int size, byte access)//248
        {
            data_process dp = new data_process();
            PE_informaton new_file = new PE_informaton();
            string file2 = del_dos_stub(pe_info, des_path);

            if(contenter.Count > size)//如果输入的字节码太多，返回错误信息
            {
                return "2";
            }

            analyzer PE_AN = new analyzer(file2);//分析new_file用

            string[] PE_info = PE_AN.load();
            new_file.magic = PE_info[1];
            new_file.lfanew = PE_info[2];

            new_file.machine = PE_info[3];
            new_file.number_of_sections = PE_info[4];
            new_file.time_data_stamp = PE_info[5];
            new_file.pointer_to_symbol_table = PE_info[6];
            new_file.number_of_symbols = PE_info[7];
            new_file.size_of_optional_header = PE_info[8];
            new_file.characterastic = PE_info[9];

            new_file.optional_magic = PE_info[10];
            new_file.MajorLinkerVersion = PE_info[11];
            new_file.MinorLInkerVersion = PE_info[12];
            new_file.SizeofCode = PE_info[13];
            new_file.SizeOfInitializedData = PE_info[14];
            new_file.SizeOfUninitializedData = PE_info[15];
            new_file.AddressOfEntryPoint = PE_info[16];
            new_file.BaseOfCode = PE_info[17];
            new_file.BaseOfData = PE_info[18];
            new_file.ImageBase = PE_info[19];
            new_file.SectionAlignment = PE_info[20];
            new_file.FileAlignment = PE_info[21];
            new_file.MajorOperatingSystemVersion = PE_info[22];
            new_file.MinorOperatingSystemVersion = PE_info[23];
            new_file.MajorImageVersion = PE_info[24];
            new_file.MinorImageVersion = PE_info[25];
            new_file.MajorSubSystemVersion = PE_info[26];
            new_file.MinorSubSystemVersion = PE_info[27];
            new_file.Win32VersionValue = PE_info[28];
            new_file.SizeOfimage = PE_info[29];
            new_file.SizeOfHeaders = PE_info[30];
            new_file.CheckSum = PE_info[31];
            new_file.Subsystem = PE_info[32];
            new_file.DLLCharacteristics = PE_info[33];
            new_file.SizeOfStackReserve = PE_info[34];
            new_file.SizeOfStackCommit = PE_info[35];
            new_file.SizeOfHeapReserve = PE_info[36];
            new_file.SizeOfHeapCommit = PE_info[37];
            new_file.LoaderFlags = PE_info[38];
            this.pe_info.NumberOfRvaAndSizes = PE_info[39];
            new_file.pe_location = PE_AN.load_location(new_file.lfanew, new_file.size_of_optional_header);
            new_file.section = PE_AN.load_section();
            new_file.data_directory = PE_AN.load_data_directory(new_file.pe_location);

            //name：name
            //misc:size
            //sizeofrawdata:根据filealignment和size确定
            //size_of_image:老的+sizerawdata
            //pointerrawdata：老文件最后一个节的pointerrawdata+sizeofrawdata
            //virtualaddress：老文件的sizeofimage
            //characterastic:1/2/4/8 00000E0
            //number_of_section:+1
            //跳转文件末尾，写contenter，如果不够就sizeofrawdata补0。

            int size_of_headers = dp.str16_to_int(new_file.SizeOfHeaders);
            int tail_sec = new_file.pe_location[40] + 0x28 * dp.str16_to_int(new_file.number_of_sections);//节表要写的位置
            if (size_of_headers - tail_sec < 0x50)//不能为节表腾出足够多的空间，返回错误信息
                return "3";
            //①
            byte[] name = dp.str_to_byte(sec_name);
            

            //②
            byte[] misc = dp.int_to_byte(size);

            //③
            int file_alignment = dp.str16_to_int(new_file.FileAlignment);
            int size_of_raw_data = ((size / file_alignment) + 1) * file_alignment;
            byte[] byte_size_of_raw_data = dp.int_to_byte(size_of_raw_data);

            //④
            int size_of_image = dp.str16_to_int(new_file.SizeOfimage)+((size_of_raw_data/dp.str16_to_int(new_file.SectionAlignment))+1)*dp.str16_to_int(new_file.SectionAlignment);
            byte[] byte_size_of_image = dp.int_to_byte(size_of_image);

            //⑤
            int pointer_to_raw_data = dp.str16_to_int(new_file.section[dp.str16_to_int(pe_info.number_of_sections) * 10 - 10 + 5]) + dp.str16_to_int(new_file.section[dp.str16_to_int(pe_info.number_of_sections) * 10 - 10 + 4]);
            byte[] byte_pointer_to_raw_data = dp.int_to_byte(pointer_to_raw_data);

            //⑥
            int virtual_address = dp.str16_to_int(new_file.SizeOfimage);
            byte[] byte_virtual_address = dp.int_to_byte(virtual_address);

            //⑦
            byte[] byte_characterastic = new byte[4];
            byte_characterastic[0] = (byte)0xE0;
            byte_characterastic[1] = (byte)0x00;
            byte_characterastic[2] = (byte)0x00;
            byte_characterastic[3] = Convert.ToByte(Convert.ToInt32(access) << 4);

            //⑧
            int new_number_of_sections = dp.str16_to_int(new_file.number_of_sections)+1;
            byte[] byte_number_of_sections = dp.int_to_byte(new_number_of_sections);

            FileStream F = new FileStream(file2, FileMode.OpenOrCreate, FileAccess.ReadWrite);
            F.Position = tail_sec;
            F.Write(name, 0, name.Length);//写入节名字
            for(int i = 0; i<8-name.Length; i++)
            {
                F.WriteByte(0);
            }//补充0直到8bytes。

            F.Write(misc, 0, 4);//写入misc
            F.Write(byte_virtual_address, 0, 4);//写入virtual_address
            F.Write(byte_size_of_raw_data, 0, 4);//写入size_of_raw_data
            F.Write(byte_pointer_to_raw_data, 0, 4);//写入pointer_to_raw_data
            for(int i = 0; i<12; i++)
            {
                F.WriteByte(0);
            }//写入pointer_to_relocation,pointer_to_line_numbers,number_of_relocations,number_of_line_number。这些字段初始化为0
            F.Write(byte_characterastic, 0, 4);//写入characterastic

            F.Position = pointer_to_raw_data;
            F.Write(contenter.ToArray(), 0, contenter.Count);//将输入的数据写入节中
            for(int i=0; i<size_of_raw_data-contenter.Count; i++)//不足size_of_raw_data的要补0.
            {
                F.WriteByte(0);
            }

            F.Position = new_file.pe_location[3];
            F.Write(byte_number_of_sections, 0, 2);//将number_of_sections+1

            F.Position = new_file.pe_location[28];
            F.Write(byte_size_of_image, 0, 4);//将size_of_image修正

            F.Close();
            int k = 1;
            string new_file_path;
            while (true)
            {
                string order = Convert.ToString(k);
                new_file_path = String.Concat(des_path, "\\new_", order, "_", System.IO.Path.GetFileName(this.path));
                if (!File.Exists(new_file_path))
                {
                    break;
                }
                else
                {
                    k++;
                }
            }

            File.Move(file2, new_file_path);
            return new_file_path;
        }

        private void label4_Click(object sender, EventArgs e)
        {

        }
    }
}
