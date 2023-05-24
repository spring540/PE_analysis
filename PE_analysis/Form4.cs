using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Text.RegularExpressions;

namespace PE_analysis
{
    public partial class Form4 : Form
    {
        private string path;
        private PE_informaton pe_info;
        public Form4(string path, PE_informaton pe_info)
        {
            InitializeComponent();
            this.path = path;
            this.pe_info = pe_info;
            label1.Text = this.path;

        }

        //节空白区插入代码，在某个节后面插入代码，并使入口地址跳转到这里且执行
        private void button1_Click(object sender, EventArgs e)
        {
            Form5 insert_code = new Form5(this.path);
            insert_code.ShowDialog();
        }

        private void button2_Click(object sender, EventArgs e)//新增节
        {
            Form6 generate_sec = new Form6(this.path, this.pe_info);
            generate_sec.ShowDialog();
        }

        private void button3_Click(object sender, EventArgs e)//导出表
        {
            if(this.pe_info.data_directory[1] == 0)
            {
                MessageBox.Show("该文件没有导出表。");
                return;
            }
            Form7 export_info = new Form7(this.path, this.pe_info);
            export_info.ShowDialog();
        }

        private void button4_Click(object sender, EventArgs e)//返回
        {
            Form2 start_panel = new Form2(this.path);
            start_panel.ShowDialog();
            this.Hide();
        }

        private void Form4_Load(object sender, EventArgs e)
        {

        }

        private void button5_Click(object sender, EventArgs e)//重定位表
        {
            Form8 relocation_table = new Form8(this.path, this.pe_info);

        }

        private void button7_Click(object sender, EventArgs e)//选择输出文件夹
        {
            FolderBrowserDialog dialog = new FolderBrowserDialog();
            dialog.Description = "选择输出文件路径";
            if (dialog.ShowDialog() == DialogResult.OK)
            {
                string foldpath = dialog.SelectedPath;
                textBox1.Text = foldpath;
            }
        }

        private void button6_Click(object sender, EventArgs e)//移动导出表和重定位表到新节
        {
            if(String.IsNullOrEmpty(textBox1.Text) || !Directory.Exists(textBox1.Text))
            {
                MessageBox.Show("请重新选择合适的文件夹。");
            }
            int res = remove_export_relocation(textBox1.Text);
            string display;
            switch(res)
            {
                case 1:
                    display = "操作成功";
                    break;
                default:
                    display = "操作失败";
                    break;
            }
            MessageBox.Show(display);
        }

        //①、创建一个字节LIST和一个整数LIST，记录每个部分的偏移。目标是在其中填充导出表和重定位表
        //②、复制导出表内容
        //③、复制DLL文件的名称字符串
        //④、复制导出函数表地址表
        //⑤、复制导出函数表名字表，同时创建一个数组，记录每个名字的偏移位置
        //⑥、复制导出函数表名字指针，按照数组顺序复制位置即可
        //⑦、复制函数表序号表
        //⑧、复制重定位表
        //⑨、LIST中Name、AddressOfFunctions、AddressOfNames、AddressOfNameOrdinals需要修正。
        //⑩、修改datadirectroty的第1和第6的va内容。
        private int remove_export_relocation(string des_path)//实现移动导出表和重定位表到新节
        {
            //先新建一个文件，获得FOA
            Form6 tool_form = new Form6(this.path, this.pe_info);//用来调用Form6下的函数
            List<byte> blank = new List<byte>();
            string insert_section_file = tool_form.insert_new_section(pe_info, ".orzzz", blank, des_path, 2000, (byte)15);
            if (insert_section_file == "2" || insert_section_file == "3")
            {
                MessageBox.Show("新增节失败，重新debug！");
            }

            data_process dp = new data_process();
            analyzer PE_AN2 = new analyzer(insert_section_file);
            PE_informaton new_file_pe_info = PE_AN2.load_all_and_fill_in();

            
            
            FileStream FF = new FileStream(insert_section_file, FileMode.Open, FileAccess.ReadWrite);

            byte[] tool = new byte[4];
            FF.Position = new_file_pe_info.pe_location[39];
            FF.Read(tool, 0, 4);
            FF.Close();//加载导出表前必须关闭文件
            PE_AN2.load_export(new_file_pe_info, PE_AN2.RVA_to_FOA(dp.byte_to_int(tool, 1, 4), new_file_pe_info));


            FileStream F = new FileStream(insert_section_file, FileMode.Open, FileAccess.ReadWrite);
            //①
            //part_offset[0]:导出表内容。[1]:DLL文件名称字符串。[2]address_of_functions [3]functions_name 
            //[4]function_names_pointer [5]ordinals [6]重定位表
            List<byte> insert_data = new List<byte>();
            List<int> part_offset = new List<int>();

            //② 复制导出表内容
            part_offset.Add(insert_data.Count);
            F.Position = PE_AN2.RVA_to_FOA(new_file_pe_info.data_directory[0 * 2 + 1], new_file_pe_info);
            for(int i = 0; i<0x28; i++)
            {
                insert_data.Add(Convert.ToByte(F.ReadByte()));
            }

            //③复制DLL文件的名称字符串
            part_offset.Add(insert_data.Count);
            F.Position = PE_AN2.RVA_to_FOA(new_file_pe_info.export.Name, new_file_pe_info);
            while(true)
            {
                int i = F.ReadByte();
                insert_data.Add(Convert.ToByte(i));
                if (i == 0)
                {
                    break;
                }
            }

            //④、复制导出函数表地址表
            part_offset.Add(insert_data.Count);//记录偏移
            F.Position = PE_AN2.RVA_to_FOA(new_file_pe_info.export.AddressOfFunctions, new_file_pe_info);//定位到address_of_functions指向的位置。
            for (int i = 0; i < new_file_pe_info.export.NumberOfFunctions; i++)
            {
                F.Read(tool, 0, 4);
                insert_data.AddRange(tool);
            }

            //⑤复制导出函数表名字表，同时创建一个数组，记录每个名字的偏移位置
            part_offset.Add(insert_data.Count);
            int[] func_name_offset = new int[new_file_pe_info.export.NumberOfName];
            for(int i = 0; i< new_file_pe_info.export.NumberOfName; i++)
            {
                F.Position = PE_AN2.RVA_to_FOA(new_file_pe_info.export.AddressOfNames, new_file_pe_info)+i*4;
                F.Read(tool, 0, 4);
                F.Position = PE_AN2.RVA_to_FOA(dp.byte_to_int(tool, 1, 4), new_file_pe_info);//跳转到字符串存储的位置，下一步复制
                func_name_offset[i] = insert_data.Count();//记录每个函数名字符串的位置
                while(true)
                {
                    int k = F.ReadByte();
                    insert_data.Add(Convert.ToByte(k));
                    if (k == 0)
                    {
                        break;
                    }
                }
            }

            //⑥复制导出函数表名字指针，按照数组顺序复制位置即可
            //最后一节的virtualaddress+offset。
            part_offset.Add(insert_data.Count);
            int last_section_va = dp.str16_to_int(new_file_pe_info.section[(dp.str16_to_int(new_file_pe_info.number_of_sections) - 1) * 10 + 3]);
            int last_section_raw_data = dp.str16_to_int(new_file_pe_info.section[(dp.str16_to_int(new_file_pe_info.number_of_sections) - 1) * 10 + 4]);
            int last_section_end = last_section_va + last_section_raw_data;
            for (int i = 0; i<func_name_offset.Length; i++)
            {
                int address_name_int = last_section_va + func_name_offset[i];
                byte[] address_name_byte = dp.int_to_byte(address_name_int);
                insert_data.AddRange(address_name_byte);
            }

            //⑦复制函数表序号表
            part_offset.Add(insert_data.Count);
            F.Position = PE_AN2.RVA_to_FOA(new_file_pe_info.export.AddressOfNameOrdinals, new_file_pe_info);
            for(int i=0; i<func_name_offset.Length; i++)
            {
                insert_data.Add(Convert.ToByte(F.ReadByte()));
                insert_data.Add(Convert.ToByte(F.ReadByte()));//读两bytes是一个序号
            }

            //⑧复制重定位表
            part_offset.Add(insert_data.Count);
            F.Position = PE_AN2.RVA_to_FOA(new_file_pe_info.data_directory[6 * 2 - 1], new_file_pe_info);
            int relocation_va, relocation_sb;
            
            while(true)
            {
                F.Read(tool, 0, 4);
                insert_data.AddRange(tool);
                relocation_va = dp.byte_to_int(tool, 1, 4);//读取va

                F.Read(tool, 0, 4);
                insert_data.AddRange(tool);
                relocation_sb = dp.byte_to_int(tool, 1, 4);//读取sb
                if(relocation_va == 0 && relocation_sb == 0)
                {
                    break;
                }    
                for(int i=0; i<relocation_sb-8; i++)
                {
                    insert_data.Add(Convert.ToByte(F.ReadByte()));
                }
            }

            //⑨ Name:c address_of_functions:1c address_of_names:20 address_of_name_ordinals:24
            

            byte[] name = dp.int_to_byte(part_offset[1] + last_section_end);
            byte[] addr_func = dp.int_to_byte(part_offset[2] + last_section_end);
            byte[] addr_name = dp.int_to_byte(part_offset[4] + last_section_end);
            byte[] addr_ordinals = dp.int_to_byte(part_offset[5] + last_section_end);
            if(dp.replace_range(insert_data, name, 0xc) && dp.replace_range(insert_data, addr_func, 0x1c) && 
            dp.replace_range(insert_data, addr_name, 0x20) && dp.replace_range(insert_data, addr_ordinals, 0x24))
            {
                //如果都替换成功了，insert_data就是要写入节的数据。
                F.Position = last_section_va;
                byte[] insert_byte = insert_data.ToArray();
                F.Write(insert_byte, 0, insert_byte.Length);
            }
            else
            { 
                return -1;
            }
            

            byte[] export_va = dp.int_to_byte(last_section_va);
            byte[] reloca_va = dp.int_to_byte(part_offset[6] + last_section_va);

            F.Position = new_file_pe_info.pe_location[39] + 8*(1-1);
            F.Write(export_va, 0, 4);
            F.Position = new_file_pe_info.pe_location[39] + 8*(6-1);
            F.Write(reloca_va, 0, 4);
            F.Close();
            return 1;
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void button8_Click(object sender, EventArgs e)//练习2（重定位还原练习）
        {
            if(!Directory.Exists(textBox2.Text))
            {
                MessageBox.Show("请重新选择合适的输出文件夹。");
                return;
            }
            if(!Regex.IsMatch(textBox3.Text, @"^[0-9|a-f|A-F]{8}$"))
            {
                MessageBox.Show("请输入正确的ImageBase。");
                return;
            }
            int res = relocation_test(textBox3.Text, textBox2.Text);
            if(res == 1)
            {
                MessageBox.Show("完成。");
                return; 
            }

        }

        //1、在目标文件夹下复制一个同样的文件
        //2、读取那个文件，并改写ImageBase为目标值
        //3、找到重定位表，依次读取，修改。
        public int relocation_test(string new_base, string des_path)
        {
            data_process dp = new data_process();
            string new_file;
            int k = 1;
            while(true)
            {
                new_file = String.Concat(des_path, "//RelocationTest", Convert.ToString(k), Path.GetFileName(this.path));
                if(File.Exists(new_file))
                {
                    k++;
                }
                else
                {
                    break;
                }
            }

            File.Copy(this.path, new_file);
            analyzer PE_AN = new analyzer(new_file);

            PE_informaton new_info = PE_AN.load_all_and_fill_in();
            FileStream F = new FileStream(new_file, FileMode.Open, FileAccess.ReadWrite);

            //找到imagebase的位置，重写为新imagebase
            F.Position = new_info.pe_location[18];//ImageBase
            byte[] tool = new byte[4];
            tool = dp.int_to_byte(dp.str16_to_int(new_base));
            F.Write(tool, 0, 4);

            //找到重定位表的位置,重定位表位于datadirectory的第6个结构体。
            F.Position = new_info.pe_location[39] + 8 * (6 - 1);
            F.Read(tool, 0, 4);
            int reloca_FOA = PE_AN.RVA_to_FOA(dp.byte_to_int(tool, 1, 4), new_info);

            //逐个读重定位表项，跳转到指定位置，然后读取值使其+new_base - new_info.imagebase

            int relocation_va, relocation_size, relocation_base, relocation_offset;
            //va:重定位表一个块的va，size是大小，base是文件中va基址，offset是每个要改的数据离va的偏移
            int relocation_des;//是要改的文件中数据位置

            F.Position = reloca_FOA;
            long back_position = F.Position;
            while (true)
            {
                F.Position = back_position;
                F.Read(tool, 0, 4);
                relocation_va = dp.byte_to_int(tool, 1, 4);
                F.Read(tool, 0, 4);
                relocation_size = dp.byte_to_int(tool, 1, 4);

                if(relocation_va == 0 && relocation_size == 0)
                {
                    F.Close();
                    return 1;
                }
                else
                {
                    relocation_base = PE_AN.RVA_to_FOA(relocation_va, new_info);
                }
                back_position = F.Position;
                for(int i=0; i<(relocation_size-8)/2; i++)
                {
                    F.Position = back_position;
                    F.Read(tool, 0, 2);
                    if((tool[1]&(byte)48) == 48)//00110101 & 00110000
                    {
                        tool[1] = (byte)(tool[1] & (byte)15);
                        relocation_offset = dp.byte_to_int(tool, 1, 2);
                        relocation_des = relocation_offset + relocation_base;

                        back_position = F.Position;//后面要跳转到文件其它地方去修改地址，使用back_postion来记录要返回的地方
                        F.Position = relocation_des;
                        F.Read(tool, 0, 4);
                        tool = dp.int_to_byte(dp.byte_to_int(tool, 1, 4) + (dp.str16_to_int(new_base) - dp.str16_to_int(new_info.ImageBase)));
                        F.Position -= 4;
                        F.Write(tool, 0, 4);
                    }
                    else
                    {
                        back_position += 2;
                    }
                }

            }
        }

        private void button9_Click(object sender, EventArgs e)//选择输出文件夹（练习2）
        {
            FolderBrowserDialog dialog = new FolderBrowserDialog();
            dialog.Description = "选择输出文件路径";
            if(dialog.ShowDialog() == DialogResult.OK)
            {
                string foldpath = dialog.SelectedPath;
                textBox2.Text = foldpath;
            }    
        }

        private void button10_Click(object sender, EventArgs e)
        {
            if (this.pe_info.data_directory[3] == 0)
            {
                MessageBox.Show("该文件没有导入表。");
                return;
            }
            Form9 import_info = new Form9(this.path, this.pe_info);
            import_info.ShowDialog();
        }

        private void button11_Click(object sender, EventArgs e)
        {
            Form10 import_table_inject = new Form10(this.path, pe_info);
            import_table_inject.ShowDialog();

        }
    }

}
