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

namespace PE_analysis
{
    public partial class Form10 : Form
    {

        string path;
        PE_informaton pe_info;
        public Form10(string path, PE_informaton pe_info)
        {
            InitializeComponent();
            this.path = path;
            this.pe_info = pe_info;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog()
            {
                Filter = "PE Files|*.dll"
            };
            var result = dialog.ShowDialog();
            if(result == true)
            {
                var file_name = dialog.FileName;
                textBox1.Text = file_name;
            }
            return;

        }

        //导入表注入函数
        //步骤：1、在目标路径新建一个新增节后的文件 
        //2、移动各个DLL的导入表描述符，在后面加上该DLL描述符
        //3、增加一个对应的INT表和IAT表，IAT表不提前加载地址
        //4、加一个存名字的表
        private int import_table_inject(string resource_path, PE_informaton pe_info, string dll_path)
        {
            string new_file_path = Path.GetDirectoryName(resource_path);

            Form6 Form_tool = new Form6(this.path, pe_info);
            List<byte> contenter = new List<byte>();
            string res = Form_tool.insert_new_section(pe_info, ".orzzzzz", contenter, new_file_path, 3000, (byte)15);
            //string res = "G:\\code\\PE_test\\new_1_winmine.exe";
            Form_tool.Close();//使用完函数即销毁对象
            switch(res)
            {
                case "2":
                    MessageBox.Show("字节码过长");
                    return 0;
                case "3":
                    MessageBox.Show("不能为新节腾出足够空间");
                    return 0;
            }
            int ret = fill_data_to_section(res, dll_path);
            switch (ret)
            {
                case 1:
                    MessageBox.Show("注入成功。");
                    return 1;
                case 0:
                    MessageBox.Show("注入失败。");
                    return 0;
            }
            MessageBox.Show("未知错误。");
            return 0;
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if(String.IsNullOrEmpty(textBox1.Text)||(!File.Exists(textBox1.Text)))
            {
                MessageBox.Show("请正确输入要注入的DLL文件路径。");
            }
            else
            {
                var res = import_table_inject(this.path, pe_info, textBox1.Text);
            }
        }

        public int fill_data_to_section(string file_path, string dll_path)//向目标文件的最后一个节加数据，并且修改头中相应地址，使其注入成功
        {
            data_process dp = new data_process();
            PE_informaton pe_info = new PE_informaton();

            analyzer PE_AN = new analyzer(file_path);
            pe_info = PE_AN.load_all_and_fill_in();
            int a = PE_AN.RVA_to_FOA(pe_info.data_directory[3], pe_info);
            PE_AN.load_import(pe_info, PE_AN.RVA_to_FOA(pe_info.data_directory[3], pe_info));

            List<byte> insert_data = new List<byte>();
            //List<byte> tmp_data = new List<byte>();

            List<int> InsertDataLocation = new List<int>();

            //
            int start_position = dp.str16_to_int(pe_info.section[dp.str16_to_int(pe_info.number_of_sections)*10-10 + 3]);
            InsertDataLocation.Add(insert_data.Count);//0
            for (int i=0; i<pe_info.imports.Length; i++)
            {
                insert_data.AddRange(dp.int_to_byte(pe_info.imports[i].OriginalFirstThunk));//
                insert_data.AddRange(dp.int_to_byte(pe_info.imports[i].TimeDateStamp));
                insert_data.AddRange(dp.int_to_byte(pe_info.imports[i].ForwarderChain));
                insert_data.AddRange(dp.int_to_byte(pe_info.imports[i].Name));
                insert_data.AddRange(dp.int_to_byte(pe_info.imports[i].FirstThunk));
            }

            InsertDataLocation.Add(insert_data.Count);//1
            insert_data.AddRange(dp.int_to_byte(0));//OriginalFirstThunk,后面确定了INT表的位置，这里要改动0 160
            insert_data.AddRange(dp.int_to_byte(0));//TimeDateStamp,0表示不提前加载IAT4 164
            insert_data.AddRange(dp.int_to_byte(-1));//ForwarderChain,-1表示没有Forwarder8 168
            insert_data.AddRange(dp.int_to_byte(0));//Name，后面确定了Name的位置，这里要改动12 172
            insert_data.AddRange(dp.int_to_byte(0));//FirstThunk,后面需要改动16 176

            for(int i=0;i<5;i++)
            {
                insert_data.AddRange(dp.int_to_byte(0));//添加导入表截断符
            }

            InsertDataLocation.Add(insert_data.Count);//2
            byte[] dll_name = dp.str_to_byte(Path.GetFileName(dll_path));
            insert_data.AddRange(dll_name);
            insert_data.Add((byte)0);//添加字符串截断符
            //修改描述符中的Name字段
            if(!dp.replace_range(insert_data, dp.int_to_byte(start_position+InsertDataLocation[2]),InsertDataLocation[1]+12))
            {
                return 0;
            }

            //按照函数名导入一个函数，后续可以根据需要导入多个函数

            //INT
            InsertDataLocation.Add(insert_data.Count);//3
            for(int i=0; i<1+1; i++)//1+1:前一个1是函数个数，后一个1是结束符
            {
                insert_data.AddRange(dp.int_to_byte(0));
            }
            //替换OriginFirstThunk
            if (!dp.replace_range(insert_data, dp.int_to_byte(start_position+InsertDataLocation[3]), InsertDataLocation[1]+0))
            {
                return 0;
            }

            //IAT
                InsertDataLocation.Add(insert_data.Count);//4
            for(int i=0; i<1+1; i++)
            {
                insert_data.AddRange(dp.int_to_byte(0));
            }
            //替换FirstThunk
            if(!dp.replace_range(insert_data, dp.int_to_byte(start_position + InsertDataLocation[4]), InsertDataLocation[1]+16))
            {
                return 0;
            }

            //函数名称表
            string func_name = "expert_function";
            InsertDataLocation.Add(insert_data.Count);//5
            insert_data.Add((byte)0);
            insert_data.Add((byte)0);//Hint
            insert_data.AddRange(dp.str_to_byte(func_name));//name
            insert_data.Add((byte)0);//截断符
            //替换INT表中的表项
            if(!dp.replace_range(insert_data, dp.int_to_byte(start_position+InsertDataLocation[5]), InsertDataLocation[3]))
            {
                return 0;
            }
            //替换IAT表中的表项
            if (!dp.replace_range(insert_data, dp.int_to_byte(start_position + InsertDataLocation[5]), InsertDataLocation[4]))
            {
                return 0;
            }

            //修改data_directory导入表地址
            int import_location = pe_info.pe_location[39] + 8;
            FileStream F = new FileStream(file_path, FileMode.Open, FileAccess.ReadWrite);
            F.Position = import_location;
            F.Write(dp.int_to_byte(start_position), 0, 4);

            int IAT_location = pe_info.pe_location[39] + 8 * 13;
            F.Position = IAT_location;
            F.Write(dp.int_to_byte(start_position + InsertDataLocation[4]), 0, 4);

            F.Position = dp.str16_to_int(pe_info.section[dp.str16_to_int(pe_info.number_of_sections) * 10 - 10 + 5]);
            F.Write(insert_data.ToArray(), 0, insert_data.Count);
            F.Close();

            return 1;
        }
    }
}
