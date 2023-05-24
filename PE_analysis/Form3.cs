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
    public partial class Form3 : Form
    {
        private string file_path;
        private int[] VirtualAddress_SizeOfRawData;
        private int size_of_image;
        private int size_of_headers;
        public Form3(string path)
        {
            InitializeComponent();
            this.file_path = path;
            this.VirtualAddress_SizeOfRawData = new int[100];
            if(fill_data() != 1)
            {
                MessageBox.Show("失败");
            }
        }

        private int fill_data()//填充节数据
        {
            FileStream F = new FileStream(this.file_path, FileMode.Open, FileAccess.Read);
            byte[] tool = new byte[9];
            data_process tool_bar = new data_process();//创建一个处理数据工具类
            string show_data = "";
            string spilt = "------------------------------------------------\r\n";

            F.Position = 60;//寻找标准PE头位置
            F.Read(tool, 0, 4);//读取标准PE头偏移
            int standard_offset = tool_bar.byte_to_int(tool, 1, 4);

            F.Position = standard_offset;//读取到标准PE开头

            F.Position += 4;//读取到PE标识的四个字节

            F.Position += 2;//跳转到number_of_sections字段
            F.Read(tool, 0, 2);//
            int number_of_sections = tool_bar.byte_to_int(tool, 1, 2);

            this.VirtualAddress_SizeOfRawData[0] = number_of_sections;//记录节数目，用来给Button2传参

            F.Position += 12;//跳转到Size_of_Optional_Header字段
            F.Read(tool, 0, 2);
            int size_of_optional_header = tool_bar.byte_to_int(tool, 1, 2);

            //读取size_of_image
            F.Position += 2 + 56;
            F.Read(tool, 0, 4);
            this.size_of_image = tool_bar.byte_to_int(tool, 1, 4);

            //读取size_of_headers
            F.Read(tool, 0, 4);
            this.size_of_headers = tool_bar.byte_to_int(tool, 1, 4);
            
            F.Position += size_of_optional_header - 56 - 4 - 4 ;
            //F.Position += 2 + size_of_optional_header;//跳转到节表开头，下面开始解析节表
            show_data = String.Concat(show_data, "节数量: ", number_of_sections.ToString(), "\r\n------------------------------------------------\r\n");
            for(int i=0; i<number_of_sections; i++)
            {
                F.Read(tool, 0, 8);//读取name字段
                string section_name = tool_bar.byte_to_ascii(tool, 1, 8);
                show_data = String.Concat(show_data, "Section Name: ", section_name, "\r\n\r\n");

                F.Read(tool, 0, 4);//读取MISC字段，没有对齐前的真实尺寸
                string misc = tool_bar.byte_to_str(tool, 1, 4);
                show_data = String.Concat(show_data, "MISC(Virtual Size): ", misc, "\r\n");
                show_data = String.Concat(show_data, "该节在没有对齐前的真实尺寸，就是真实数据的长度（不算文件对齐而填充的0）,可以不准确，不影响程序运行\r\n\r\n");

                F.Read(tool, 0, 4);//读取virtual_address
                string virtual_address = tool_bar.byte_to_str(tool, 1, 4);
                show_data = String.Concat(show_data, "Virtual Address: ", virtual_address, "\r\n");
                show_data = String.Concat(show_data, "节区在内存中的偏移地址，需要加上ImageBase才是真正地址。离ImageBase有多远\r\n\r\n");
                this.VirtualAddress_SizeOfRawData[i * 2 + 1] = tool_bar.byte_to_int(tool, 1, 4);

                F.Read(tool, 0, 4);
                string size_of_raw_data = tool_bar.byte_to_str(tool, 1, 4);
                show_data = String.Concat(show_data, "Size Of Raw Data: ", size_of_raw_data, "\r\n");
                show_data = String.Concat(show_data, "节在文件中对齐后的尺寸，与Misc字段对应，这个字段区别就是带上文件对齐而填充的0所占用的长度\r\n\r\n");
                this.VirtualAddress_SizeOfRawData[2 * i + 2] = tool_bar.byte_to_int(tool, 1, 4);

                F.Read(tool, 0, 4);
                string pointer_to_raw_data = tool_bar.byte_to_str(tool, 1, 4);//
                show_data = String.Concat(show_data, "Pointer To Raw Data: ", pointer_to_raw_data, "\r\n");
                show_data = String.Concat(show_data, "节区在文件中的偏移，注意和VirtualAddress区分，这个字段是指文件中，VirtualAddress是在内存中。VirtualAddress一般会大于PointerToRawData，当内存对齐和文件对齐一样时，这两个值相同。PointerToRawData总是文件对齐的整数倍。\r\n\r\n");

                F.Read(tool, 0, 4);
                string pointer_to_relocations = tool_bar.byte_to_str(tool, 1, 4);
                show_data = String.Concat(show_data, "Pointer To Relocations: ", pointer_to_relocations, "\r\n\r\n");

                F.Read(tool, 0, 4);
                string pointer_to_line_numbers = tool_bar.byte_to_str(tool, 1, 4);
                show_data = String.Concat(show_data, "Pointer To Line Numbers: ", pointer_to_line_numbers, "\r\n\r\n");

                F.Read(tool, 0, 2);
                string number_of_relocations = tool_bar.byte_to_str(tool, 1, 2);
                show_data = String.Concat(show_data, "Number Of Relocations: ", number_of_relocations, "\r\n\r\n");

                F.Read(tool, 0, 2);
                string number_of_line_numbers = tool_bar.byte_to_str(tool, 1, 2);
                show_data = String.Concat(show_data, "Number Of Line Numbers: ", number_of_line_numbers, "\r\n\r\n");

                F.Read(tool, 0, 4);
                string characterastic = tool_bar.byte_to_str(tool, 1, 4);
                show_data = String.Concat(show_data, "Characterastic: ", characterastic, "\r\n");
                show_data = String.Concat(show_data, "节的属性，其中00000020：包含可执行代码，00000040包含已初始化数据，00000080包含未初始化数据。10000000：共享块，20000000：可执行，40000000：可读，80000000：可写。\r\n\r\n");

                show_data = String.Concat(show_data, spilt);
            }
            textBox1.Text = show_data;
            return 1;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            Form2 back_panel = new Form2(this.file_path);
            back_panel.ShowDialog();
            this.Hide();
            Application.ExitThread();
        }

        private void button2_Click(object sender, EventArgs e)
        {
            analyzer PE_AN = new analyzer(this.file_path);
            if (PE_AN.generate_image_buffer(this.size_of_image, this.size_of_headers, this.VirtualAddress_SizeOfRawData) == true)
            {
                MessageBox.Show("生成完成，路径是G:/code/PE_test/test.exe");
            }
        }

        private void Form3_Load(object sender, EventArgs e)
        {

        }
    }
}
