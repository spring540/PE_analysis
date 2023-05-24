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
    public partial class Form5 : Form
    {
        private string path;
        private string[] headers;
        private string[] sections;
        public Form5(string path)
        {
            InitializeComponent();
            this.path = path;
            label1.Text = path;
            Data_preload();
            SetDefaultText();
            textBox1.GotFocus += new EventHandler(text_Enter);
            textBox1.LostFocus += new EventHandler(text_Leave);

        }

        private void SetDefaultText()
        {
            textBox1.Text = "请输入字节数据，使用空格作为不同字节的分割符，允许使用回车分割为不同的行，举例如下：\r\n------------\r\n12 34 56 78   合法\r\n------------\r\n12345678       不合法\r\n------------\r\n12 34\r\n56 78         合法";
            textBox1.ForeColor = Color.Gray;
        }

        private void text_Enter(object sender, EventArgs e)
        {
            if(!String.IsNullOrEmpty(textBox1.Text))
            {
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

        private void Data_preload()
        {
            analyzer PE_AN = new analyzer(path);
            data_process dp = new data_process();

            this.headers = PE_AN.load();
            this.sections = PE_AN.load_section();
            int num_sec = dp.str16_to_int(headers[4]);

            for(int i=0; i<num_sec; i++)
            {
                comboBox1.Items.Add(sections[i * 10 + 1]);
                comboBox1.SelectedIndex = 0;
            }
            

        }
            

        private void label3_Click(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)//点击生成
        {
            string machine_code = textBox1.Text;
            int sec_index = comboBox1.SelectedIndex;//选择选中的节
            string des_path = textBox2.Text;//选择路径

            //输入的机器码格式：xx xx xx xx [aa aa aa aa]
            string a = textBox1.Text;
            int[] address_index = new int[100];//指明机器码中地址的index,[0]处存储有几个地址，[单数]存储开始位置，[双数]存储结束位置
            byte[] insert_to_byte = new byte[300];//[0]存储状态码，byte(1)机器码输入格式正确，byte(0)机器码输入格式错误
            int length = insert_process(textBox1.Text, address_index, insert_to_byte);
            if(insert_to_byte[0] == (byte)0)
            {
                MessageBox.Show("输入的机器码格式有误，请重新输入。");
            }
            else if(!(File.Exists(path)))
            {
                MessageBox.Show("文件路径不存在，请重新选择。");
            }
            generate_new_file(sec_index, insert_to_byte, address_index, des_path, length);


        }


        //在指定路径生成一个在指定节后插入指定机器码的新文件，并将文件OEP修改到机器码处。同时，要修改用户编辑的函数地址，使其能在内存中运行。
        //流程：读取那个文件，读第n个节的节表，令size_of_raw_data-misc得空闲空间h，如果insert_to_byte.Length较大，则不能插入，返回-1。
        //      否则，令Pointer_To_raw_data + h 得到这个机器码序列写入的开头m。另外读characterastic，根据最高位得知其权限信息。
        //      然后需要做地址转换，获取用户输入的地址信息（默认为32位），根据address_index和m获取每个地址的起始位置，-1得该指令的起始位置。
        //      对于每一个地址，都有指令起始位置（文件中）y1,y2,y3,...。x计算：用户已给出跳转地址u1,u2,u3，当前位置（文件中）y1,y2,y3...，
        //      计算当前位置（内存对齐之后）：令写入节的Virtual_address + misc 得到写入的机器码在内存中的实际位置，加上address_index -1得到各个指令地址
        //      在内存中的实际位置z1,z2,z3...，最后x1 = u1 - z1 - 5(这里默认地址前仅有1字节操作码）,x2 = u2 - z2 - 5...，写入到x1写入到m + address_index[1]。..
        //      最后，将OEP改为virtual_address + misc。
        //功能限制：默认必须为32位程序，64位后续再写，另外默认地址前仅有1字节操作码。这些也可以改善。
        //成功：返回1
        //失败1（节后空闲空间不足以插入这些代码）：返回-1
        //警告1（节不具有执行权限）：返回2
        //用到的变量：path，headers，sections
        private int generate_new_file(int sec_index, byte[] insert_to_byte, int[] address_index, string des_path, int length)//插入节的索引，插入的机器码，机器码中的地址信息，目标
        {
            //FileStream F = new FileStream(this.path, FileMode.Open, FileAccess.Read);//打开文件
            File.Copy(this.path, String.Concat(des_path, "\\test1.exe"), true);
            data_process dp = new data_process();

            int free_place = dp.str16_to_int(this.sections[sec_index * 10 + 4]) - dp.str16_to_int(this.sections[sec_index * 10 + 2]);//获取空闲代码空间，h
            if(free_place < length)
            {
                return -1;
            }
            int write_start = dp.str16_to_int(this.sections[sec_index * 10 + 5]) + dp.str16_to_int(this.sections[sec_index * 10 + 2]);//在文件中开始写的地方，m
            FileStream new_F = new FileStream(String.Concat(des_path, "\\test1.exe"), FileMode.OpenOrCreate, FileAccess.ReadWrite);
            new_F.Position = write_start;
            new_F.Write(insert_to_byte, 1, length);
            

            int image_base = dp.str16_to_int(this.headers[19]);
            string characterastic = this.sections[sec_index * 10 + 10];//其中包含权限信息
            int[] z = new int[address_index[0] + 1];//内存中实际位置
            int[] u = new int[address_index[0] + 1];//用户给出的跳转地址
            byte[] x;//实际要写入的地址偏移
            byte[] oep = BitConverter.GetBytes(dp.str16_to_int(this.sections[sec_index * 10 + 3]) + dp.str16_to_int(this.sections[sec_index * 10 + 2]));
            for (int i = 1; i <= address_index[0]; i++)
            {
                z[i] = dp.str16_to_int(this.sections[sec_index * 10 + 3]) + dp.str16_to_int(this.sections[sec_index * 10 + 2]) + address_index[2*i -1] - 2;
                u[i] = BitConverter.ToInt32(insert_to_byte, address_index[i * 2 - 1]);
                x = BitConverter.GetBytes(u[i] - z[i] - 5 - image_base);
                new_F.Position = write_start + address_index[2 * i - 1] - 1;
                new_F.Write(x, 0, 4);
            }

            new_F.Position = 0x3c;
            byte[] tool = new byte[4];
            new_F.Read(tool, 0, 4);
            int standard_pe = dp.byte_to_int(tool, 1, 4);

            //oep的位置
            new_F.Position = standard_pe + 0x14 + 0x4 + 0x10;
            //new_F.Read(tool, 0, 4);
            new_F.Write(oep, 0, 4);
            new_F.Close();
            return 1;
        }

        //处理输入的机器码，将其转为byte格式，同时要识别不同行和需要改变的地址,如果成功，返回输入机器码的字节数，失败返回0
        private int insert_process(string insert_str, int[] address_index, byte[] result)
        {
            string[] str1 = Regex.Split(insert_str, "\r\n", RegexOptions.IgnoreCase);//将行分割开
            string[] str2 = new string[300];//输入的机器码按照行分割，然后按照空格分割后将每一个字节作为一个元素
            string[] str3;//用于暂时存储处理str1的某行分割后子字符串组
            int cursor = 1;
            int address_cursor = 1;

            for(int i = 0;i<str1.Length; i++)
            {
                str3 = Regex.Split(str1[i], " ", RegexOptions.IgnoreCase);//从第一行开始，分割“ ”
                for(int k = 0; k<str3.Length; k++)
                {
                    if((str3[k].Length == 2 && Regex.Match(str3[k], @"[0-9|a-f]{2}").Length > 0) || (str3[k].Length == 3 && Regex.Match(str3[k], @"\[*[0-9|a-f]{2}\]*").Length >= 0))//检验每一项输入是否合规则
                    { 
                        if(Regex.Match(str3[k], @"[\[|\]]").Length == 1)//在字符串中检索到[]
                        {
                        address_index[address_cursor] = cursor;
                        address_cursor++;
                        str2[cursor] = Regex.Match(str3[k], @"[0-9|a-f]{2}").Value;
                        }
                        else
                        {
                        str2[cursor] = str3[k];//
                        }
                        cursor++;
                    }
                    else//不合规则就将状态码置0，返回
                    {
                        result[0] = (byte)0;
                        return 0;
                    }
                }
            }
            for(int i = 1; i<= cursor-1; i++)
            {
                result[i] = Convert.ToByte(str2[i], 16);
            }
            address_index[0] = (address_cursor - 1) / 2;
            result[0] = (byte)1;//转换成功
            return cursor - 1;
        }

        private void button3_Click(object sender, EventArgs e)//选择输出目标文件夹
        {
            FolderBrowserDialog dialog = new FolderBrowserDialog();
            dialog.Description = "选择输出文件路径";
            if(dialog.ShowDialog() == DialogResult.OK)
            {
                string foldpath = dialog.SelectedPath;
                textBox2.Text = foldpath;
            }
        }

        private void Form5_Load(object sender, EventArgs e)
        {

        }

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void button2_Click(object sender, EventArgs e)
        {
            this.Hide();
        }
    }
}
