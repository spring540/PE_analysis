using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace PE_analysis
{
    public partial class Form2 : Form
    {
        public string path;
        public Form3 section_info;
        public PE_informaton pe_info;
        public Form2(string file_path)
        {
            InitializeComponent();
            this.path = file_path;
            preload(this.path);
            label1.Text = file_path;
        }

        private void preload(string path)
        {
            this.pe_info = new PE_informaton();
            analyzer PE_AN = new analyzer(this.path);
            if (PE_AN.check_vaild())
            {
                string[] PE_info = PE_AN.load();
                if(PE_info[0] != "Format Failing")
                {
                    this.pe_info.magic = PE_info[1];
                    this.pe_info.lfanew = PE_info[2];

                    this.pe_info.machine = PE_info[3];
                    this.pe_info.number_of_sections = PE_info[4];
                    this.pe_info.time_data_stamp = PE_info[5];
                    this.pe_info.pointer_to_symbol_table = PE_info[6];
                    this.pe_info.number_of_symbols = PE_info[7];
                    this.pe_info.size_of_optional_header = PE_info[8];
                    this.pe_info.characterastic = PE_info[9];

                    this.pe_info.optional_magic = PE_info[10];
                    this.pe_info.MajorLinkerVersion = PE_info[11];
                    this.pe_info.MinorLInkerVersion = PE_info[12];
                    this.pe_info.SizeofCode = PE_info[13];
                    this.pe_info.SizeOfInitializedData = PE_info[14];
                    this.pe_info.SizeOfUninitializedData = PE_info[15];
                    this.pe_info.AddressOfEntryPoint = PE_info[16];
                    this.pe_info.BaseOfCode = PE_info[17];
                    this.pe_info.BaseOfData = PE_info[18];
                    this.pe_info.ImageBase = PE_info[19];
                    this.pe_info.SectionAlignment = PE_info[20];
                    this.pe_info.FileAlignment = PE_info[21];
                    this.pe_info.MajorOperatingSystemVersion = PE_info[22];
                    this.pe_info.MinorOperatingSystemVersion = PE_info[23];
                    this.pe_info.MajorImageVersion = PE_info[24];
                    this.pe_info.MinorImageVersion = PE_info[25];
                    this.pe_info.MajorSubSystemVersion = PE_info[26];
                    this.pe_info.MinorSubSystemVersion = PE_info[27];
                    this.pe_info.Win32VersionValue = PE_info[28];
                    this.pe_info.SizeOfimage = PE_info[29];
                    this.pe_info.SizeOfHeaders = PE_info[30];
                    this.pe_info.CheckSum = PE_info[31];
                    this.pe_info.Subsystem = PE_info[32];
                    this.pe_info.DLLCharacteristics = PE_info[33];
                    this.pe_info.SizeOfStackReserve = PE_info[34];
                    this.pe_info.SizeOfStackCommit = PE_info[35];
                    this.pe_info.SizeOfHeapReserve = PE_info[36];
                    this.pe_info.SizeOfHeapCommit = PE_info[37];
                    this.pe_info.LoaderFlags = PE_info[38];
                    this.pe_info.NumberOfRvaAndSizes = PE_info[39];
                }
                this.pe_info.section = PE_AN.load_section();
                this.pe_info.pe_location = PE_AN.load_location(this.pe_info.lfanew, this.pe_info.size_of_optional_header);
                this.pe_info.data_directory = PE_AN.load_data_directory(this.pe_info.pe_location);
            }
        }


        private void button1_Click(object sender, EventArgs e)//开始解析
        {
            analyzer PE_AN = new analyzer(this.path);
            if(PE_AN.check_vaild())
            {
                string[] PE_info   = PE_AN.load();
                if(PE_info[0] == "Format Failing")
                {
                    MessageBox.Show("加载失败，这可能是由于文件格式不对造成的");
                    return;
                }
                else if(PE_info[0] == "Success")
                {
                    //DOS头
                    textBox1.Text = PE_info[1];//magic
                    textBox2.Text = PE_info[2];//lfanew

                    //标准PE头
                    textBox3.Text = PE_info[3];//machine
                    textBox4.Text = PE_info[4];//number_of_sections
                    textBox5.Text = PE_info[5];//time_data_stamp
                    textBox6.Text = PE_info[6];//pointer_to_symbol_table
                    textBox7.Text = PE_info[7];//number_of_symbols
                    textBox8.Text = PE_info[8];//size_of_optional_header
                    textBox9.Text = PE_info[9];//characterastic

                    //可选PE头
                    textBox10.Text = PE_info[10];//optional magic
                    textBox11.Text = PE_info[13];//size_of_code
                    textBox12.Text = PE_info[14];//size_initialized_data
                    textBox13.Text = PE_info[15];//uninitialized
                    textBox14.Text = PE_info[16];//address_of_entry_point
                    textBox15.Text = PE_info[17];//base_of_code
                    textBox16.Text = PE_info[18];//base_of_data
                    textBox17.Text = PE_info[19];//imageBase
                    textBox18.Text = PE_info[20];//sectionAlignment
                    textBox19.Text = PE_info[21];//fileAlignment
                    textBox20.Text = PE_info[29];//size_of_image
                    textBox21.Text = PE_info[30];//size_of_headers
                    textBox22.Text = PE_info[31];//check_sum
                    textBox23.Text = PE_info[39];//number_of_rva_and_size
                    textBox24.Text = PE_info[34];//reverse_stack
                    textBox25.Text = PE_info[35];//commit_stack
                    textBox26.Text = PE_info[36];//reverse_heap
                    textBox27.Text = PE_info[37];//commit_heap
                }
                
            }
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void label4_Click(object sender, EventArgs e)
        {

        }

        private void label5_Click(object sender, EventArgs e)
        {

        }

        private void label13_Click(object sender, EventArgs e)
        {

        }

        private void button2_Click(object sender, EventArgs e)//选择文件夹
        {
            var openFileDialog = new Microsoft.Win32.OpenFileDialog()
            {
                Filter = "PE Files|*.dll;*.exe;*.lib"
            };
            var result = openFileDialog.ShowDialog();
            if (result == true)
            {
                Form2 new_form2;
                new_form2 = new Form2(openFileDialog.FileName);
                this.Hide();
                new_form2.ShowDialog();
                Application.ExitThread();
            }
        }

        private void button3_Click(object sender, EventArgs e)//查看节信息
        {
            section_info = new Form3(this.path);
            //this.Hide();
            //this.ShowDialog();
            //this.Hide();
            //this.Close();
            section_info.ShowDialog();
            Application.ExitThread();
        }

        private void button4_Click(object sender, EventArgs e)
        {
            Form4 Advance_Func = new Form4(this.path, this.pe_info);
            this.Hide();
            Advance_Func.ShowDialog();
            Application.ExitThread();
        }

        private void Form2_Load(object sender, EventArgs e)
        {

        }
    }
}
