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
    public partial class Form7 : Form
    {
        string path;
        PE_informaton PE_INFO;
        public Form7(string path, PE_informaton PE_INFO)
        {
            InitializeComponent();
            this.path = path;
            this.PE_INFO = PE_INFO;

            string[] res = GetFunctionInfo(PE_INFO);
            FillDataToGrid(res);

        }

        //获取导出表中的函数信息序号、函数名、函数入口地址
        private string[] GetFunctionInfo(PE_informaton pe_info)
        {
            analyzer PE_AN = new analyzer(this.path);
            string[] failure = { "null" };
            //这里没有导出表的文件
            if(pe_info.data_directory[1] == 0)
            {
                return failure;
            }
            int export_virtual_address = PE_AN.RVA_to_FOA(pe_info.data_directory[1], this.PE_INFO);//获取data_directory的第一个结构体，获取导出表的virtualAddress,并转化为FOA
            PE_AN.load_export(pe_info, export_virtual_address);
            int FOA_address_functions = PE_AN.RVA_to_FOA(pe_info.export.AddressOfFunctions, pe_info);//获取address_functions表的FOA地址
            int FOA_address_name_ordinal = PE_AN.RVA_to_FOA(pe_info.export.AddressOfNameOrdinals, pe_info);//获取序号表的FOA地址
            int FOA_names = PE_AN.RVA_to_FOA(pe_info.export.AddressOfNames, pe_info);//获取名字表的FOA地址
            int name = PE_AN.RVA_to_FOA(pe_info.export.Name, pe_info);


            
            //读取Base和NumberOfFunction,得到address_function表大小，读取其中所有函数入口地址，他们各自的序号是索引+Base。
            //然后读取numberOfNmaes,得到address_name表大小，分别读取然后记其索引为i，在address_name_ordinal表中找索引为i的地方，读取值+Base就是序号函数的名字。
            int Base = pe_info.export.Base;
            int number_of_functions = pe_info.export.NumberOfFunctions;

            string[] result = new string[3 * number_of_functions + 1];//[0]表示有几个函数,[1]:函数名，[2]:函数序号, [3]:函数入口地址（RVA）
            PE_AN.load_and_write_ordinals_address(result, number_of_functions, FOA_address_functions, Base);

            int number_of_name = pe_info.export.NumberOfName;

            PE_AN.load_and_write_name(result, number_of_name, FOA_address_name_ordinal, FOA_names, Base, pe_info);
            return result;
        }

        private void dataGridView1_CellContentClick(object sender, DataGridViewCellEventArgs e)
        {

        }

        private void FillDataToGrid(string[] data)
        {
            int cursor=1;
            dataGridView1.RowsDefaultCellStyle.Font = new Font
            ("宋体", 10, FontStyle.Regular);
            //dataGridView1.Rows.Add();
            //dataGridView1.Rows[1].Cells[0].Value = "1";
            //dataGridView1.Rows[0].Cells[0].Value = "1";
            //dataGridView1.Rows.Add();
            //dataGridView1.Rows[2].Cells[2].Value = "1";
            for (int i = 0; i< int.Parse(data[0])-1; i++)
            {
                dataGridView1.Rows.Add();
            }
            for (int i = 0; i < int.Parse(data[0]); i++)//
            {
                for (int k = 0; k < 3; k++)
                {
                    dataGridView1.Rows[i].Cells[k].Value = data[cursor];
                    cursor++;
                }
            }
            return;
            
        }

        private void Form7_Load(object sender, EventArgs e)
        {

        }
    }
}
