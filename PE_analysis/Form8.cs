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
    public partial class Form8 : Form
    {
        string path;
        PE_informaton pe_info;
        public Form8(string path, PE_informaton pe_info)
        {
            InitializeComponent();
            this.path = path;
            this.pe_info = pe_info;
            List<int> relocation_info = load_relocation();


        }

        private void Form8_Load(object sender, EventArgs e)
        {

        }

        private List<int> load_relocation()
        {
            FileStream F = new FileStream(this.path, FileMode.Open, FileAccess.Read);
            analyzer PE_AN = new analyzer(this.path);
            data_process dp = new data_process();
            List<int> result = new List<int>();

            int relocation_location = PE_AN.RVA_to_FOA(pe_info.data_directory[5 * 2 + 1], pe_info);//读取relocation的入口位置，并作FOA转换。
            int block_start = 0, block_size = 0, address_num = 0;
            byte[] tool = new byte[4];

            F.Position = relocation_location;

            F.Read(tool, 0, 4);
            block_start = dp.byte_to_int(tool, 1, 4);//获取块入口地址

            F.Read(tool, 0, 4);
            block_size = dp.byte_to_int(tool, 1, 4);//获取块大小

            while(block_size!=0 && block_start!=0)
            {
                address_num = (block_size - 8) / 2;//获取有多少个要修改的地址
                result.Add(block_start);
                result.Add(address_num);
                for (int i = 0; i<address_num; i++)//每次读取2字节，读取address_num次
                {
                    F.Read(tool, 0, 2);
                    //if((tool[1] & (byte)0x30) == 0x30)//如果前四位是3，则将这条地址计入结果中
                    //{

                    //}
                    result.Add(dp.byte_to_int(tool, 1, 2));
                }
                F.Read(tool, 0, 4);
                block_start = dp.byte_to_int(tool, 1, 4);//获取块入口地址
                F.Read(tool, 0, 4);
                block_size = dp.byte_to_int(tool, 1, 4);//获取块大小
            }
            result.Add(-1);
            result.Add(-1);
            return result;
        }
    }
}
