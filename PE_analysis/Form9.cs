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
    public partial class Form9 : Form
    {
        string path;
        PE_informaton pe_info;
        public Form9(string path, PE_informaton pe_info)
        {
            InitializeComponent();
            this.path = path;
            this.pe_info = pe_info;

            string[][] res = GetImportTableInfo();
            FillDataToGrid(res);
        }

        private string[][] GetImportTableInfo()
        {
            analyzer PE_AN1 = new analyzer(this.path);
            data_process dp = new data_process();
            List<string[]> list_res = new List<string[]>();
            List<string> mid_tmp = new List<string>();//用于中间存储一个dll的所有函数名和序号以及入口地址

            FileStream F = new FileStream(this.path, FileMode.Open, FileAccess.Read);
            byte[] tool = new byte[4];
            long back_address;
            

            PE_AN1.load_import(pe_info, PE_AN1.RVA_to_FOA(this.pe_info.data_directory[3], pe_info));//加载pe_info中的import字段
            for(int i = 0; i<pe_info.imports.Length; i++)//对每个dll作处理
            {
                int FOA_OriginalFirstThunk = PE_AN1.RVA_to_FOA(pe_info.imports[i].OriginalFirstThunk, pe_info);//确定导入名称表的位置
                int FOA_First_Thunk = PE_AN1.RVA_to_FOA(pe_info.imports[i].FirstThunk, pe_info);
                int loop_flag = 0;
                string Name = PE_AN1.load_str(PE_AN1.RVA_to_FOA(pe_info.imports[i].Name, pe_info), F);//读取name
                string entry_address="0";
                if(pe_info.imports[i].TimeDateStamp == 0)
                {
                    entry_address = "NULL";
                }
                mid_tmp.Add(Name);//mid_tmp第一位是dll文件名称，后面按照序号-名字-入口地址的顺序排列。
                F.Position = FOA_OriginalFirstThunk;
                while(true)
                {
                    F.Read(tool, 0, 4);
                    if(dp.byte_to_int(tool, 1, 4) == 0)
                    {
                        break;
                    }
                    //判断最高位是否为1
                    if((tool[3] & (byte)128) == 128)
                    {
                        tool[3] = (byte)(tool[3] & (byte)127);
                        mid_tmp.Add(Convert.ToString(dp.byte_to_int(tool, 1, 4)));//写序号
                        mid_tmp.Add("NULL");//没有名字，写NULL
                        back_address = F.Position;
                    }
                    else 
                    {
                        back_address = F.Position;//后面要跳一次地址，所以需要记录返回地址
                        F.Position = PE_AN1.RVA_to_FOA(dp.byte_to_int(tool, 1, 4), pe_info);

                        mid_tmp.Add("NULL");//不按序号导入，写NULL
                        mid_tmp.Add(PE_AN1.load_str((int)F.Position + 2, F));
                        
                    }
                    if(entry_address == "NULL")
                    {
                        mid_tmp.Add("NULL");
                        F.Position = back_address;
                    }
                    else
                    {
                        F.Position = FOA_First_Thunk + loop_flag * 4;
                        F.Read(tool, 0, 4);
                        mid_tmp.Add(dp.byte_to_str(tool, 1, 4));
                        F.Position = back_address;
                    }
                    loop_flag++ ;
                    
                }
                list_res.Add(mid_tmp.ToArray());
                mid_tmp.Clear();
            }

            return list_res.ToArray();
        }

        private void FillDataToGrid(string[][] data)
        {
            dataGridView1.RowsDefaultCellStyle.Font = new Font("宋体", 10, FontStyle.Regular);

            for(int i=0; i<data.Length; i++)
            {
                for(int j=0; j<(data[i].Length-1)/3; j++)
                {
                    dataGridView1.Rows.Add();
                }
            }//先新增行

            int cursor = 0;
            for(int i=0; i< data.Length; i++)
            {
                for(int j=0; j<(data[i].Length-1)/3; j++)
                {
                    dataGridView1.Rows[cursor].Cells[0].Value = data[i][0];
                    dataGridView1.Rows[cursor].Cells[1].Value = data[i][3 * j + 1];
                    dataGridView1.Rows[cursor].Cells[2].Value = data[i][3 * j + 2];
                    dataGridView1.Rows[cursor].Cells[3].Value = data[i][3 * j + 3];
                    cursor++;
                }
            }
                return;
        }

        private void Form9_Load(object sender, EventArgs e)
        {

        }
    }
}
