using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;

namespace PE_analysis
{
    public class data_process
    {
        public data_process()
        {

        }

        public string byte_to_str(byte[] data, int little_or_big_endian, int length)//十进制转十六进制，按照大小端换序，再转为字符串
        {
            string result = "";
            for(int i = 0; i<length; i++)
            {
                string hex_v = data[i].ToString("X");
                if(hex_v.Length == 1)
                {
                    hex_v = String.Concat("0", hex_v);
                }
                //Console.Write(hex_v);
                if (little_or_big_endian == 1)//小端序
                {
                    result = String.Concat(hex_v,result);
                }
                else if(little_or_big_endian == 0)//大端序
                {
                    result = String.Concat(result, hex_v);
                }
            }
            return result;
        }

        public int byte_to_int(byte[] data, int little_or_big_endian, int length)
        {
            int result=0;
            if(little_or_big_endian == 1)//小端序
            {
                if(length == 2)
                {
                    result = System.BitConverter.ToInt16(data, 0);
                }
                else if(length == 4)
                {
                    result = System.BitConverter.ToInt32(data, 0);
                }    
            }
            else if(little_or_big_endian == 0)//大端序
            {
                byte[] tool = new byte[length];
                for(int i = 0; i<length; i++)
                {
                    tool[length - i - 1] = data[i];
                }
                if (length == 2)
                {
                    result = System.BitConverter.ToInt16(data, 0);
                }
                else if (length == 4)
                {
                    result = System.BitConverter.ToInt32(data, 0);
                }
            }
            else
            {
                result = -1;
            }
            return result;
        }

        public string byte_to_ascii(byte[] data, int little_or_big_endian, int length)
        {
            string result;
            int cursor = 0;
            if (little_or_big_endian == 1)//小端序
            {
                while(data[cursor]!=0)
                {
                    cursor++;
                }
                result = Encoding.ASCII.GetString(data,0,cursor);
                return result;
            }
            else if (little_or_big_endian == 0)//大端序
            {
                byte[] tool = new byte[length];
                for (int i = 0; i < length; i++)
                {
                    tool[length - i - 1] = data[i];
                }
                while (data[cursor] != 0)
                {
                    cursor++;
                }
                result = Encoding.ASCII.GetString(data, 0, cursor);
                return result;
            }
            return "F41LEO";//表示解析失败
        }

        public int str16_to_int(string data)
        {
            int result;
            result = Convert.ToInt32(data, 16);
            return result;
        }

        //对一个字符串进行检查，是否符合本程序对于字节码的格式要求。如果符合，就返回一个byte[]数组。否则，返回
        public bool str_to_muli_byte(string data, List<byte> contenter)
        {
            if(String.IsNullOrEmpty(data))
            {
                return true;
            }
            string[] str1 = Regex.Split(data, "\r\n", RegexOptions.IgnoreCase);
            //string[] str2 = new string[300];

            for (int i = 0; i < str1.Length; i++)
            {
                string[] str3 = Regex.Split(str1[i], " ", RegexOptions.IgnoreCase);
                for (int k = 0; k < str3.Length; k++)
                {
                    if ((str3[k].Length == 2 && Regex.Match(str3[k], @"[0-9|a-f]{2}").Length > 0))//检验每一项输入是否合规则
                    {
                        contenter.Add(Convert.ToByte(str3[k], 16));
                    }
                    else//不合规则就将状态码置0，返回
                    {
                        return false;
                    }
                }
            }
            return true;
        }

        public bool is_digit(string data)
        {
            if (Regex.Match(data, @"^[0-9]+$").Length > 0)
            {
                return true;
            }
            else return false;
        }

        //将一个包含英文字符的字符串转为byte，ascii编码解码
        public byte[] str_to_byte(string data)
        {
            return Encoding.UTF8.GetBytes(data);
        }

        //data:要操作的byteLIST，des_data:要替换的byte，range：替换的位置
        public bool replace_range(List<byte> data, byte[] des_data, int range)
        {
            try
            {
                data.RemoveRange(range, des_data.Length);
                for(int i = 0; i<des_data.Length; i++)
                {
                    data.Insert(range, des_data[i]);
                    range++;
                }
            }
            catch
            {
                return false;
            }
            return true;
        }

        //将一个数字转为byte数组，byte数组长度为4
        public byte[] int_to_byte(int data)
        {
            byte[] result = new byte[4];
            result = BitConverter.GetBytes(data);
            return result;
        }
    }
}
