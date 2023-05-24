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
    public partial class Form1 : Form
    {
        public Form2 anotherForm;
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }
        public void button1_Click(object sender, EventArgs e)
        {
            var openFileDialog = new Microsoft.Win32.OpenFileDialog()
            {
                Filter = "PE Files|*.dll;*.exe;*.lib"
            };
            var result = openFileDialog.ShowDialog();
            if (result == true)
            {
                //MessageBox.Show(openFileDialog.FileName);
                //跳转界面到PE头界面，
                //MessageBox.Show(string.Join(Environment.NewLine, openFileDialog.FileNames.ToList()));
                anotherForm = new Form2(openFileDialog.FileName);
                this.Hide();
                anotherForm.ShowDialog();
                Application.ExitThread();
            }
        }


    }
}
