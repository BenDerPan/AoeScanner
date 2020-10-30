using Aoe.Scaner.Arp;
using Aoe.Scaner.Device;
using Aoe.Scaner.Syn;
using System;
using System.Net;

namespace AoeScaner.SimpleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            while (true)
            {
                Console.Write("输入目标IP(输入exit退出)>");
                var cmd = Console.ReadLine().Trim();
                if (cmd.ToLower()=="exit")
                {
                    break;
                }

                if (!IPAddress.TryParse(cmd,out var ip))
                {
                    Console.WriteLine($"{cmd} 不是合法的IP地址!!!");
                    continue;
                }

                try
                {
                    SynScaner scaner = new SynScaner("172.16.17.22", cmd);
                    scaner.Scan();
                    foreach (var port in scaner.OpenPorts)
                    {
                        Console.WriteLine($"开放端口:{port}");
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine($"扫描错误：{e}");
                }
            }
           
        }
    }
}
