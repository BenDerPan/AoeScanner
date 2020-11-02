using Aoe.Scaner.Syn;
using System;
using System.Diagnostics;
using System.Net;

namespace AoeScanner.SimpleApp
{
    class Program
    {
        static void Main(string[] args)
      {
            string localIp = string.Empty;
            while (true)
            {
                Console.Write("请输入监听网卡IP>");
                localIp= Console.ReadLine().Trim();
                if (!IPAddress.TryParse(localIp,out _))
                {
                    continue;
                }
                break;
            }
            while (true)
            {
                Console.Write("输入目标IP(输入exit退出)>");
                var cmd = Console.ReadLine().Trim();
                if (cmd.ToLower()=="exit")
                {
                    break;
                }

               
                try
                {
                    Stopwatch watch = new Stopwatch();
                    
                    SynScanner scaner = new SynScanner(localIp, cmd);
                    watch.Start();
                    scaner.Scan();
                    watch.Stop();
                    foreach (var port in scaner.OpenPorts)
                    {
                        Console.WriteLine($"开放端口:{port}");
                    }

                    Console.WriteLine($"扫描完成，总耗时:{watch.ElapsedMilliseconds / 1000}s");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"扫描错误：{e}");
                }
            }
           
        }
    }
}
