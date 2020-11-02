using Aoe.Scanner.Device;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Aoe.Scaner.Syn
{
    public class SynScanner
    {
        IPAddress _localIpAddr;
        ushort _localPort;
        PhysicalAddress _localMacAddr;
        LibPcapLiveDevice _device;
        string _target;
        IPAddress _targetIpAddr;
        int _scanStartPort;
        int _scanEndPort;

        const int DefaultThreadCount = 20;
        const int DefaultStartPort = 1;
        const int DefaultEndPort=65535;
        int _maxThreadCount;

        PhysicalAddress _targetMacAddr;

        private readonly HashSet<ushort> _openPorts = new HashSet<ushort>();
        private readonly HashSet<ushort> _filteredPorts = new HashSet<ushort>();

        public IEnumerable<ushort> OpenPorts => _openPorts;
        public IEnumerable<ushort> FilteredPorts => _filteredPorts;

        /// <summary>
        /// Syn Scanner
        /// </summary>
        /// <param name="localIp"></param>
        /// <param name="target"></param>
        /// <param name="portStart"></param>
        /// <param name="portEnd"></param>
        /// <param name="threadCount"></param>
        public SynScanner(string localIp,string target, int portStart =DefaultStartPort, int portEnd =DefaultEndPort,int threadCount=DefaultThreadCount)
        {
            _localIpAddr = IPAddress.Parse(localIp);
            _localPort = (ushort)new Random().Next(20000, 60000);
            _target = target;
            _scanStartPort = portStart>0?portStart:DefaultStartPort;
            _scanEndPort = portEnd>0?portEnd:DefaultEndPort;
            if (_scanEndPort>ushort.MaxValue)
            {
                _scanEndPort = ushort.MaxValue;
            }
            _maxThreadCount = threadCount>0?threadCount:DefaultThreadCount;
        }

        public void Scan()
        {
            if (!DeviceHelper.TryGetDevice(_localIpAddr, out _device))
            {
                throw new NullReferenceException("cannot find the target network interface!!!");
            }
            _localMacAddr = _device.Interface.MacAddress;

           

            _targetIpAddr = Dns.GetHostAddresses(_target).First(x => x.AddressFamily == AddressFamily.InterNetwork);
            ARP arp = new ARP(_device);
            //获取目标IP对应的Mac地址（通常外网地址则对应获取网关的Mac）
            var gatewayIpAddr = _device.Interface.GatewayAddresses[0];
            _targetMacAddr = arp.Resolve(gatewayIpAddr, _localIpAddr, _localMacAddr);

            _device.Open(DeviceMode.Promiscuous, 100);

            _device.OnPacketArrival += async (sender, eventArgs) =>
            {
                var packet = Packet.ParsePacket(eventArgs.Packet.LinkLayerType, eventArgs.Packet.Data);
                var arrivedIpPacket = packet.Extract<IPPacket>() as IPv4Packet;

                if (arrivedIpPacket == null)
                    return;

                if (!arrivedIpPacket.SourceAddress.Equals(_targetIpAddr)) return;

                var pcapDevice = sender as LibPcapLiveDevice;
                if (pcapDevice == null)
                    return;

                var ethPacket = packet as EthernetPacket;
                if (ethPacket != null)
                {
                    _targetMacAddr = ethPacket.SourceHardwareAddress;
                }

                var arrivedTcpPacket = arrivedIpPacket.Extract<TcpPacket>() as TcpPacket;

                if (arrivedTcpPacket == null) { return; }

                var sourcePort = arrivedTcpPacket.SourcePort;
                if (arrivedTcpPacket.Reset)
                {
                    Monitor.Enter(_filteredPorts);
                    if (_filteredPorts.Contains(sourcePort))
                        return;
                    _filteredPorts.Add(sourcePort);
                    Monitor.Pulse(_filteredPorts);

                   // Console.WriteLine("Filtered Port: {0}", sourcePort);
                }
                
                if (arrivedTcpPacket.Synchronize && arrivedTcpPacket.Acknowledgment)
                {
                    var newEther = GenerateEthernetPacket(sourcePort, isSyn:false,isRst:true);

                    pcapDevice.SendPacket(newEther);
                    Monitor.Enter(_openPorts);
                    if (_openPorts.Contains(sourcePort))
                        return;
                    _openPorts.Add(sourcePort);
                    Monitor.Pulse(_openPorts);

                    Console.WriteLine($"Open Port:{sourcePort}");
                }
            };

            _device.Filter = $"ip and tcp";

            ConcurrentQueue<int> needScanPortQueue = new ConcurrentQueue<int>();
            for (int i = _scanStartPort; i <= _scanEndPort; i++)
            {
                needScanPortQueue.Enqueue(i);
            }

            _device.StartCapture();

            var tasks = new List<Task>();
            for (ushort i = 0; i <= _maxThreadCount; i++)
            {
                var task = Task.Run(async () =>
                {
                    while (true)
                    {
                        if (needScanPortQueue.Count<1)
                        {
                            break;
                        }
                        if (needScanPortQueue.TryDequeue(out var portNum))
                        {
                            var port = (ushort)portNum;
                            var ethernetPacket = GenerateEthernetPacket(port, isSyn: true);
                            _device.SendPacket(ethernetPacket);
                        }
                        
                    }
                });

                tasks.Add(task);
            }
            Task.WaitAll(tasks.ToArray());
            _device.Close();


        }

        public static TcpPacket CreateTcpPacket(ushort sourcePort, ushort destinationPort, bool syn, bool rst)
        {
            var result = new TcpPacket(sourcePort, destinationPort) { Synchronize = syn, Reset = rst };

            return result;
        }

        public static IPv4Packet CreateIpV4Packet(IPAddress sourceIpAddress, IPAddress destinationIpAddress,
           TcpPacket payloadPacket)
        {
            var result = new IPv4Packet(sourceIpAddress, destinationIpAddress) { PayloadPacket = payloadPacket };

            payloadPacket.UpdateTcpChecksum();

            result.UpdateIPChecksum();
            result.UpdateCalculatedValues();

            return result;
        }
        public static EthernetPacket CreateEthernetPacket(PhysicalAddress sourceAddress,
            PhysicalAddress destinationAddress, Packet payloapPacket)
        {
            var result = new EthernetPacket(sourceAddress, destinationAddress, EthernetType.IPv4)
            {
                PayloadPacket = payloapPacket
            };

            return result;
        }
        private EthernetPacket GenerateEthernetPacket(ushort destinationPort, bool isSyn=false,bool isRst=false)
        {
            TcpPacket tcpPacket=CreateTcpPacket(_localPort, destinationPort, isSyn, isRst);
            var ipPacket = CreateIpV4Packet(_localIpAddr, _targetIpAddr, tcpPacket);
            if (_targetMacAddr!=null)
            {
                return CreateEthernetPacket(_localMacAddr, _targetMacAddr, ipPacket);
            }
            else
            {
                throw new NullReferenceException("target mac address is null");
            }

        }
    }
}
