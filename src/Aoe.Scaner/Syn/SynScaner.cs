using Aoe.Scaner.Device;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Aoe.Scaner.Syn
{
    public class SynScaner
    {
        IPAddress _localIpAddr;
        ushort _localPort;
        PhysicalAddress _localMacAddr;
        LibPcapLiveDevice _device;
        string _target;
        IPAddress _targetIpAddr;
        ushort _scanStartPort;
        ushort _scanEndPort;

        PhysicalAddress _targetMacAddr;

        private readonly HashSet<ushort> _openPorts = new HashSet<ushort>();
        private readonly HashSet<ushort> _filteredPorts = new HashSet<ushort>();

        public IEnumerable<ushort> OpenPorts => _openPorts;
        public SynScaner(string localIp,string target,ushort portStart=1,ushort portEnd=65535)
        {
            _localIpAddr = IPAddress.Parse(localIp);
            _localPort = (ushort)new Random().Next(30000, 60000);
            _target = target;
            _scanStartPort = portStart;
            _scanEndPort = portEnd;
        }

        public void Scan()
        {
            if (!DeviceHelper.TryGetDevice(_localIpAddr, out _device))
            {
                throw new NullReferenceException("找不到指定的网卡!");
            }
            _localMacAddr = _device.Interface.MacAddress;

            _targetIpAddr = Dns.GetHostAddresses(_target).First(x => x.AddressFamily == AddressFamily.InterNetwork);

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
                //if (arrivedTcpPacket.Rst)
                //{
                //    Monitor.Enter(filteredPorts);
                //    if (filteredPorts.Contains(sourcePort))
                //        return;
                //    filteredPorts.Add(sourcePort);
                //    Monitor.Pulse(filteredPorts);

                //    if (shouldPrint)
                //        Console.WriteLine("Filtered: {0}", sourcePort);
                //}
                //else
                if (arrivedTcpPacket.Synchronize && arrivedTcpPacket.Acknowledgment)
                {
                   
                   
                    var newEther = GenerateEthernetPacket(sourcePort, isSyn:false,isRst:true);

                    pcapDevice.SendPacket(newEther);

                    //var tcp = new TcpClient(new IPEndPoint(localIp, localPort));
                    //await tcp.ConnectAsync(arrivedIpPacket.SourceAddress, arrivedTcpPacket.SourcePort);
                    //tcp.ExclusiveAddressUse = false;
                    //await tcp.GetStream().WriteAsync("Which protocol?".Select(Convert.ToByte).ToArray(), 0, "Which protocol?".Length);
                    //var readStream = new MemoryStream((int) Math.Pow(2, 16));
                    //await tcp.GetStream().ReadAsync(readStream.GetBuffer(), 0, readStream.Capacity);

                    Monitor.Enter(_openPorts);
                    if (_openPorts.Contains(sourcePort))
                        return;
                    _openPorts.Add(sourcePort);
                    Monitor.Pulse(_openPorts);

                    Console.WriteLine($"Open Port:{sourcePort}");
                }
            };

            _device.Filter = "ip and tcp";

            //开始扫描
            _device.StartCapture();

            

            var tasks = new List<Task>();
            for (ushort i = _scanStartPort; i < _scanEndPort; i++)
            {
                var ethernetPacket = GenerateEthernetPacket(i, isSyn:true);

                var portNum = i;
                var task = Task.Run(async () =>
                {
                    var timeoutMs = 128;

                    for (var j = 0; j < 4; j++)
                    {
                        _device.SendPacket(ethernetPacket);
                        if (_openPorts.Contains(portNum) || _filteredPorts.Contains(portNum))
                            return;
                        await Task.Delay(timeoutMs * j);
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
            return CreateEthernetPacket(_localMacAddr, new PhysicalAddress(new byte[] { 0,0,0,0,0,0}), ipPacket);

        }
    }
}
