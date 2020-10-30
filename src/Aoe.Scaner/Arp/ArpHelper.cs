using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using SharpPcap;
using SharpPcap.LibPcap;
using SharpPcap.Npcap;
using SharpPcap.WinPcap;

namespace Aoe.Scaner.Arp
{
   public class ArpHelper
    {
        public static bool TryGetMacAddress(LibPcapLiveDevice device, IPAddress targetAddress, out PhysicalAddress macAddress)
        {
            macAddress = null;
            ARP arp = new ARP(device);
            try
            {
                macAddress = arp.Resolve(targetAddress);
            }
            catch
            {
            }
            return macAddress != null;


        }

    }
}
