using SharpPcap.LibPcap;
using SharpPcap.Npcap;
using SharpPcap.WinPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;

namespace Aoe.Scaner.Device
{
    public class DeviceHelper
    {
        public static bool TryGetDevice(IPAddress localIpAddress, out LibPcapLiveDevice device)
        {
            device = null;
            try
            {
                device = LibPcapLiveDeviceList.Instance.First(
                    x => x.Interface.Addresses.Select(y => y.Addr.ipAddress).Contains(localIpAddress));
                return true;
            }
            catch (Exception)
            {
                return false;
            }

        } 
    }
}
