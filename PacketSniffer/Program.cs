/**
 * Program: PACKET SNIFFER
 * Meno: Peter Vinarcik
 * Login: xvinar00
 * Datum: 24.4.2020
 * FIT VUT Brno, 2020
 */

using System;
using SharpPcap;

namespace PacketSniffer
{
    public class PacketSniffer
    {
        private bool i = false;
        private string deviceName;
        
        private bool p = false;
        private int port;
        
        private bool tcp = false;
        private bool udp = false;
        
        private int number = 1;
        private int countPackets = 0;
        private ICaptureDevice device;
        
        void parseArguments(string[] args) {
            bool nextIsNumber = false; 
            bool nextIsPort = false; 
            bool nextIsDevice = false; 
        
            bool wasI = false; 
            bool wasP = false; 
            bool wasTCP = false; 
            bool wasUDP = false; 
            bool wasN = false;

            if (args.Length == 0) {
                return;
            }
            
            if (args[0] != "-i") {
                return;
            }
            
            foreach (var dev in args) {
                if (nextIsDevice) {
                    deviceName = dev;
                    nextIsDevice = false;
                }
                else if (nextIsPort) {
                    try {
                        port = Int32.Parse(dev);
                    }
                    catch (FormatException e) {
                        Console.WriteLine(e.Message);
                        Environment.Exit(10);
                    }
                    nextIsPort = false;
                }
                else if (nextIsNumber) {
                    try {
                        number = Int32.Parse(dev);
                    }
                    catch (FormatException e) {
                        Console.WriteLine(e.Message);
                        Environment.Exit(10);
                    }
                    nextIsNumber = false;
                } 
                else {
                    if (dev == "-i" && !wasI) {
                        i = true;
                        nextIsDevice = true;
                        wasI = true;
                    }
                    else if (dev == "-p" && !wasP) {
                        p = true;
                        nextIsPort = true;
                        wasP = true;
                    }
                    else if ((dev == "-tcp" || dev == "-t") && !wasTCP) {
                        tcp = true;
                        wasTCP = true;
                    }
                    else if ((dev == "-udp" || dev == "-u") && !wasUDP) {
                        udp = true;
                        wasUDP = true;
                    }
                    else if (dev == "-n" && !wasN) {
                        nextIsNumber = true;
                        wasN = true;
                    }
                    else {
                        Console.WriteLine("BAD ARGUMENTS!");
                        Environment.Exit(10);
                    }
                }
            }
        }
        ICaptureDevice checkIfDeviceExists(string deviceName, CaptureDeviceList devices)
        {
            bool isThere = false;
            ICaptureDevice deviceToReturn = devices[0];
            foreach (var dev in devices)
            {
                
                if (dev.Name == deviceName)
                {
                    isThere = true;
                    deviceToReturn = dev;
                    break;
                }
            }
            
            if (!isThere) {
                Console.WriteLine("GIVEN DEVICE IS NOT EXISTS!");
                Environment.Exit(10);
            }
            
            return deviceToReturn;
        }
        
        public static void Main(string[] args)
        {
            PacketSniffer Foo = new PacketSniffer();
            Foo.parseArguments(args);
            
            var devices = CaptureDeviceList.Instance;
            
            if (!Foo.i) {
                foreach (var dev in devices)
                    Console.WriteLine("{0}", dev.Name);
                return;
            }

            Foo.device = Foo.checkIfDeviceExists(Foo.deviceName, devices);
            Foo.device.Open();
            Foo.device.Filter = Foo.createFilter();
            Foo.device.OnPacketArrival += Foo.device_OnPacketArrival;
            Foo.device.Capture();
        }

        string createFilter()
        {
            string filter = "";
            if (p){
                if ((!tcp && !udp) || (tcp && udp)) {
                    filter = "tcp port " + port + " or udp port " + port;
                }
                else if (tcp) {
                    filter = "tcp port " + port;
                }
                else if (udp) {
                    filter = "udp port " + port;
                }
            }
            else {
                if ((!tcp && !udp) || (tcp && udp)) {
                    filter = "tcp or udp";
                }
                else if (tcp) {
                    filter = "tcp";
                }
                else if (udp) {
                    filter = "udp";
                }
            }
            return filter;
        }
        
        void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;

            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);

            var tcpPacket = packet.Extract<PacketDotNet.TcpPacket>();
            var udpPacket = packet.Extract<PacketDotNet.UdpPacket>();

            countPackets++;
            if (number < countPackets) {
                device.Close();
                device.StopCapture();
                Environment.Exit(0);
            }
            
            if (udpPacket != null)
            {
                var ipPacket = (PacketDotNet.IPPacket)udpPacket.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = udpPacket.SourcePort;
                int dstPort = udpPacket.DestinationPort;
                
                Console.WriteLine("{0}:{1}:{2}.{3} Len={4} {5}:{6} -> {7}:{8}\n",
                    time.Hour, time.Minute, time.Second, time.Millisecond, len,
                    srcIp, srcPort, dstIp, dstPort);
                Console.WriteLine(udpPacket.PrintHex());
            }
            
            if (tcpPacket != null)
            {
                var ipPacket = (PacketDotNet.IPPacket)tcpPacket.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = tcpPacket.SourcePort;
                int dstPort = tcpPacket.DestinationPort;
                
                Console.WriteLine("{0}:{1}:{2}.{3} Len={4} {5}:{6} -> {7}:{8}\n",
                    time.Hour, time.Minute, time.Second, time.Millisecond, len,
                    srcIp, srcPort, dstIp, dstPort);
                Console.WriteLine(tcpPacket.PrintHex());
            }
        }
    }
}