/**
 * Program: PACKET SNIFFER
 * Meno: Peter Vinarcik
 * Login: xvinar00
 * Datum: 24.4.2020
 * FIT VUT Brno, 2020
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks.Dataflow;
using PacketDotNet.Utils;
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
        
        private int firstNum = 0;
        private int secondNum = 0;
        private int thirdNum = 0;
        private int fourthNum = 0;
        
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
            foreach (var dev in devices) {
                
                if (dev.Name == deviceName) {
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

        /**
         * Function for applying filter(s) which were given as command line arguments
         * If there is -udp and -tcp filter at the same time (or both are not given)
         * it will apply filter for search for both of those packet types
         */
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
        
        /**
         * Function which Extract Packet
         * take info (about source and destination -> ports, address(which is converted to DN))
         * and at the end of function, there is print function for print sniffed packet
         */
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
            
            /**
             * We detected that we got udp packet, so it execute this part of code
             * which take source and destination address / port
             * also take hostName (if exists) from function findHostName
             * and print it as a info of packet
             */
            
            if (udpPacket != null)
            {
                var Packet = (PacketDotNet.IPPacket)udpPacket.ParentPacket;
                
                var src = Packet.SourceAddress;
                var dst = Packet.DestinationAddress;
                var srcPort = udpPacket.SourcePort;
                var dstPort = udpPacket.DestinationPort;
                
                string hostnameSrc = findHostName(src.ToString());;
                string hostnameDst = findHostName(dst.ToString());;

                Console.WriteLine("{0}:{1}:{2}.{3} {4} : {5} > {6} : {7}\n",
                    time.Hour, time.Minute, time.Second, time.Millisecond, hostnameSrc, srcPort, hostnameDst, dstPort);
                
                int length = len - udpPacket.PayloadData.Length; //calculate length of header data
                
                firstNum = 0;
                secondNum = 0;
                thirdNum = 0;
                fourthNum = 0;

                /**
                 * THIS PART OF CODE, SEPARATE HEADERS AND
                 * OPTIONS IN PACKET AND PRINT PRINTABLE ASCII CHARACTERS
                 * IF IS NONPRINTABLE CHAR THERE, IT WILL PRINT AS DOT
                 */
                string[] udpfile = fillSeparatedParts(0, length, udpPacket.BytesSegment);
                createAsciiChars(udpfile);
                Console.WriteLine();

                if (udpPacket.PayloadData.Length > 0) {
                    string[] udpfile2 = fillSeparatedParts(length, len, udpPacket.PayloadDataSegment);
                    if (udpfile2.Length > 0) {
                        createAsciiChars(udpfile2);
                    }
                    Console.WriteLine();
                }
                Console.WriteLine();
            }
            
            /**
             * We detected that we got tcp packet, so it execute this part of code
             * which take source and destination address / port
             * also take hostName (if exists) from function findHostName
             * and print it as a info of packet
             */
            
            if (tcpPacket != null)
            {
                var Packet = (PacketDotNet.IPPacket)tcpPacket.ParentPacket;
                
                var src = Packet.SourceAddress;
                var dst = Packet.DestinationAddress;
                var srcPort = tcpPacket.SourcePort;
                var dstPort = tcpPacket.DestinationPort;

                string hostnameSrc = findHostName(src.ToString());
                string hostnameDst = findHostName(dst.ToString());

                Console.WriteLine("{0}:{1}:{2}.{3} {4} : {5} > {6} : {7}\n",
                    time.Hour, time.Minute, time.Second, time.Millisecond, hostnameSrc, srcPort, hostnameDst, dstPort);

                /**
                 * THIS PART OF CODE, SEPARATE HEADERS AND
                 * OPTIONS IN PACKET AND PRINT PRINTABLE ASCII CHARACTERS
                 * IF IS NONPRINTABLE CHAR THERE, IT WILL PRINT AS DOT
                 */
                int length = len - tcpPacket.PayloadData.Length; //calculate length of header data
                
                firstNum = 0;
                secondNum = 0;
                thirdNum = 0;
                fourthNum = 0;
                
                string[] tcpfile = fillSeparatedParts(0, length, tcpPacket.BytesSegment);
                createAsciiChars(tcpfile);
                Console.WriteLine();

                if (tcpPacket.PayloadData.Length > 0) {
                    string[] tcpfile2 = fillSeparatedParts(length, len, tcpPacket.PayloadDataSegment);
                    if (tcpfile2.Length > 0) {
                        createAsciiChars(tcpfile2);
                    }
                    Console.WriteLine();
                }
                Console.WriteLine();
            }
        }

        /**
         * >Because builded function .HexPrint() from library SharpPcap didn't print tcpdumb hex in format
         * that we have to print it, i have to create function, which creates ASCII characters based on hexadecimals characters
         * taken by PayloadDataSegment (and also header part).
         */
        public void createAsciiChars(string[] tcpfile)
        {
            foreach (var item in tcpfile) {
                string hexValue1 = firstNum.ToString("x");
                string hexValue2 = secondNum.ToString("x");
                string hexValue3 = thirdNum.ToString("x");
                string hexValue4 = fourthNum.ToString("x");
                Console.Write("0x{0}{1}{2}{3}:  ", hexValue1, hexValue2, hexValue3, hexValue4);
                Console.Write(item.Substring(0, item.Length-1));

                int counter1 = 0;
                int counter2 = 0;
                var testarr = item.Split(" ");
                bool firstTim = true;
                for (int j = 0; j < testarr.Length; j++) {
                    if (!string.IsNullOrWhiteSpace(testarr[j])) {
                        if (item.Length-1 != 50 && firstTim) {
                            int countSymbols = 0;
                            for (int i = 0; i < item.Length; i++) {
                                if (!char.IsWhiteSpace(item[i])) {
                                    countSymbols += 1;
                                }
                            }
                            fourthNum = countSymbols / 2;
                            for (int k = 0; k <= 50-item.Length; k++) {
                                Console.Write(" ");
                            }

                            thirdNum--;
                            firstTim = false;
                        }
                        int decValue = Convert.ToInt32(testarr[j], 16);
                        counter1++;
                        counter2++;
                        if (decValue > 32 && decValue < 127) {
                            Console.Write((char)decValue);
                        }
                        else {
                            Console.Write(".");
                        }

                        if (counter1 % 8 == 0) {
                            Console.Write(" ");
                        }
                        if (counter2 % 16 == 0){
                            Console.Write("\n");
                        }
                    }
                }
                thirdNum++;
                if (thirdNum == 16) {
                    secondNum++;
                    thirdNum = 0;
                }
                if (secondNum == 16) {
                    firstNum++;
                    secondNum = 0;
                    thirdNum = 0;
                }
            }
        }

        /**
         * This Function takes bytes written as hexadecimals and separate them into format
         * a1 b1 c1 d1 e1 f1 g1 h1  a2 b2 c2 d2 e2 f2 g2 h2
         */
        public string[] fillSeparatedParts(int start, int stop, ByteArraySegment payloadDataSegment)
        {
            string temp = "";
            List<string> tcpfile = new List<string>();
            int counter1 = 0;
            int counter2 = 0;
            for (int j = start; j < stop; j++) {
                temp += payloadDataSegment.Bytes[j].ToString("x2");
                temp += " ";
                counter1++;
                counter2++;
                if (counter1 % 8 == 0) {
                    temp += " ";
                }

                if (counter2 % 16 == 0) {
                    temp += "\n";
                    tcpfile.Add(temp);
                    temp = "";
                }
            }

            if (temp.Length != 0) {
                temp += "\n";
                tcpfile.Add(temp);
            }
            
            return tcpfile.ToArray();
        }

        /**
         * Find hostname of given ip address,
         * if FQDN not exists, it returns given ip address.
         */
        public string findHostName(string src)
        {
            string hostname = "";
            IPAddress url = IPAddress.Parse(src);
            
            try {
                IPHostEntry iphe = Dns.GetHostEntry(url);
                hostname = iphe.HostName;
            }
            catch (Exception)
            {
                hostname = src;
            }

            return hostname;
        }
    }
}