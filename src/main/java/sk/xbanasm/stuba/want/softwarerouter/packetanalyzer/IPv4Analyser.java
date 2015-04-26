/*
 Autor: Martin Baňas
 Ročník: 2.
 Predmet: Počítačové a komunikačné siete
 Akademický rok: 2013/2014
 Semester: letný
 */
package sk.xbanasm.stuba.want.softwarerouter.packetanalyzer;

import java.io.IOException;
import org.jnetpcap.packet.PcapPacket;
import sk.xbanasm.stuba.want.softwarerouter.equip.Utils;

public class IPv4Analyser {
    private String srcIp = null;
    private String dstIp = null;
    
    private byte[] srcIpBA;
    private byte[] dstIpBA;
    
    private Integer ipHeaderOptionsLen = 0;
    
    private String ipProtocol = null;

    private IcmpAnalyser icmpHeader;
    private boolean icmpFound = false;

    private TcpUdpAnalyser tcpUdpAnalyser;
    private boolean transportProtocolFound = false;

    public IPv4Analyser(PcapPacket packet) throws IOException {
        int ihl, ipProtocolNum;
        /*
         analyzing IPv4
         */

        ihl = packet.getByte(14) & 0x0F;
        if (ihl > 5) {
            ipHeaderOptionsLen = (ihl - 5) * 4;
        }
        ipProtocolNum = packet.getByte(23) & 0xFF;
        
        srcIpBA = packet.getByteArray(26, 4);
        dstIpBA = packet.getByteArray(30, 4);

        srcIp = Utils.ipByteArrayToString(srcIpBA);
        dstIp = Utils.ipByteArrayToString(dstIpBA);

        /*
         analyzing IPv4 protocol;
         */
        switch (ipProtocolNum) {
            case 1: {
                /*
                 ICMP Analyser
                 */
                icmpHeader = new IcmpAnalyser(packet, ipHeaderOptionsLen);
                icmpFound = true;
                break;
            }
            
            case 6: {
                /*
                 TCP Analyser
                 */
                //tcpUdpAnalyser = new TcpUdpAnalyser(packet, ipHeaderOptionsLen, "TCP");
                System.out.println("TCP");
                transportProtocolFound = true;
                break;
            }
            case 17: {
                /*
                 UDP Analyser
                 */
                System.out.println("UDP");
                tcpUdpAnalyser = new TcpUdpAnalyser(packet, ipHeaderOptionsLen, "UDP");
                transportProtocolFound = true;
                break;
            }
        
            default: {
                ipProtocol = "Other L4";
            }
        }
    }

    public byte[] getSrcIpBA() {
        return srcIpBA;
    }
    
    public byte[] getDstIpBA() {
        return dstIpBA;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public String getDstIp() {
        return dstIp;
    }

    public Integer getIpHeaderOptionsLen() {
        return ipHeaderOptionsLen;
    }    
   
    public IcmpAnalyser getIcmpHeader() {
        return icmpHeader;
    }

    public boolean isIcmpFound() {
        return icmpFound;
    }

    public boolean isTransportProtocolFound() {
        return transportProtocolFound;
    }

    public TcpUdpAnalyser getTcpUdpAnalyser() {
        return tcpUdpAnalyser;
    }

    public String getIpProtocol() {
        return ipProtocol;
    }

}
