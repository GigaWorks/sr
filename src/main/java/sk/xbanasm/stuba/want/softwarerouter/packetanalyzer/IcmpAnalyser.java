/*
Autor: Martin Baňas
Ročník: 2.
Predmet: Počítačové a komunikačné siete
Akademický rok: 2013/2014
Semester: letný
*/

package sk.xbanasm.stuba.want.softwarerouter.packetanalyzer;

import org.jnetpcap.packet.PcapPacket;

public class IcmpAnalyser {
    private int icmpType;
    private String icmpMessage;
    
    public IcmpAnalyser(PcapPacket packet, int ipHeaderOptionsLen) {        
        icmpType = packet.getByte(34 + ipHeaderOptionsLen) & 0xff;
        switch (icmpType) {
            case 0: {
                icmpMessage = "Echo Reply";
                break;
            }
            case 3: {
                icmpMessage = icmpType + " - Destination Unreachable";
                break;
            }
            case 4: {
                icmpMessage = icmpType + " - Source Quench";
                break;
            }
            case 5: {
                icmpMessage = icmpType + " - Redirect Message";
                break;
            }
            case 8: {
                icmpMessage = "Echo Request";
                break;
            }
            case 9: {
                icmpMessage = icmpType + " - Router Advertisement";
                break;
            }
            case 10: {
                icmpMessage = icmpType + " - Router Solicitation";
                break;
            }
            case 11: {
                icmpMessage = icmpType + " - Time Exceeded";
                break;
            }
            case 12: {
                icmpMessage = icmpType + " - Parameter Problem: Bad IP header";
                break;
            }
            case 13: {
                icmpMessage = icmpType + " - Timestamp";
                break;
            }
            case 14: {
                icmpMessage = icmpType + " – Timestamp Reply";
                break;
            }
            case 15: {
                icmpMessage = icmpType + " – Information Request";
                break;
            }
            case 16: {
                icmpMessage = icmpType + " – Information Reply";
                break;
            }
            case 17: {
                icmpMessage = icmpType + " – Address Mask Request";
                break;
            }
            case 18: {
                icmpMessage = icmpType + " – Address Mask Reply";
                break;
            }
            case 30: {
                icmpMessage = icmpType + " – Traceroute";
                break;
            }
        }
    }

    public String getIcmpMessage() {
        return icmpMessage;
    }
}