/*
 Autor: Martin Baňas
 Ročník: 2.
 Predmet: Počítačové a komunikačné siete
 Akademický rok: 2013/2014
 Semester: letný
 */
package sk.xbanasm.stuba.want.softwarerouter.packetanalyzer;

import org.jnetpcap.packet.PcapPacket;

public final class TcpUdpAnalyser {

    private final String transportProtocolName;
    private final int sourcePortNumber;
    private final int destinationPortNumber;

    private boolean ripFound = false;
    private boolean request = false;
    private int version;
    private int entriesCount;
    private int entriesOffset;

    public TcpUdpAnalyser(PcapPacket packet, int ipHeaderOptionsLen, String transportProtocolName) {
        this.transportProtocolName = transportProtocolName;

        sourcePortNumber = (packet.getByte(34 + ipHeaderOptionsLen) & 0xFF) * 256 + (packet.getByte(35 + ipHeaderOptionsLen) & 0xFF);
        destinationPortNumber = (packet.getByte(36 + ipHeaderOptionsLen) & 0xFF) * 256 + (packet.getByte(37 + ipHeaderOptionsLen) & 0xFF);

        //System.out.println(transportProtocolName + "\nsrc port: " + sourcePortNumber + "  dst port: " + destinationPortNumber);
        if (sourcePortNumber == 520) {                  
            if (packet.getUByte(42 + ipHeaderOptionsLen) == 1) {
                request = true;
            }
            version = packet.getUByte(43 + ipHeaderOptionsLen);
            if (version == 2) {
                ripFound = true;
            }
            entriesCount = (packet.size() - 46  - ipHeaderOptionsLen) / 20;
            entriesOffset = 46 + ipHeaderOptionsLen;
        }
    }

    public boolean isRipFound() {
        return ripFound;
    }

    public boolean isRequest() {
        return request;
    }

    public String getTransportProtocolName() {
        return transportProtocolName;
    }

    public int getEntriesCount() {
        return entriesCount;
    }

    public int getEntriesOffset() {
        return entriesOffset;
    }

}
