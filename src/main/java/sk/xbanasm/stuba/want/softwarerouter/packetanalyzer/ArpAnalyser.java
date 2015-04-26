/*
Autor: Martin Baňas
Ročník: 2.
Predmet: Počítačové a komunikačné siete
Akademický rok: 2013/2014
Semester: letný
*/

package sk.xbanasm.stuba.want.softwarerouter.packetanalyzer;

import java.net.UnknownHostException;
import org.jnetpcap.packet.PcapPacket;
import sk.xbanasm.stuba.want.softwarerouter.equip.Utils;

public class ArpAnalyser {
    private byte[] arpHeaderBA;
    
    private final int operation; 
    private boolean request = true;
    
    private byte[] senderHwAddrBA;
    private byte[] senderProtAddrBA;
    private byte[] targetHwAddrBA;
    private byte[] targetProtAddrBA;
    
    private String senderHwAddr;
    private String senderProtAddr;
    private String targetHwAddr;
    private String targetProtAddr;
               
    public ArpAnalyser(PcapPacket packet) throws UnknownHostException {   
        arpHeaderBA = packet.getByteArray(14, 6);
        operation = packet.getByte(21);
        if (operation == 2) {
            request = false;
        }
        
        senderHwAddrBA = packet.getByteArray(22, 6);
        senderProtAddrBA = packet.getByteArray(28, 4);
        targetHwAddrBA = packet.getByteArray(32, 6);
        targetProtAddrBA = packet.getByteArray(38, 4);
        
        senderHwAddr = Utils.macByteArrayToHexString(senderHwAddrBA);
        senderProtAddr = Utils.ipByteArrayToString(senderProtAddrBA);        
        targetHwAddr = Utils.macByteArrayToHexString(targetHwAddrBA);
        targetProtAddr = Utils.ipByteArrayToString(targetProtAddrBA);
    }

    public byte[] getArpHeaderBA() {
        return arpHeaderBA;
    }
    
    public int getOperation() {
        return operation;
    }

    public boolean isRequest() {
        return request;
    }

    public byte[] getSenderHwAddrBA() {
        return senderHwAddrBA;
    }

    public byte[] getSenderProtAddrBA() {
        return senderProtAddrBA;
    }

    public byte[] getTargetHwAddrBA() {
        return targetHwAddrBA;
    }

    public byte[] getTargetProtAddrBA() {
        return targetProtAddrBA;
    }        
    
    public String getSenderHardwareAddress() {
        return senderHwAddr.toString();
    }

    public String getSenderProtocolAddress() {
        return senderProtAddr.toString();
    }

    public String getTargetHardwareAddress() {
        return targetHwAddr.toString();
    }

    public String getTargetProtocolAddress() {
        return targetProtAddr.toString();
    }
}