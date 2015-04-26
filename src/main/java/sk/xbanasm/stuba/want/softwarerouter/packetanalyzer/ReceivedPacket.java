/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.xbanasm.stuba.want.softwarerouter.packetanalyzer;

import java.io.IOException;
import org.jnetpcap.packet.PcapPacket;
import sk.xbanasm.stuba.want.softwarerouter.equip.Utils;
import sk.xbanasm.stuba.want.softwarerouter.machine.Interface;

/**
 *
 * @author Martin Banas
 */
public class ReceivedPacket {

    private final Interface inputInterface;
    private final PcapPacket packet;
    private Interface outputInterface = null;

    private final String srcMac;
    private final String dstMac;
    
    private final byte[] srcMacBA;
    private final byte[] dstMacBA;

    private String etherTypeName = null;
    private Integer etherType;
    private byte[] etherTypeBA;    

    private boolean ipv4Found = false;
    private String internetLayerProtocol = null;
    private IPv4Analyser ipv4Header;   
    
    private boolean arpFound = false;
    private ArpAnalyser arpHeader;
    
    private boolean forRouter = false;

    public ReceivedPacket(Interface inputInterface, PcapPacket packet) throws IOException {
        this.inputInterface = inputInterface;
        this.packet = packet;

        dstMacBA = packet.getByteArray(0, 6);
        srcMacBA = packet.getByteArray(6, 6);
        
        dstMac = Utils.macByteArrayToHexString(dstMacBA);
        srcMac = Utils.macByteArrayToHexString(srcMacBA);                

        //rozoberaj pakety
        packetAnalyze();
    }

    private void packetAnalyze() throws IOException {
        /*
         parse ether type
         */
        etherTypeBA = packet.getByteArray(12, 2);
        
        etherType = ((packet.getByte(12) & 0xff) * 256) | (packet.getByte(13) & 0xff);
        if (etherType >= 1536) {
            etherTypeName = "Ethernet II";

            //internetLayerProtocol = Utils.getDataFromExternFile(etherType, "ethertypes");
            switch (etherType) {
                case 2048: {
                    ipv4Found = true;
                    ipv4Header = new IPv4Analyser(packet);
                    break;
                }
                case 2054: {
                    arpFound = true;
                    arpHeader = new ArpAnalyser(packet);
                    break;
                }
                default: {
                    internetLayerProtocol = "Other L3";
                }
            }

        } else if (etherType <= 1500) {
            String payload2StartBytes;

            payload2StartBytes = Utils.macByteArrayToHexString(packet.getByteArray(14, 2));

            switch (payload2StartBytes) {
                case "FF:FF":
                    etherTypeName = "IEEE 802.3 – Raw";
                    break;
                case "AA:AA":
                    etherTypeName = "IEEE 802.2 - SNAP";
                    break;
                default:
                    etherTypeName = "IEEE 802.2 LLC";
                    break;
            }
        } else {
            etherTypeName = "Other L2";
        }
    }

    public void setForRouter(boolean forRouter) {
        this.forRouter = forRouter;
    }

    public boolean isForRouter() {
        return forRouter;
    }
    
    public Interface getInputInterface() {
        return inputInterface;
    }
    
    public Interface getOutputInterface() {
        return outputInterface;
    }
    
    public void setOutputInterface(Interface outputInterface) {
        this.outputInterface = outputInterface;
    }

    public PcapPacket getPacket() {
        return packet;
    }

    public String getDstMac() {
        return dstMac;
    }

    public String getSrcMac() {
        return srcMac;
    }

    public byte[] getDstMacBA() {
        return dstMacBA;
    }

    public byte[] getSrcMacBA() {
        return srcMacBA;
    }

    public Integer getEtherType() {
        return etherType;
    }        

    public byte[] getPacketByteArray() {
        return packet.getByteArray(0, packet.size());
    }

    public String getEtherTypeName() {
        return etherTypeName;
    }

    public byte[] getEtherTypeBA() {
        return etherTypeBA;
    }    

    public boolean isIpv4Found() {
        return ipv4Found;
    }    

    public IPv4Analyser getIpv4Header() {
        return ipv4Header;
    }
    
    public String getInternetLayerProtocol() {
        return internetLayerProtocol;
    }

    public boolean isArpFound() {
        return arpFound;
    }

    public ArpAnalyser getArpHeader() {
        return arpHeader;
    }

    
}
