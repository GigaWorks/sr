package sk.xbanasm.stuba.want.softwarerouter.forwarding;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Queue;
import java.util.logging.Level;
import java.util.logging.Logger;
import sk.xbanasm.stuba.want.softwarerouter.machine.Interface;
import sk.xbanasm.stuba.want.softwarerouter.packetanalyzer.ReceivedPacket;

/**
 *
 * @author Martin Banas
 */
public class ArpTable implements Runnable {

    private List<ArpTableItem> arpTable = new ArrayList<>();
    private Queue<ReceivedPacket> receivedArpPacketsQueue;
    private ReceivedPacket arpPacket;

    private final byte[] broadcastMac = new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
    private final byte[] zeroMac = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};

    public ArpTable(Queue<ReceivedPacket> receivedArpPacketsQueue) {
        this.receivedArpPacketsQueue = receivedArpPacketsQueue;
    }

    @Override
    public void run() {
        Date actualDate;
        while (true) {
            while (!receivedArpPacketsQueue.isEmpty()) {
                arpPacket = receivedArpPacketsQueue.poll();                
                //najprf cekni ci je to arp request
                if (arpPacket.getArpHeader().isRequest()) {
                    //prisiel arp request a teda vytvor reply
                    sendArpReply(arpPacket);
                } else {
                    // prisiel reply..cekni ci je to on ten spravny na spravny request
                    checkArpReply(arpPacket);
                }
            }

            for (Iterator<ArpTableItem> it = arpTable.iterator(); it.hasNext();) {
                ArpTableItem tableItem = it.next();
                actualDate = new Date();
                if (tableItem.getLastActivity().getTime() < actualDate.getTime() - 60000) {
                    it.remove();
                }
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException ex) {
                Logger.getLogger(ArpTable.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public byte[] getDestMacAddress(byte[] internetAddress, Interface iface) throws UnknownHostException {
        byte[] foundMac = checkArpTable(internetAddress, iface);

        if (foundMac == null) {
            ArpTableItem item = new ArpTableItem(internetAddress, iface, false);
            arpTable.add(item);
            sendArpRequest(internetAddress, iface);
            synchronized (item.getArpItemUpdateLock()) {
                try {
                    item.getArpItemUpdateLock().wait(2000);                    
                } catch (InterruptedException ex) {
                    Logger.getLogger(ArpTable.class
                            .getName()).log(Level.SEVERE, null, ex);
                }
            }
            foundMac = checkArpTable(internetAddress, iface);
        }
        return foundMac;
    }
    
    private byte[] checkArpTable(byte[] internetAddress, Interface iface) {
        boolean changedPort = false;
        byte[] foundMac = null;

        for (ArpTableItem item : arpTable) {
            if (item.isResolved() && Arrays.equals(item.getIpAddressBA(), internetAddress) && item.getInterface().equals(iface)) {
                //found the same item in arp table...update activity
                item.updateItemActivity();
                foundMac = item.getMacAddressBA();
            }
            /*
            } else if (item.getMacAddressBA() != null && Arrays.equals(item.getIpAddressBA(), internetAddress) && item.getPort().equals(port) && Arrays.equals(item.getMacAddressBA(), packet.getSrcMacBA()) && !item.getPort().equals(packet.getSourcePort())) {              
                //the port has changed...flush the arp table
                changedPort = true;
            } else {
                //arpTable.add(new ArpTableItem(packet.getArpHeader().getSenderProtAddrBA(), packet.getArpHeader().getSenderHwAddrBA(), packet.getSourcePort()));
            }
            */
        }
        if (changedPort) {
            arpTable.clear();
        }
        return foundMac;
    }

    public void sendArpRequest(byte[] internetAddress, Interface iface) {
        byte[] packetBA = new byte[42];
        //dst mac
        System.arraycopy(broadcastMac, 0, packetBA, 0, 6);
        //src mac
        System.arraycopy(iface.getMacAddressBA(), 0, packetBA, 6, 6);
        //ethertype = ARP
        System.arraycopy(new byte[]{(byte) 0x08, (byte) 0x06}, 0, packetBA, 12, 2);
        //hardware type
        System.arraycopy(new byte[]{(byte) 0x00, (byte) 0x01}, 0, packetBA, 14, 2);
        //protocol type
        System.arraycopy(new byte[]{(byte) 0x08, (byte) 0x00}, 0, packetBA, 16, 2);
        //hardware add length, protocol add length
        System.arraycopy(new byte[]{(byte) 0x06, (byte) 0x04}, 0, packetBA, 18, 2);
        //opcode
        packetBA[20] = 0;
        packetBA[21] = 1;
        //SHA
        System.arraycopy(iface.getMacAddressBA(), 0, packetBA, 22, 6);
        //SPA
        System.arraycopy(iface.getIpAddressBA(), 0, packetBA, 28, 4);
        //THA
        System.arraycopy(zeroMac, 0, packetBA, 32, 6);
        //TPA
        System.arraycopy(internetAddress, 0, packetBA, 38, 4);
        
        iface.sendPacket(packetBA);
    }

    public void sendArpReply(ReceivedPacket packet) {
        byte[] packetBA = new byte[42];

        //arpTable.add(new ArpTableItem(packet.getArpHeader().getSenderProtAddrBA(), packet.getArpHeader().getSenderHwAddrBA(), packet.getSourcePort()));
        //dst mac
        System.arraycopy(packet.getArpHeader().getSenderHwAddrBA(), 0, packetBA, 0, 6);
        //src mac
        System.arraycopy(packet.getInputInterface().getMacAddressBA(), 0, packetBA, 6, 6);
        //ethertype
        System.arraycopy(packet.getEtherTypeBA(), 0, packetBA, 12, 2);
        //arp header
        System.arraycopy(packet.getArpHeader().getArpHeaderBA(), 0, packetBA, 14, 6);
        //opcode
        packetBA[20] = 0;
        packetBA[21] = 2;
        //SHA
        System.arraycopy(packet.getInputInterface().getMacAddressBA(), 0, packetBA, 22, 6);
        //SPA
        System.arraycopy(packet.getInputInterface().getIpAddressBA(), 0, packetBA, 28, 4);
        //THA
        System.arraycopy(packet.getArpHeader().getSenderHwAddrBA(), 0, packetBA, 32, 6);
        //TPA
        System.arraycopy(packet.getArpHeader().getSenderProtAddrBA(), 0, packetBA, 38, 4);

        packet.getInputInterface().sendPacket(packetBA);
    }

    public void checkArpReply(ReceivedPacket packet) {
        //musi sediet dst ip, dst mac routra a src 
        for (ArpTableItem item : arpTable) {
            if (Arrays.equals(item.getIpAddressBA(), packet.getArpHeader().getSenderProtAddrBA()) && item.getInterface().getName().equals(packet.getInputInterface().getName())) {
                //System.out.println("ARP resolved: " + Utils.ipByteArrayToString(item.getIpAddressBA()));
                item.setMacAddress(packet.getSrcMacBA());
                item.setResolved();
                break;
            }
        }
    }

    public void addItem(ArpTableItem item) {
        arpTable.add(item);
    }

    public List<ArpTableItem> getArpTableList() {
        return arpTable;
    }
    
    public void wipeArpTable() {
        arpTable.clear();
    }
}
