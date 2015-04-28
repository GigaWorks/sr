package sk.xbanasm.stuba.want.softwarerouter.gui;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.table.DefaultTableModel;
import sk.xbanasm.stuba.want.softwarerouter.equip.Utils;
import sk.xbanasm.stuba.want.softwarerouter.forwarding.ArpTableItem;
import sk.xbanasm.stuba.want.softwarerouter.routing.RoutingTableItem;
import sk.xbanasm.stuba.want.softwarerouter.machine.Interface;
import sk.xbanasm.stuba.want.softwarerouter.machine.Router;
import sk.xbanasm.stuba.want.softwarerouter.routing.GatewayItem;
import sk.xbanasm.stuba.want.softwarerouter.routing.RouteTypeEnum;

/**
 *
 * @author Martin Banas
 */
public class RouterGuiUpdater implements Runnable {

    private RouterGui routerGui;
    private Router router;

    public RouterGuiUpdater(RouterGui routerGui, Router router) {
        this.routerGui = routerGui;
        this.router = router;
    }

    @Override
    public void run() {
        while (true) {
            fillArpTable();
            //fillipRouteTable();
            try {
                Thread.sleep(100);
            } catch (InterruptedException ex) {
                Logger.getLogger(RouterGuiUpdater.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public void fillInterfacesTable() {
        Integer rowNumber = 1;
        String[] tableData = new String[5];

        DefaultTableModel portsTableModel = (DefaultTableModel) routerGui.getInterfacesTable().getModel();
        portsTableModel.setRowCount(0);

        for (Interface iface : router.getInterfaces()) {
            tableData[0] = rowNumber.toString();
            tableData[1] = iface.getName();
            tableData[2] = iface.getStatus();
            tableData[3] = iface.getIpAddress();
            tableData[4] = iface.getSubnetMask();

            portsTableModel.addRow(tableData);
            rowNumber++;
        }
    }

    public void fillArpTable() {
        Integer rowNumber = 1;
        String[] tableData = new String[4];

        DefaultTableModel arpTableModel = (DefaultTableModel) routerGui.getArpTable().getModel();
        arpTableModel.setRowCount(0);

        for (ArpTableItem item : router.getForwarder().getArpTable().getArpTableList()) {
            if (item.isResolved()) {
                tableData[0] = rowNumber.toString();
                tableData[1] = item.getIpAddress();
                tableData[2] = item.getMacAddress();
                tableData[3] = item.getInterface().getName();

                arpTableModel.addRow(tableData);
                rowNumber++;
            }
        }
    }

    public void fillipRouteTable() {
        Integer rowNumber = 1;
        String[] tableData = new String[6];
        List<GatewayItem> gatewaysList;

        DefaultTableModel ipRouteTableModel = (DefaultTableModel) routerGui.getIpRouteTable().getModel();
        ipRouteTableModel.setRowCount(0);

        for (RoutingTableItem item : router.getRoutingTable().getRoutingTableList()) {
            tableData[0] = rowNumber.toString();
            tableData[1] = item.getRouteType().toString();
            tableData[2] = item.getNetworkAddress();
            tableData[3] = item.getMask();
            if (item.getRouteType().equals(RouteTypeEnum.CONNECTED)) {
                tableData[4] = item.getOutputInterface().getName();
                ipRouteTableModel.addRow(tableData);
            } else {
                gatewaysList = item.getGatewaysList();
                tableData[4] = Utils.ipByteArrayToString(gatewaysList.get(0).getIpAddress()) + " " + (gatewaysList.get(0).isActive() ? " A" : " P");
                tableData[5] = item.getAdministrativeDistance().toString() + "/" + (gatewaysList.isEmpty() ? "-" : gatewaysList.get(0).getMetric().toString());

                ipRouteTableModel.addRow(tableData);

                tableData[0] = "";
                tableData[1] = "";
                tableData[2] = "";
                tableData[3] = "";
                for (int i = 1; i < gatewaysList.size(); i++) {
                    tableData[4] = Utils.ipByteArrayToString(gatewaysList.get(i).getIpAddress()) + " " + (gatewaysList.get(i).isActive() ? " A" : " P");
                    tableData[5] = item.getAdministrativeDistance().toString() + "/" + gatewaysList.get(i).getMetric().toString();
                    ipRouteTableModel.addRow(tableData);
                }
            }
            rowNumber++;
        }
    }

    public void fillActiveDynamicNetworksTable() {
        Integer rowNumber = 1;
        String[] tableData = new String[3];

        DefaultTableModel activeDynamicNetworksTable = (DefaultTableModel) routerGui.getActiveDynamicNetworksTable().getModel();
        activeDynamicNetworksTable.setRowCount(0);

        for (Interface item : router.getRipManager().getActiveRipIfacesList()) {
                tableData[0] = rowNumber.toString();
                tableData[1] = Utils.ipByteArrayToString(Utils.getNetworkAddress(item.getIpAddressBA(), item.getSubnetMaskBA()));
                tableData[2] = item.getName();

                activeDynamicNetworksTable.addRow(tableData);
                rowNumber++;
            
        }
    }
}
