package sk.xbanasm.stuba.want.softwarerouter.routing;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import sk.xbanasm.stuba.want.softwarerouter.equip.Utils;
import sk.xbanasm.stuba.want.softwarerouter.machine.Interface;
import sk.xbanasm.stuba.want.softwarerouter.packetanalyzer.ReceivedPacket;

/**
 *
 * @author Martin Banas
 */
public class RoutingTable {

    private List<RoutingTableItem> routingTableList;

    public RoutingTable() {
        this.routingTableList = new CopyOnWriteArrayList<>();
    }

    //treba tu spravit thread na timer updejtu gatewaye
    public void addRoute(RouteTypeEnum routeType, byte[] ipAddress, byte[] subnetMask, Interface outputInterface, GatewayItem gateway) throws UnknownHostException {
        boolean foundRoute = false;
        boolean foundGateway = false;
        System.out.println("add route " + Utils.ipByteArrayToString(ipAddress) + " " + Utils.ipByteArrayToString(subnetMask) + " " + routeType);

        for (RoutingTableItem route : routingTableList) {
            if (!route.getRouteType().equals(RouteTypeEnum.CONNECTED) && Arrays.equals(route.getNetworkAddressBA(), ipAddress) && Arrays.equals(route.getMaskBA(), subnetMask)) {
                //toto je ten prefix, ktory si dostal
                route.setLastUpdate(new Date());

                for (GatewayItem gatewayItem : route.getGatewaysList()) {
                    if (Arrays.equals(gatewayItem.getIpAddress(), gateway.getIpAddress())) { //found same gateway
                        //toto je ta gateway, ktoru si dostal
                        foundGateway = true;

                        if (gateway.getMetric() > 15) { //poisoned route
                            if (route.getGatewaysList().size() == 1) {
                                route.setRouteState(RouteStateEnum.INVALID);
                                //TRIGGERED UPDATE NIGGA S POISONED ROUTOU
                            }
                            gateway.setActive(false);
                            gatewayItem.setMetric(gateway.getMetric());
                            route.sortGateways();
                        } else if (!gatewayItem.getMetric().equals(gateway.getMetric())) {
                            gatewayItem.setMetric(gateway.getMetric());
                            route.sortGateways();
                            //TRIGGERED UPDATE S 
                        }
                    }
                }
                if (!foundGateway) {
                    route.addGateway(gateway);
                    route.sortGateways();
                }

                return;
            }
        }

        routingTableList.add(new RoutingTableItem(routeType, ipAddress, subnetMask, outputInterface, gateway));
        sortRoutes();

        System.out.println("foundPrefix: " + foundRoute + "  foundGateway: " + foundGateway);
    }

    public byte[] getRoute(ReceivedPacket packet, byte[] dstIp) {
        //System.out.print("[GET ROUTE]");
        //System.out.println("  DEST IP: " + packet.getIpv4Header().getDstIp() + "  SRC IP: " + packet.getIpv4Header().getSrcIp());

        for (RoutingTableItem route : routingTableList) {
            System.out.println("Item: " + route.getNetworkAddress() + " " + route.getMask());
            System.out.println("network addresy: " + Utils.ipByteArrayToString(Utils.getNetworkAddress(dstIp, route.getSubnetMaskBA())) + " " + Utils.ipByteArrayToString(route.getNetworkAddressBA()));
            if (Arrays.equals(Utils.getNetworkAddress(dstIp, route.getSubnetMaskBA()), route.getNetworkAddressBA())) {
                //paket patri do podsiete tejto polozky routovacej tabulky                
                if (route.getRouteType().equals(RouteTypeEnum.CONNECTED)) {
                    //directly connected                                        
                    if (Arrays.equals(dstIp, route.getOutputInterface().getIpAddressBA())) {
                        //paket ma ako cielovu ip adresu interface routra, treba teda pozriet ci src ip je v routovacej tabulke  
                        System.out.println("Je to pre router, idem do rekurzie");
                        packet.setForRouter(true);
                        return getRoute(packet, packet.getIpv4Header().getSrcIpBA());
                    } else {
                        System.out.println("Neni to pre router, odchadza to do: " + route.getOutputInterface().getName() + " " + Utils.ipByteArrayToString(dstIp));
                        packet.setOutputInterface(route.getOutputInterface());
                        return dstIp;
                    }
                } else {
                    //nie je direct, cekni do ktoreho directly connected portu ide
                    for (RoutingTableItem gatewayItem : routingTableList) {
                        System.out.println("Gateway: " + gatewayItem.getNetworkAddress() + " " + gatewayItem.getMask() + " " + gatewayItem.getOutputInterface().getName());
                        if (gatewayItem.getRouteType().equals(RouteTypeEnum.CONNECTED) && Arrays.equals(Utils.getNetworkAddress(route.getActiveGateway().getIpAddress(), gatewayItem.getSubnetMaskBA()), gatewayItem.getNetworkAddressBA())) {
                            packet.setOutputInterface(gatewayItem.getOutputInterface());
                            System.out.println("Undirect output interface: " + gatewayItem.getOutputInterface().getName());
                            return route.getActiveGateway().getIpAddress();
                        }
                    }
                }
            }
        }
        System.out.println("Zvraciam null z getRoute");
        return null;
    }

    private void sortRoutes() {
        List<RoutingTableItem> tempRoutingTableList = new ArrayList<>(routingTableList);
        Collections.sort(tempRoutingTableList, new Comparator<RoutingTableItem>() {
            @Override
            public int compare(RoutingTableItem i1, RoutingTableItem i2) {
                Integer adCmp = i1.getAdministrativeDistance().compareTo(i2.getAdministrativeDistance());
                if (adCmp == 0) {
                    Integer netCmp = Utils.ipToLong(i1.getNetworkAddressBA()).compareTo(Utils.ipToLong(i2.getNetworkAddressBA()));
                    if (netCmp == 0) {
                        Integer maskCmp = Utils.ipToLong(i1.getMaskBA()).compareTo(Utils.ipToLong(i2.getMaskBA()));
                        return maskCmp;
                    } else {
                        return netCmp;
                    }
                } else {
                    return adCmp;
                }
            }
        });
        routingTableList = tempRoutingTableList;
    }

    public void removeConnectedRoute(Interface iface) {
        for (Iterator<RoutingTableItem> it = routingTableList.iterator(); it.hasNext();) {
            RoutingTableItem tableItem = it.next();
            if (tableItem.getRouteType().equals(RouteTypeEnum.CONNECTED) && tableItem.getOutputInterface().getName().equals(iface.getName())) {
                it.remove();
            }
        }
    }

    public List<RoutingTableItem> getRoutingTableList() {
        return routingTableList;
    }

    public void removeRoutes() {

    }
}
