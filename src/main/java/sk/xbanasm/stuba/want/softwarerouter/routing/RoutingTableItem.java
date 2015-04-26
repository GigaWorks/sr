package sk.xbanasm.stuba.want.softwarerouter.routing;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import sk.xbanasm.stuba.want.softwarerouter.equip.Utils;
import sk.xbanasm.stuba.want.softwarerouter.machine.Interface;

/**
 *
 * @author Martin Banas
 */
public class RoutingTableItem {

    protected RouteTypeEnum routeType;
    protected byte[] networkAddressBA;
    protected String networkAddress;
    protected byte[] maskBA;
    protected String mask;

    protected Integer administrativeDistance;

    private Interface outputInterface;
    private List<GatewayItem> gatewaysList = new CopyOnWriteArrayList<>();

    public RoutingTableItem(RouteTypeEnum routeType, byte[] ipAddress, byte[] subnetMask, Interface outputInterface, GatewayItem gateway) throws UnknownHostException {
        this.routeType = routeType;
        if (routeType.equals(RouteTypeEnum.CONNECTED)) {
            this.networkAddressBA = Utils.getNetworkAddress(ipAddress, subnetMask);
            this.networkAddress = Utils.ipByteArrayToString(this.networkAddressBA);
            this.outputInterface = outputInterface;
            this.administrativeDistance = 0;
        } else {
            this.networkAddressBA = ipAddress;
            this.networkAddress = Utils.ipByteArrayToString(this.networkAddressBA);
            this.gatewaysList.add(gateway);

            if (routeType.equals(RouteTypeEnum.STATIC)) {
                this.administrativeDistance = 1;
            } else {
                this.administrativeDistance = 120;
            }
        }

        this.maskBA = subnetMask;
        this.mask = Utils.ipByteArrayToString(maskBA);

    }

    public void addGateway(GatewayItem gateway) {       
        gatewaysList.add(gateway);
        System.out.println("brana: " + Utils.ipByteArrayToString(gateway.getIpAddress()) + "  metrika: " + gateway.getMetric());
        sortGateways();
        gatewaysList.get(0).setActive(true);
        for (int i = 1; i < gatewaysList.size(); i++) {
            gatewaysList.get(i).setActive(false);
        }
    }

    public void sortGateways() {
        List<GatewayItem> tempGatewaysList = new ArrayList<>(gatewaysList);
        Collections.sort(tempGatewaysList, new Comparator<GatewayItem>() {
            @Override
            public int compare(GatewayItem i1, GatewayItem i2) {
                return i1.getMetric().compareTo(i2.getMetric());
            }
        });
        gatewaysList = tempGatewaysList;
    }

    public GatewayItem getActiveGateway() {
        if (gatewaysList.get(0).isActive()) {
            return gatewaysList.get(0);
        } else {
            return null;
        }
    }

    public Interface getOutputInterface() {
        return outputInterface;
    }

    public List<GatewayItem> getGatewaysList() {
        return gatewaysList;
    }

    public RouteTypeEnum getRouteType() {
        return routeType;
    }

    public byte[] getNetworkAddressBA() {
        return networkAddressBA;
    }

    public String getNetworkAddress() {
        return networkAddress;
    }

    public byte[] getSubnetMaskBA() {
        return maskBA;
    }

    public String getMask() {
        return mask;
    }

    public byte[] getMaskBA() {
        return maskBA;
    }

    public Integer getAdministrativeDistance() {
        return administrativeDistance;
    }

}
