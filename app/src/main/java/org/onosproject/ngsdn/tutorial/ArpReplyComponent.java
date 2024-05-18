/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.onosproject.ngsdn.tutorial;

import org.onlab.packet.Ip4Address;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.util.ItemNotFoundException;
import org.onosproject.core.ApplicationId;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleOperations;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.Host;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.host.InterfaceIpAddress;
import org.onosproject.net.intf.Interface;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.ngsdn.tutorial.common.FabricDeviceConfig;
import org.onosproject.ngsdn.tutorial.common.Utils;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.onosproject.ngsdn.tutorial.AppConstants.INITIAL_SETUP_DELAY;

/**
 * App component that configures devices to generate NDP Neighbor Advertisement
 * packets for all interface IPv6 addresses configured in the netcfg.
 */
@Component(
        immediate = true,
        // *** DONE EXERCISE 5
        // Enable component (enabled = true)
        enabled = true
)
public class ArpReplyComponent {

    private static final Logger log =
            LoggerFactory.getLogger(ArpReplyComponent.class.getName());

    //--------------------------------------------------------------------------
    // ONOS CORE SERVICE BINDING
    //
    // These variables are set by the Karaf runtime environment before calling
    // the activate() method.
    //--------------------------------------------------------------------------

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigService configService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MainComponent mainComponent;

    private DeviceListener deviceListener = new InternalDeviceListener();
    private HostListener hostListener = new InternatlHostListener();
    private ApplicationId appId;

    //--------------------------------------------------------------------------
    // COMPONENT ACTIVATION.
    //
    // When loading/unloading the app the Karaf runtime environment will call
    // activate()/deactivate().
    //--------------------------------------------------------------------------

    @Activate
    public void activate() {
        appId = mainComponent.getAppId();
        // Register listeners to be informed about device events.
        deviceService.addListener(deviceListener);
        hostService.addListener(hostListener);
        // Schedule set up of existing devices. Needed when reloading the app.
        mainComponent.scheduleTask(this::setUpAllDevices, INITIAL_SETUP_DELAY);
        // Schedule set up of existing hosts. Needed when reloading the app.
        mainComponent.scheduleTask(this::setUpAllHosts, INITIAL_SETUP_DELAY);
        log.info("Started");
    }

    @Deactivate
    public void deactivate() {
        deviceService.removeListener(deviceListener);
        hostService.removeListener(hostListener);
        log.info("Stopped");
    }

    //--------------------------------------------------------------------------
    // METHODS TO COMPLETE.
    //
    // Complete the implementation wherever you see TODO.
    //--------------------------------------------------------------------------

    /**
     * Set up all devices for which this ONOS instance is currently master.
     */
    private void setUpAllDevices() {
        deviceService.getAvailableDevices().forEach(device -> {
            if (mastershipService.isLocalMaster(device.id())) {
                log.info("*** ARP REPLY - Starting Initial set up for {}...", device.id());
                setUpDevice(device.id());
            }
        });
    }

    /**
     * Performs setup of the given device by creating a flow rule to generate
     * ARP Reply packets for IPv4 addresses associated to the device interfaces.
     *
     * @param deviceId device ID
     */
    private void setUpDevice(DeviceId deviceId) {

        // Get this device config from netcfg.json.
        final FabricDeviceConfig config = configService.getConfig(
                deviceId, FabricDeviceConfig.class);
        if (config == null) {
            // Config not available yet
            throw new ItemNotFoundException("Missing fabricDeviceConfig for " + deviceId);
        }

        // Get this device myStation mac.
        final MacAddress deviceMac = config.myStationMac();

        // Get all interfaces currently configured for the device
        final Collection<Interface> interfaces = interfaceService.getInterfaces()
                .stream()
                .filter(iface -> iface.connectPoint().deviceId().equals(deviceId))
                .collect(Collectors.toSet());

        if (interfaces.isEmpty()) {
            log.info("{} does not have any IPv4 interface configured",
                     deviceId);
            return;
        }

        // Generate and install flow rules.
        log.info("Adding rules to {} to generate ARP REPLY for {} IPv4 interfaces...",
                 deviceId, interfaces.size());
        
        // TODO: replace interface approach
        // Get list of IPs
        final Collection<Ip4Address> ip4Addresses = interfaces.stream()
                .map(this::getIp4Addresses)
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());

        // Get list of switches
        final Collection<DeviceId> devices = StreamSupport
            .stream(deviceService.getAvailableDevices().spliterator(), false)
            .map(Device::id)
            .collect(Collectors.toSet());
        
        log.info("Adding ARP rules for device {} in [{}]", deviceId, devices);

        // Create flowRules for each switch
        Collection<FlowRule> flowRules = new ArrayList<FlowRule>();
        
        for (DeviceId device : devices) {

            flowRules.addAll( ip4Addresses.stream()
                .map(ipv4addr -> buildArpReplyFlowRule(device, ipv4addr, deviceMac))
                .collect(Collectors.toSet()) );
            
        }

        installRules(flowRules);   
    }

    /**
     * Set up all hosts for which this ONOS instance is currently master.
     */
    private void setUpAllHosts() {
        hostService.getHosts().forEach(host -> {
            if (mastershipService.isLocalMaster(host.location().deviceId())) {
                log.info("*** ARP REPLY - Starting Initial set up for {}...", host.id());
                setUpHost(host);
            }
        });
    }

    /**
     * Performs setup of the given device by creating a flow rule to generate
     * ARP Reply packets for IPv4 addresses associated to the host interface.
     * 
     * @param host host
     */
    private void setUpHost(Host host) {

        // Get IPv4
        final Collection<Ip4Address> hostIpv4Addrs = host.ipAddresses().stream()
            .filter(IpAddress::isIp4)
            .map(IpAddress::getIp4Address)
            .collect(Collectors.toSet());
        
        if (hostIpv4Addrs.isEmpty()) {
            // Ignore.
            log.debug("No IPv4 addresses for host {}, ignore", host.id());
            return;
        } else {
            log.info("Adding ARP routes on all devices for host {} [{}]",
                    host.id(), hostIpv4Addrs);
        }

        // first IPv4
        final Ip4Address hostIp = hostIpv4Addrs.iterator().next();

        //get MAC
        final MacAddress hostMac = host.mac();

        //get all devices and create flow rules
        final Collection<FlowRule> flowRules = StreamSupport
            .stream(deviceService.getAvailableDevices().spliterator(), false)
            .map(Device::id)
            .map(id -> buildArpReplyFlowRule(id, hostIp, hostMac))
            .collect(Collectors.toSet());
        
        installRules(flowRules);
    }

    private void removeHost(Host host){

        // Get IPv4
        final Collection<Ip4Address> hostIpv4Addrs = host.ipAddresses().stream()
            .filter(IpAddress::isIp4)
            .map(IpAddress::getIp4Address)
            .collect(Collectors.toSet());
        
        if (hostIpv4Addrs.isEmpty()) {
            // Ignore.
            log.debug("No IPv4 addresses for host {}, ignore", host.id());
            return;
        } else {
            log.info("Removing ARP routes on all devices for host {} [{}]",
                    host.id(), hostIpv4Addrs);
        }

        // first IPv4
        final Ip4Address hostIp = hostIpv4Addrs.iterator().next();

        //get MAC
        final MacAddress hostMac = host.mac();

        //get all devices and create flow rules
        final Collection<FlowRule> flowRules = StreamSupport
            .stream(deviceService.getAvailableDevices().spliterator(), false)
            .map(Device::id)
            .map(id -> buildArpReplyFlowRule(id, hostIp, hostMac))
            .collect(Collectors.toSet());
        
        removeRules(flowRules);
}

    /**
     * Build a flow rule for the NDP reply table on the given device, for the
     * given target IPv6 address and MAC address.
     *
     * @param deviceId          device ID where to install the flow rules
     * @param targetIpv6Address target IPv6 address
     * @param targetMac         target MAC address
     * @return flow rule object
     */
    private FlowRule buildArpReplyFlowRule(DeviceId deviceId,
                                           Ip4Address targetIpv4Address,
                                           MacAddress targetMac) {

        // *** DONE EXERCISE 5
        // Modify P4Runtime entity names to match content of P4Info file (look
        // for the fully qualified name of tables, match fields, and actions.
        // ---- START SOLUTION ----
        // Build match.
        final PiCriterion match = PiCriterion.builder()
                .matchExact(PiMatchFieldId.of("hdr.arp.protoDstAddr"), targetIpv4Address.toOctets())
                .build();
        // Build action.
        final PiActionParam targetMacParam = new PiActionParam(
                PiActionParamId.of("target_mac"), targetMac.toBytes());
        final PiAction action = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.arp_request_to_reply"))
                .withParameter(targetMacParam)
                .build();
        // Table ID.
        final String tableId = "IngressPipeImpl.arp_reply_table";
        // ---- END SOLUTION ----

        // Build flow rule.
        final FlowRule rule = Utils.buildFlowRule(
                deviceId, appId, tableId, match, action);

        return rule;
    }

    //--------------------------------------------------------------------------
    // EVENT LISTENERS
    //
    // Events are processed only if isRelevant() returns true.
    //--------------------------------------------------------------------------

    /**
     * Listener of device events.
     */
    public class InternalDeviceListener implements DeviceListener {

        @Override
        public boolean isRelevant(DeviceEvent event) {
            switch (event.type()) {
                case DEVICE_ADDED:
                case DEVICE_AVAILABILITY_CHANGED:
                    break;
                default:
                    // Ignore other events.
                    return false;
            }
            // Process only if this controller instance is the master.
            final DeviceId deviceId = event.subject().id();
            return mastershipService.isLocalMaster(deviceId);
        }

        @Override
        public void event(DeviceEvent event) {
            final DeviceId deviceId = event.subject().id();
            if (deviceService.isAvailable(deviceId)) {
                // A P4Runtime device is considered available in ONOS when there
                // is a StreamChannel session open and the pipeline
                // configuration has been set.

                // Events are processed using a thread pool defined in the
                // MainComponent.
                mainComponent.getExecutorService().execute(() -> {
                    log.info("{} event! deviceId={}", event.type(), deviceId);
                    setUpDevice(deviceId);
                });
            }
        }
    }

    /**
     * Listener of host events.
     */
    public class InternatlHostListener implements HostListener {

        @Override
        public boolean isRelevant(HostEvent event) {
            switch (event.type()) {
                case HOST_ADDED:
                case HOST_REMOVED:
                    break;
                case HOST_UPDATED:
                case HOST_MOVED:
                default:
                    // Ignore other events.
                    // Food for thoughts:
                    // how to support host moved/removed events?
                    return false;
            }
            // Process host event only if this controller instance is the master
            // for the device where this host is attached.
            final Host host = event.subject();
            final DeviceId deviceId = host.location().deviceId();
            return mastershipService.isLocalMaster(deviceId);
        }

        //example https://github.com/opennetworkinglab/onos/blob/2b4de873e4033b7973b399d25cb8828a73bc2e24/web/gui/src/main/java/org/onosproject/ui/impl/topo/model/UiSharedTopologyModel.java#L491
        @Override
        public void event(HostEvent event) {
            //load ARP to all devices
            Host host = event.subject();
            mainComponent.getExecutorService().execute(() -> {
                log.info("{} event! host={}",
                    event.type(), host.id());
                
                switch(event.type()){

                    case HOST_ADDED:
                        setUpHost(host);
                        break;

                    case HOST_REMOVED:
                        removeHost(host);
                        break;

                    // TODO: HOST_UPDATED, HOST_MOVED
                    default:
                        break;
                }
            });
        }

    }

    //--------------------------------------------------------------------------
    // UTILITY METHODS
    //--------------------------------------------------------------------------

    /**
     * Returns all IPv6 addresses associated with the given interface.
     *
     * @param iface interface instance
     * @return collection of IPv6 addresses
     */
    private Collection<Ip4Address> getIp4Addresses(Interface iface) {
        return iface.ipAddressesList()
                .stream()
                .map(InterfaceIpAddress::ipAddress)
                .filter(IpAddress::isIp4)
                .map(IpAddress::getIp4Address)
                .collect(Collectors.toSet());
    }

    /**
     * Install the given flow rules in batch using the flow rule service.
     *
     * @param flowRules flow rules to install
     */
    private void installRules(Collection<FlowRule> flowRules) {
        FlowRuleOperations.Builder ops = FlowRuleOperations.builder();
        flowRules.forEach(ops::add);
        flowRuleService.apply(ops.build());
    }

    /**
     * Removes the given flow rules in batch using the flow rule service.
     *
     * @param flowRules flow rules to remove
     */
    private void removeRules(Collection<FlowRule> flowRules) {
        flowRuleService.removeFlowRules(flowRules.toArray(new FlowRule[flowRules.size()]));
    }
}
