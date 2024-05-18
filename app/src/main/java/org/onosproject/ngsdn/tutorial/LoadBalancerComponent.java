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
import org.onlab.packet.MacAddress;
import org.onlab.util.ItemNotFoundException;
import org.onosproject.core.ApplicationId;
import org.onosproject.mastership.MastershipService;
import org.onosproject.net.Device;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.config.NetworkConfigService;
import org.onosproject.net.device.DeviceEvent;
import org.onosproject.net.device.DeviceListener;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.group.GroupService;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.host.HostEvent.Type;
import org.onosproject.net.intf.InterfaceService;
import org.onosproject.net.link.LinkService;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiTableAction;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.onosproject.ngsdn.tutorial.common.FabricDeviceConfig;
import org.onosproject.ngsdn.tutorial.common.Utils;
import org.onosproject.ngsdn.tutorial.common.LoadBalancerConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.grpc.Server;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Map.Entry;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import static com.google.common.collect.Streams.stream;
import static org.onosproject.ngsdn.tutorial.AppConstants.INITIAL_SETUP_DELAY;

/**
 * App component that configures devices to provide IPv4 routing capabilities
 * across the whole fabric.
 */
@Component(
        immediate = true,
        // *** DONE EXERCISE 5
        // set to true when ready
        enabled = true
)
public class LoadBalancerComponent {

    private static final Logger log = LoggerFactory.getLogger(LoadBalancerComponent.class);

    private final HostListener hostListener = new InternalHostListener();
    private final DeviceListener deviceListener = new InternalDeviceListener();
    private final PacketProcessor packetProcessor = new InternalPacketProcessor();

    private ApplicationId appId;

    private HashMap<String, Float> serverCpuStorage;
    private HashMap<String, Float> serverLatencyStorage;
    private HashMap<String, ServerFlows> serverFlowsStorage;
    private HashMap<String, String> onlineServers;
    private List<FlowRule> currentFlowRules;
    private int currentPriority;

    private int FLOWS = 128;
    private double RATIO = 0.15;
    
    //Aux object
    class ServerFlows {
        public MacAddress mac;
        public Ip4Address ip;
        public String name;
        public int flows;
        public ServerFlows (String serverString, int flows){
            String[] serverSplit = serverString.split("/");
            this.mac = MacAddress.valueOf(serverSplit[0]);
            this.ip = Ip4Address.valueOf(serverSplit[1]);
            this.name = serverSplit[2];
            this.flows = flows;
        }
    }

    //--------------------------------------------------------------------------
    // ONOS CORE SERVICE BINDING
    //
    // These variables are set by the Karaf runtime environment before calling
    // the activate() method.
    //--------------------------------------------------------------------------

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MastershipService mastershipService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private GroupService groupService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private DeviceService deviceService;

    @Reference(cardinality =  ReferenceCardinality.MANDATORY)
    private PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private NetworkConfigService networkConfigService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private InterfaceService interfaceService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private LinkService linkService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    private MainComponent mainComponent;

    //--------------------------------------------------------------------------
    // COMPONENT ACTIVATION.
    //
    // When loading/unloading the app the Karaf runtime environment will call
    // activate()/deactivate().
    //--------------------------------------------------------------------------

    @Activate
    protected void activate() {
        appId = mainComponent.getAppId();

        serverCpuStorage = new HashMap<String, Float>();
        serverLatencyStorage = new HashMap<String, Float>();
        serverFlowsStorage = new HashMap<String, ServerFlows>();
        onlineServers = new HashMap<String, String>();
        currentFlowRules = new ArrayList<FlowRule>();
        currentPriority = 0;

        hostService.addListener(hostListener);
        deviceService.addListener(deviceListener);
        packetService.addProcessor(packetProcessor, 10);

        // Schedule set up for all devices.
        mainComponent.scheduleTask(this::setUpAllDevices, INITIAL_SETUP_DELAY);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        hostService.removeListener(hostListener);
        deviceService.removeListener(deviceListener);
        packetService.removeProcessor(packetProcessor);

        log.info("Stopped");
    }

    //one time setup for load balancer
    private void setupLoadBalancer(DeviceId deviceId){

        log.info("Adding Load Balancing Configurations to {} ...", deviceId);
        LoadBalancerConfig loadBalancerConfig = getLoadBalancerConfig(deviceId);

        //----
        //set special acl for load balancing controller packets
        PiCriterion controllerCriterion = PiCriterion.builder()
            .matchTernary(
                PiMatchFieldId.of("hdr.ethernet.dst_addr"),
                MacAddress.valueOf("00:aa:00:00:00:ff").toBytes(),
                MacAddress.valueOf("00:aa:00:00:00:ff").toBytes())
            .build();
        PiAction cloneToCpuAction = PiAction.builder()
            .withId(PiActionId.of("IngressPipeImpl.clone_to_cpu"))
            .build();
        FlowRule aclRule = Utils.buildFlowRule(
            deviceId, appId, "IngressPipeImpl.acl_table", controllerCriterion, cloneToCpuAction);

        //set Virtual Ip rule (10.0.0.1) - packet goes through load balancing if it has this IP
        PiCriterion myVirtualIpCriterion = PiCriterion.builder()
            .matchExact(
                PiMatchFieldId.of("hdr.ipv4.dst_addr"),
                loadBalancerConfig.myVirtualIp.toOctets())
            .build();
        PiTableAction noAction = PiAction.builder()
            .withId(PiActionId.of("NoAction"))
            .build();
        FlowRule myStationRule = Utils.buildFlowRule(
            deviceId, appId, "IngressPipeImpl.my_virtual_ip_table", myVirtualIpCriterion, noAction);

        //ARP entry for Virtual Ip
        PiCriterion arpCriterion = PiCriterion.builder()
            .matchExact(
                PiMatchFieldId.of("hdr.arp.protoDstAddr"), 
                loadBalancerConfig.myVirtualIp.toOctets())
            .build();
        PiActionParam arpActionParam = new PiActionParam(
            PiActionParamId.of("target_mac"), 
            loadBalancerConfig.myVirtualMac.toBytes());
        PiAction arpAction = PiAction.builder()
            .withId(PiActionId.of("IngressPipeImpl.arp_request_to_reply"))
            .withParameter(arpActionParam)
            .build();
        FlowRule arpRule = Utils.buildFlowRule(
            deviceId, appId, "IngressPipeImpl.arp_reply_table", arpCriterion, arpAction);

        //install all basic flow rules
        flowRuleService.applyFlowRules(aclRule, myStationRule, arpRule);
    }

    //create server unsetRule - 
    //rules for packets that go from server to host need to replace the server IP with the virtual IP
    private FlowRule createUnsetRule(DeviceId deviceId, String serverConfig){
        LoadBalancerConfig loadBalancerConfig = getLoadBalancerConfig(deviceId);

        PiCriterion unsetCriterion = PiCriterion.builder()
            .matchExact(
                    PiMatchFieldId.of("hdr.ipv4.src_addr"),
                    Ip4Address.valueOf(serverConfig.split("/")[1]).toOctets() )
            .build();
        List<PiActionParam> params = new LinkedList<PiActionParam>();
        params.add(new PiActionParam(
            PiActionParamId.of("mac"),
            loadBalancerConfig.myVirtualMac.toBytes()));
        params.add(new PiActionParam(
            PiActionParamId.of("ip"),
            loadBalancerConfig.myVirtualIp.toOctets()));
        PiTableAction unsetAction = PiAction.builder()
            .withId(PiActionId.of("IngressPipeImpl.unset_server"))
            .withParameters(params)
            .build();
        FlowRule unsetRule = Utils.buildFlowRule(
            deviceId, appId, "IngressPipeImpl.unset_server_table",
            unsetCriterion, unsetAction);
        
        return unsetRule;
    }

    //initial setup all serverFlows based only on online servers
    private void setupServerFlowsStorage(DeviceId deviceId){
        synchronized(serverFlowsStorage){
            int nServers = onlineServers.size();
            int nFlows = FLOWS / nServers;
    
            //clear serverFlowsStorage
            serverFlowsStorage.clear();
    
            //set initial server flows
            for (String serverConfig : onlineServers.values()){
                String serverName = serverConfig.split("/")[2];
                ServerFlows serverFlows = new ServerFlows(serverConfig, nFlows);
                serverFlowsStorage.put(serverName, serverFlows);
            }
    
            //apply flows
            applyServerFlowsStorage(deviceId);
        }
    }

    //pre-load onlineServers with serverConfig string
    private void serverOnline(Host host){
        String hostName = host.annotations().value("name");
        DeviceId deviceId = host.location().deviceId();
        LoadBalancerConfig loadBalancerConfig = getLoadBalancerConfig(deviceId);
        String serverConfig = loadBalancerConfig.servers.stream()
            .filter(config -> config.split("/")[2].equals(hostName))
            .findFirst().orElse(null);
        
        if (serverConfig == null){
            log.info("Server online without config: {}", hostName);
            return;
        }
        
        //save in onlineServers map
        onlineServers.put(hostName, serverConfig);

        //apply unset rule
        FlowRule unsetRule = createUnsetRule(deviceId, serverConfig);
        flowRuleService.applyFlowRules(unsetRule);

        //setup and apply ServerFlowsStorage
        setupServerFlowsStorage(deviceId);

        log.info("Server online: {}", hostName);
    }

    //remove offline servers
    private void serverOffline(Host host){
        String hostName = host.annotations().value("name");
        DeviceId deviceId = host.location().deviceId();
        LoadBalancerConfig loadBalancerConfig = getLoadBalancerConfig(deviceId);
        String serverConfig = loadBalancerConfig.servers.stream()
            .filter(config -> config.split("/")[2].equals(hostName))
            .findFirst().get();

        //remove from onlineServers map
        onlineServers.remove(hostName);

        //remove unset rule
        FlowRule unsetRule = createUnsetRule(deviceId, serverConfig);
        flowRuleService.removeFlowRules(unsetRule);

        //setup and apply ServerFlowsStorage
        setupServerFlowsStorage(deviceId);

        log.info("Server offline: {}", hostName);
    }

    //Install flow rules for servers
    public void applyServerFlowsStorage(DeviceId deviceId){
        int total = serverFlowsStorage.values().stream()
            .map(serverFlows -> serverFlows.flows)
            .reduce(0, (load1, load2) -> load1 + load2);
        // log.info("Install server flows, total: {}", Integer.toString(total));
        if (total > FLOWS){
            log.info("Total flows > {}, aborting...", FLOWS);
            return;
        }

        int i = 0;
        int start = 0;
        FlowRule[] rules = new FlowRule[serverFlowsStorage.size()];

        for (ServerFlows serverFlows : serverFlowsStorage.values()) {
            int end = start + serverFlows.flows - 1;
            if (end == (FLOWS - 2)) { end = (FLOWS - 1); serverFlows.flows++;} //special case for odd number of servers

            PiCriterion criterion = PiCriterion.builder()
                .matchRange(
                    PiMatchFieldId.of("local_metadata.next_server"),
                    start,
                    end )
                .build();
                
            List<PiActionParam> params = new LinkedList<PiActionParam>();
            params.add(new PiActionParam(
                PiActionParamId.of("mac"), 
                serverFlows.mac.toBytes()));
            params.add(new PiActionParam(
                PiActionParamId.of("ip"),
                serverFlows.ip.toOctets()));
            PiTableAction action = PiAction.builder()
                .withId(PiActionId.of("IngressPipeImpl.set_next_server"))
                .withParameters(params)
                .build();
            FlowRule flowRule = Utils.buildFlowRule(
                deviceId, appId, "IngressPipeImpl.load_balancer_table", criterion, action, currentPriority);
            
            log.info("Installing {} flows for {}", serverFlows.flows, serverFlows.name);
            rules[i] = flowRule;
            start = end + 1;
            i++;
        }

        //update priority
        if (currentPriority >= org.onosproject.net.flow.FlowRule.MAX_PRIORITY ) {
            currentPriority = 0;
        } else {
            currentPriority++;
        }
        //remove old rules
        flowRuleService.removeFlowRules(currentFlowRules.toArray(new FlowRule[0]));
        //save new rules
        currentFlowRules = new ArrayList<FlowRule>(Arrays.asList(rules));
        //apply new rules
        flowRuleService.applyFlowRules(rules);

    }

    //--------------------------------------------------------------------------
    // EVENT LISTENERS
    //
    // Events are processed only if isRelevant() returns true.
    //--------------------------------------------------------------------------

    /**
     * Listener of host events which triggers configuration of routing rules on
     * the device where the host is attached.
     */
    class InternalHostListener implements HostListener {

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

        @Override
        public void event(HostEvent event) {
            String hostName = event.subject().annotations().value("name");
            if (hostName != null && hostName.contains("server")){
                if (event.type() == Type.HOST_ADDED){
                    serverOnline(event.subject());
                } else if (event.type() == Type.HOST_REMOVED){
                    serverOffline(event.subject());
                }
            }
        }
    }

    /**
     * Listener of device events which triggers configuration of the My Station
     * table.
     */
    class InternalDeviceListener implements DeviceListener {

        @Override
        public boolean isRelevant(DeviceEvent event) {
            switch (event.type()) {
                case DEVICE_AVAILABILITY_CHANGED:
                case DEVICE_ADDED:
                    break;
                default:
                    return false;
            }
            // Process device event if this controller instance is the master
            // for the device and the device is available.
            DeviceId deviceId = event.subject().id();
            return mastershipService.isLocalMaster(deviceId) &&
                    deviceService.isAvailable(event.subject().id());
        }

        @Override
        public void event(DeviceEvent event) {
            mainComponent.getExecutorService().execute(() -> {
                DeviceId deviceId = event.subject().id();
                log.info("{} event! device id={}", event.type(), deviceId);
                setupLoadBalancer(deviceId);
            });
        }
    }

    class InternalPacketProcessor implements PacketProcessor {

        //TODO refactor to use the new flow rule algorithm
        //cpu load algorithm
        public void processCpu(DeviceId deviceId, String[] serverLoadArray) {
            float load = Float.parseFloat(serverLoadArray[2]);
            serverCpuStorage.put(serverLoadArray[0], load);

            if(onlineServers.size() == 0){
                log.info("No servers online");
                return;
            } else {
                for (String srv : onlineServers.keySet()) {
                    if (!serverCpuStorage.containsKey(srv)){
                        log.info("serverLoadStorage incomplete");
                        return; //storage does not contain all servers yet
                    }
                }
            }
            float totalLoad = serverCpuStorage.values().stream().reduce((float)0, Float::sum);
            if (totalLoad < 1){
                log.info("Not enough load");
                serverCpuStorage.clear();
                return;
            }

            List<String> roundRobin = new LinkedList<String>();
            for (String srv : serverCpuStorage.keySet()){
                float srvLoad = serverCpuStorage.get(srv);

                int weigth = serverCpuStorage.size() == 1 ? 16 :
                    (int) Math.ceil( (1.0 - (srvLoad / totalLoad)) * 16.0);
                for (int j = 0; j < weigth; j++){
                    roundRobin.add(onlineServers.get(srv));
                }
                log.info("Added {} flows to {}", weigth, srv);
            }

            // DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
            String tableId = "IngressPipeImpl.load_balancer_table";
            int k = 0;
            for (String srvConfig : roundRobin) {

                if (k >= 16) break;
                
                PiCriterion piCriterion = PiCriterion.builder()
                    .matchExact(
                        PiMatchFieldId.of("local_metadata.next_server"), 
                        k++ )
                    .build();
                
                // TODO change implementation to use 'range' key in P4
                
                List<PiActionParam> params = new LinkedList<PiActionParam>();
                params.add(new PiActionParam(
                    PiActionParamId.of("mac"), 
                    MacAddress.valueOf(srvConfig.split("/")[0]).toBytes()));
                params.add(new PiActionParam(
                    PiActionParamId.of("ip"),
                    Ip4Address.valueOf(srvConfig.split("/")[1]).toOctets()));
                PiTableAction piAction = PiAction.builder()
                    .withId(PiActionId.of("IngressPipeImpl.set_next_server"))
                    .withParameters(params)
                    .build();
                
                FlowRule flowRule = Utils.buildFlowRule(
                    deviceId, appId, tableId, piCriterion, piAction);
                
                flowRuleService.applyFlowRules(flowRule);
            }
            
            //delete storage
            serverCpuStorage.clear();

        }

        //reponse time algorithm
        public void processLatency(DeviceId deviceId, String[] serverLatencyArray){

            synchronized(serverLatencyStorage){
    
                String serverName = serverLatencyArray[0];
                float latency = Float.parseFloat(serverLatencyArray[2]); //avgLatency
                // float latency = Float.parseFloat(serverLatencyArray[3]); //sumLatency
    
                //update serverLatencyStorage
                serverLatencyStorage.put(serverName, latency);
    
                //error checking
                if(onlineServers.size() == 0){
                    log.info("No servers online");
                    return;
                } else if (onlineServers.size() == 1){
                    log.info("Only one server online");
                } else {
                    for (String srv : onlineServers.keySet()) {
                        if (!serverLatencyStorage.containsKey(srv)){
                            return; //storage does not contain all servers yet
                        }
                    }
                }
    
                //algorithm
                Entry<String, Float> maxLatency = serverLatencyStorage.entrySet().stream()
                    .max((entry1, entry2) -> entry1.getValue() > entry2.getValue() ? 1 : -1).get();
                Entry<String, Float> minLatency = serverLatencyStorage.entrySet().stream()
                    .min((entry1, entry2) -> entry1.getValue() > entry2.getValue() ? 1 : -1).get();
                
                float diff = Math.abs(maxLatency.getValue() / minLatency.getValue() -1);
                int maxLatencyFlows = serverFlowsStorage.get(maxLatency.getKey()).flows;
                
                if (maxLatencyFlows <= 2){
                    //entry cannot go below 2 flows
                    log.info("Flows at minimum of 2, aborting...");
                } else if (diff < RATIO){
                    //only update flows if they are at least RATIO different    
                    log.info("Similar values (<{}% diff), aborting...", RATIO*100);
                } else {

                    //remove one flow to max
                    serverFlowsStorage.get(maxLatency.getKey()).flows -= 1;
                    //add one flow to min
                    serverFlowsStorage.get(minLatency.getKey()).flows += 1;
        
                    //apply changes to serverFlowsStorage
                    applyServerFlowsStorage(deviceId);

                }

                //reset serverLatencyStorage
                serverLatencyStorage.clear();
            }

        }


        @Override
        public void process (PacketContext context){
            // log.info("Packet received!");
            MacAddress mac = context.inPacket().parsed().getDestinationMAC();
            MacAddress lbMac = MacAddress.valueOf("00:aa:00:00:00:ff");
            if (mac.equals(lbMac)) {
                synchronized (serverFlowsStorage){ //lock variable

                    ByteBuffer buffer = context.inPacket().unparsed().position(42); //body start position
                    int max = 128;
                    byte[] body = new byte[max];
                    int i = 0;
                    while (buffer.hasRemaining()){
                        if (i >= max){
                            log.warn("Exception avoided! i = {}", i);
                            break;
                        }
                        body[i++] = buffer.get(); //exception Index out of bounds here
                    }
                    String serverLoad = new String(body, StandardCharsets.UTF_8);
                    log.info("Server Load Packet: {}", serverLoad);
    
                    DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
                    String[] serverLoadArray = serverLoad.split(":");

                    //type of message
                    if (serverLoadArray[1].equals("latency")){
                        processLatency(deviceId, serverLoadArray);
                        return;
                    } else if (serverLoadArray[1].equals("cpu")){
                        processCpu(deviceId, serverLoadArray);
                        return;
                    } else {
                        log.info("Invalid command: {}", serverLoad);
                    }
                }
            }
        }
    }


    //--------------------------------------------------------------------------
    // UTILITY METHODS
    //--------------------------------------------------------------------------

    /**
     * Returns the FabricDeviceConfig config object for the given device.
     *
     * @param deviceId the device ID
     * @return FabricDeviceConfig device config
     */
    private Optional<FabricDeviceConfig> getDeviceConfig(DeviceId deviceId) {
        FabricDeviceConfig config = networkConfigService.getConfig(
                deviceId, FabricDeviceConfig.class);
        return Optional.ofNullable(config);
    }

    /**
     * Returns the Load Balancer Config object
     * 
     * @param deviceId the device ID
     * @return LoadBalancerConfig load balancer config
     */
    private LoadBalancerConfig getLoadBalancerConfig(DeviceId deviceId) {
        return getDeviceConfig(deviceId)
                .map(FabricDeviceConfig::loadBalancerConfig)
                .orElseThrow(() -> new ItemNotFoundException(
                        "Missing load balancer config for " + deviceId));
    }

    /**
     * Sets up IPv6 routing on all devices known by ONOS and for which this ONOS
     * node instance is currently master.
     */
    private synchronized void setUpAllDevices() {
        // Set up host routes
        stream(deviceService.getAvailableDevices())
                .map(Device::id)
                .filter(mastershipService::isLocalMaster)
                .forEach(deviceId -> {
                    log.info("*** Load Balancing - Starting initial set up for {}...", deviceId);
                    setupLoadBalancer(deviceId);
                    hostService.getConnectedHosts(deviceId).stream()
                        .filter(host -> host.annotations().value("name").contains("server"))
                        .forEach(host -> serverOnline(host));
                });
    }
}
