package org.onosproject.ngsdn.tutorial.common;

import java.util.List;
import java.util.ArrayList;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.MacAddress;

public class LoadBalancerConfig {

    public MacAddress myVirtualMac;
    public Ip4Address myVirtualIp;
    public List<String> servers;

    LoadBalancerConfig( JsonNode node){

        myVirtualMac = MacAddress.valueOf( node.get("myVirtualMac").asText() );
        myVirtualIp = Ip4Address.valueOf( node.get("myVirtualIp").asText() );

        servers = new ArrayList<String>();
        ArrayNode arrayNode = (ArrayNode) node.path("servers");
        arrayNode.forEach(i -> servers.add( i.asText() ));

    }
    
}
