#!/usr/bin/env python2

import os, sys, subprocess, socket, time, threading, random, json, argparse, signal
import SimpleHTTPServer
import SocketServer
import logging

CONTROLLER_IP = "10.0.0.254"
CONTROLLER_MAC = "00:aa:00:00:00:ff"
PORT = 80
LB=True
CPU=False
LATENCY=True
# LATENCY=False
COUNT=0
CLIENT_SLEEP=0.1*128
PREV_BATCH=32 #start with the same N of flows of the controller
BATCH_TRIGGER=True
LATENCY_TRIGGER=True

latencyListGlobal = []
bytes_transferred = 0  # New variable to track data transferred

def myExceptHook(exctype, value, tb):
    logging.exception(exctype)
    logging.exception(value)
    logging.exception(tb)

def sendCpuLoadLoop(args, alive, opened_socket):
    while alive[0]:
        time.sleep(1)
        cmd = 'top -bcn2 -w512 | grep -v grep | grep python | grep %s | tail -1 | awk \'{print $9}\'' % args.serverName
        cpu = subprocess.check_output(cmd, shell=True)
        message = args.serverName + ":cpu:" + str(cpu).split('\n')[0]
        byte_message = message.encode("utf-8")
        try:
            opened_socket.sendto(byte_message, (CONTROLLER_IP, 5005))
        except:
            pass

def sendCpuLoad(args, alive):
    opened_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    thread = threading.Thread(target=sendCpuLoadLoop, args=(args, alive, opened_socket))
    thread.start()
    return (opened_socket, thread)

def cpuLoad(load):
    for i in range(0, load):
        x = random.random()
        x * x ** x

def subtractCount():
    global PREV_BATCH, COUNT, BATCH_TRIGGER
    time.sleep(CLIENT_SLEEP)
    logging.debug("Previous batch: %s, New Batch: %s" % (PREV_BATCH, COUNT))
    PREV_BATCH=COUNT
    COUNT=0
    BATCH_TRIGGER=True

def sendLatencyLoop(args, alive, mySocket):
    global latencyListGlobal
    while alive[0]:
        time.sleep(CLIENT_SLEEP)
        if (len(latencyListGlobal) > 0):
            #format: serverName:latency:<avg latency>:<sum latency>:<max latency>
            message = args.serverName + ":latency:" + str(sum(latencyListGlobal) / len(latencyListGlobal)) + ":" + str(sum(latencyListGlobal)) + ":" + str(max(latencyListGlobal))
            byte_message = message.encode("utf-8")
            try:
                mySocket.sendto(byte_message, (CONTROLLER_IP, 5005))
                latencyListGlobal = [] #reset list
            except:
                pass

def sendLatency(args, alive):
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    thread = threading.Thread(target=sendLatencyLoop, args=(args, alive, mySocket))
    # thread.start()
    return (mySocket, thread)

def sendLatencyOnTriggger(serverName, mySocket):
    global latencyListGlobal
    time.sleep(CLIENT_SLEEP)
    try:
        mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if (len(latencyListGlobal) > 0):
            #format: serverName:latency:<avg latency>:<sum latency>:<max latency>
            message = serverName + ":latency:" + str(sum(latencyListGlobal) / len(latencyListGlobal)) + ":" + str(sum(latencyListGlobal)) + ":" + str(max(latencyListGlobal))
            byte_message = message.encode("utf-8")
            
            # mySocket.connect((CONTROLLER_IP, 5005))
            # mySocket.sendall(byte_message)
            mySocket.sendto(byte_message, (CONTROLLER_IP, 5005))
            latencyListGlobal = [] #reset list
    except:
        pass
    finally:
        mySocket.close()

def sendThroughputLoop(args, alive, mySocket):
    global bytes_transferred
    while alive[0]:
        time.sleep(CLIENT_SLEEP)
        # Calculate throughput (bytes_transferred / elapsed_time)
        throughput_bps = bytes_transferred / CLIENT_SLEEP
        # Convert to desired units (KBps, Mbps, etc.)
        throughput_kbps = throughput_bps / 1024
        # Format the message
        message = args.serverName + ":throughput:" + str(throughput_kbps)
        byte_message = message.encode("utf-8")
        try:
            mySocket.sendto(byte_message, (CONTROLLER_IP, 5005))
        except:
            pass

def sendThroughput(args, alive):
    mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    thread = threading.Thread(target=sendThroughputLoop, args=(args, alive, mySocket))
    thread.start()
    return (mySocket, thread)


def MakeGetHandler(args, mySocket):
    
    class GetHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

        def __init__(self, request, client_address, server):
            self.serverName = args.serverName
            # self.latencyThread = latencyThread
            self.mySocket = mySocket
            self.bytes_transferred = 0  # Initialize bytes_transferred
            SimpleHTTPServer.SimpleHTTPRequestHandler.__init__(self, request, client_address, server)
            # logging.debug("Handler Started")

        def log_message(self, format, *args):
            pass

        def _set_headers(self):
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
        
        def handle_one_request(self):
            global COUNT, BATCH_TRIGGER, LATENCY_TRIGGER
            COUNT += 1
            start = time.time()
            # logging.debug("Request received")

            if BATCH_TRIGGER:
                # logging.debug("Batch Trigger")
                threading.Thread(target=subtractCount).start()

                threading.Thread(target=sendLatencyOnTriggger, args=(self.serverName,mySocket)).start()

                BATCH_TRIGGER=False
                # if LATENCY_TRIGGER:
                #     # self.latencyThread.start()
                #     LATENCY_TRIGGER=False
            
            SimpleHTTPServer.SimpleHTTPRequestHandler.handle_one_request(self)

            end = time.time() - start
            # logging.debug("Request took %s sec" % end)

            if(LATENCY):
                global latencyListGlobal
                latencyListGlobal += [end]
                # logging.debug("Latency List: %s" % ', '.join(map(str, latencyListGlobal)) )

        def do_HEAD(self):
            self._set_headers()

        def do_GET(self):
            self._set_headers()
            self.wfile.write(json.dumps({'server': self.serverName}))

            #artificial load/latency
            if(LB):
                global PREV_BATCH
                sleepBase = 0.005
                sleepIncrement = [0.0004, 0.0008]
                connections = PREV_BATCH
                if (self.serverName == "server1" or self.serverName == "server3"):
                    if (LATENCY):
                        sleep = sleepIncrement[0] * connections + sleepBase
                        # logging.debug("sleeping %s with %s connections" % (sleep, connections))
                        time.sleep(sleep)
                    if (CPU):
                        cpuLoad(800)

                elif (self.serverName == "server2" or self.serverName == "server4"):
                    if (LATENCY):
                        sleep = sleepIncrement[1] * connections + sleepBase
                        # logging.debug("sleeping %s with %s connections" % (sleep, connections))
                        time.sleep(sleep)
                    if (CPU):
                        cpuLoad(1000)
    
    return GetHandler

def main():

    #argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('serverName', type=str, help="Server id")
    parser.add_argument('flows', type=int, default=32, help="Server flows")
    args = parser.parse_args()
    global PREV_BATCH
    PREV_BATCH = args.flows

    #logging
    filename = "/tmp/%s.out" % args.serverName
    logging.basicConfig(filename=filename, encoding='utf-8', level=logging.DEBUG)
    logging.info("Server %s Started" % args.serverName)
    sys.excepthook = myExceptHook

    #inject controller in ARP Table
    os.system('arp -s %s %s' % (CONTROLLER_IP, CONTROLLER_MAC))

    #thread to send cpu load
    if (CPU):
        cpuLoadAlive = [True] #pass variable by reference
        (cpuLoadSocket, cpuLoadThread) = sendCpuLoad(args, cpuLoadAlive)
    
    # if(LATENCY):
    #     latencyAlive = [True] #pass variable by reference
    #     (latencySocket, latencyThread) = sendLatency(args, latencyAlive)
    
    #http server
    # HandlerClass = MakeGetHandler(args, latencyThread)
    mySocket = "no" # mySocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    HandlerClass = MakeGetHandler(args, mySocket)
    httpd = SocketServer.TCPServer(("", PORT), HandlerClass)

    #SIGINT
    def signal_handler(sig, frame):
        logging.info("Signal handler, shutdown server")

        if (CPU):
            logging.debug("Closing cpuLoad socket")
            cpuLoadAlive[0] = False
            cpuLoadThread.join()
            cpuLoadSocket.close()
        
        # if (LATENCY):
        #     logging.debug("Closing latency socket")
        #     latencyAlive[0] = False
        #     if latencyThread.is_alive():
        #         latencyThread.join()
        #     latencySocket.close()

        # mySocket.close()

        logging.debug("Shutdown httpd")
        threading.Thread(target=httpd.shutdown).start()

        logging.debug("Exiting Signal handler")
    
    signal.signal(signal.SIGINT, signal_handler)

    #start http server
    httpd.serve_forever()

    logging.info("Exit")

if __name__ == "__main__":
    main()
