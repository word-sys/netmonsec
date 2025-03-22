
#include "NetworkMonitor.h"

namespace NetMon {

PacketCapture::PacketCapture() {}

PacketCapture::~PacketCapture() {
    stopCapture();
}

bool PacketCapture::initialize() {
    #ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    #endif
    return true;
}

std::vector<NetworkInterface> PacketCapture::getNetworkInterfaces() {
    std::vector<NetworkInterface> interfaces;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << std::endl;
        return interfaces;
    }
    
    for (pcap_if_t *dev = alldevs; dev; dev = dev->next) {
        std::string address;
        if (dev->addresses && dev->addresses->addr) {
            char ip[INET_ADDRSTRLEN];
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)dev->addresses->addr;
            inet_ntop(AF_INET, &(ipv4->sin_addr), ip, INET_ADDRSTRLEN);
            address = ip;
        }
        
        interfaces.emplace_back(
            dev->name, 
            dev->description ? dev->description : "No description available",
            address
        );
    }
    
    pcap_freealldevs(alldevs);
    return interfaces;
}

bool PacketCapture::startCapture(const std::string& interfaceName, const std::string& filter) {
    if (running) {
        return false;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    
    handle = pcap_open_live(interfaceName.c_str(), 65536, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return false;
    }
    
    if (!filter.empty()) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
            pcap_close(handle);
            handle = nullptr;
            return false;
        }
        
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
            pcap_freecode(&fp);
            pcap_close(handle);
            handle = nullptr;
            return false;
        }
        
        pcap_freecode(&fp);
    }
    
    running = true;
    captureThreadObj = std::thread(captureThread, this);
    
    return true;
}

void PacketCapture::stopCapture() {
    if (!running) {
        return;
    }
    
    running = false;
    
    if (captureThreadObj.joinable()) {
        captureThreadObj.join();
    }
    
    if (handle) {
        pcap_close(handle);
        handle = nullptr;
    }
}

void PacketCapture::captureThread(PacketCapture* capture) {
    pcap_loop(capture->handle, 0, packetHandler, reinterpret_cast<u_char*>(capture));
}

void PacketCapture::packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData) {
    PacketCapture* capture = reinterpret_cast<PacketCapture*>(userData);
    
    if (!capture->running || !capture->packetQueue) {
        return;
    }
    
    const struct ether_header* ethHeader = reinterpret_cast<const struct ether_header*>(packetData);
    
    // IP packet
    if (ntohs(ethHeader->ether_type) != ETHERTYPE_IP) {
        return;
    }
    
    const struct ip* ipHeader = reinterpret_cast<const struct ip*>(packetData + sizeof(struct ether_header));
    
    Packet packet;
    packet.length = pkthdr->len;
    packet.timestamp = std::chrono::system_clock::now();
    packet.data.assign(packetData, packetData + pkthdr->len);
    
    // IP addresses
    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIP, INET_ADDRSTRLEN);
    
    packet.sourceIP = sourceIP;
    packet.destIP = destIP;
    packet.protocol = ipHeader->ip_p;
    
    // TCP/UDP
    if (ipHeader->ip_p == IPPROTO_TCP) {
        const struct tcphdr* tcpHeader = reinterpret_cast<const struct tcphdr*>(
            packetData + sizeof(struct ether_header) + ipHeader->ip_hl * 4);
        packet.sourcePort = ntohs(tcpHeader->th_sport);
        packet.destPort = ntohs(tcpHeader->th_dport);
    }
    else if (ipHeader->ip_p == IPPROTO_UDP) {
        const struct udphdr* udpHeader = reinterpret_cast<const struct udphdr*>(
            packetData + sizeof(struct ether_header) + ipHeader->ip_hl * 4);
        packet.sourcePort = ntohs(udpHeader->uh_sport);
        packet.destPort = ntohs(udpHeader->uh_dport);
    }
    else {
        packet.sourcePort = 0;
        packet.destPort = 0;
    }
    
    capture->packetQueue->push(std::move(packet));
}

PacketAnalyzer::PacketAnalyzer(std::shared_ptr<AlertManager> alertManager)
    : alertManager(alertManager) {}

PacketAnalyzer::~PacketAnalyzer() {
    stopAnalysis();
}

void PacketAnalyzer::initialize() {
    // Initialize any analyzer-specific resources
}

void PacketAnalyzer::startAnalysis() {
    if (running) {
        return;
    }
    
    running = true;
    analysisThreadObj = std::thread(&PacketAnalyzer::analysisThread, this);
}

void PacketAnalyzer::stopAnalysis() {
    if (!running) {
        return;
    }
    
    running = false;
    
    if (analysisThreadObj.joinable()) {
        analysisThreadObj.join();
    }
}

void PacketAnalyzer::analysisThread() {
    Packet packet;
    
    while (running) {
        if (packetQueue && packetQueue->pop(packet)) {
            analyzePacket(packet);
        }
    }
}

void PacketAnalyzer::analyzePacket(const Packet& packet) {
    updateFlowStats(packet);
    
    // Additional packet analysis logic can be added here
    // For example:
    // - Protocol-specific analysis
    // - Deep packet inspection
    // - Signature matching
    // - Heuristic analysis
}

void PacketAnalyzer::updateFlowStats(const Packet& packet) {
    FlowKey flowKey{
        packet.sourceIP,
        packet.destIP,
        packet.sourcePort,
        packet.destPort,
        packet.protocol
    };
    
    std::lock_guard<std::mutex> lock(flowStatsMutex);
    
    auto& stats = flowStats[flowKey];
    auto now = std::chrono::system_clock::now();
    
    if (stats.packetCount == 0) {
        // This is a new flow
        stats.firstSeen = now;
    }
    
    stats.packetCount++;
    stats.byteCount += packet.length;
    
    if (stats.packetCount > 1) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
            now - stats.firstSeen).count();
        
        if (duration > 0) {
            stats.bytesPerSecond = static_cast<double>(stats.byteCount) / duration;
            stats.packetsPerSecond = static_cast<double>(stats.packetCount) / duration;
        }
    }
    
    stats.lastSeen = now;
    
    checkForAnomalies(flowKey, stats);
}

void PacketAnalyzer::checkForAnomalies(const FlowKey& flowKey, const FlowStats& stats) {
    if (stats.bytesPerSecond > HIGH_TRAFFIC_THRESHOLD_BPS) {
        std::string message = "High traffic volume detected: " + 
                             std::to_string(static_cast<int>(stats.bytesPerSecond / 1000)) + 
                             " KB/s from " + flowKey.sourceIP + ":" + 
                             std::to_string(flowKey.sourcePort) + " to " + 
                             flowKey.destIP + ":" + std::to_string(flowKey.destPort);
        
        alertManager->addAlert(AlertLevel::WARNING, message, flowKey);
    }
    
    if (stats.packetsPerSecond > HIGH_TRAFFIC_THRESHOLD_PPS) {
        std::string message = "High packet rate detected: " + 
                             std::to_string(static_cast<int>(stats.packetsPerSecond)) + 
                             " packets/s from " + flowKey.sourceIP + ":" + 
                             std::to_string(flowKey.sourcePort) + " to " + 
                             flowKey.destIP + ":" + std::to_string(flowKey.destPort);
        
        alertManager->addAlert(AlertLevel::WARNING, message, flowKey);
    }
    
}

AlertManager::AlertManager() {}

AlertManager::~AlertManager() {}

void AlertManager::initialize() {
    // Initialize alert management system
}

void AlertManager::addAlert(AlertLevel level, const std::string& message, const FlowKey& flow) {
    Alert alert{
        level,
        message,
        std::chrono::system_clock::now(),
        flow
    };
    
    {
        std::lock_guard<std::mutex> lock(alertsMutex);
        alerts.push_back(alert);
        
        if (alerts.size() > 1000) {
            alerts.erase(alerts.begin());
        }
    }
    
    if (alertCallback) {
        alertCallback(alert);
    }
}

std::vector<Alert> AlertManager::getAlerts(size_t count) {
    std::lock_guard<std::mutex> lock(alertsMutex);
    
    std::vector<Alert> result;
    auto startIdx = alerts.size() > count ? alerts.size() - count : 0;
    
    for (size_t i = startIdx; i < alerts.size(); ++i) {
        result.push_back(alerts[i]);
    }
    
    return result;
}

DataStorage::DataStorage(const std::string& storageDirectory) 
    : storageDirectory(storageDirectory) {}

DataStorage::~DataStorage() {
    running = false;
    if (periodicThread.joinable()) {
        periodicThread.join();
    }
}

void DataStorage::initialize() {
    #ifdef _WIN32
    CreateDirectoryA(storageDirectory.c_str(), NULL);
    #else
    mkdir(storageDirectory.c_str(), 0755);
    #endif
    
    running = true;
    periodicThread = std::thread([this]() {
        while (running) {
            storePeriodic();
            std::this_thread::sleep_for(std::chrono::minutes(5));
        }
    });
}

void DataStorage::storePacket(const Packet& packet) {
    std::lock_guard<std::mutex> lock(storageMutex);
    
    std::string filename = createFileName("packets");
    std::ofstream file(filename, std::ios::app);
    
    if (file.is_open()) {
        file << formatTimestamp(packet.timestamp) << ","
             << packet.sourceIP << "," 
             << packet.destIP << ","
             << packet.sourcePort << ","
             << packet.destPort << ","
             << static_cast<int>(packet.protocol) << ","
             << packet.length << std::endl;
        file.close();
    }
}

void DataStorage::storeAlert(const Alert& alert) {
    std::lock_guard<std::mutex> lock(storageMutex);
    
    std::string filename = createFileName("alerts");
    std::ofstream file(filename, std::ios::app);
    
    if (file.is_open()) {
        file << formatTimestamp(alert.timestamp) << ","
             << static_cast<int>(alert.level) << ","
             << alert.message << ","
             << alert.flow.sourceIP << ","
             << alert.flow.destIP << ","
             << alert.flow.sourcePort << ","
             << alert.flow.destPort << ","
             << static_cast<int>(alert.flow.protocol) << std::endl;
        file.close();
    }
}

void DataStorage::storePeriodic() {
    // Perform any periodic storage tasks
    // This could include aggregating statistics, cleaning up old data, etc.
}

std::string DataStorage::formatTimestamp(const std::chrono::system_clock::time_point& time) {
    auto t = std::chrono::system_clock::to_time_t(time);
    std::tm* tm = std::localtime(&t);
    
    char buffer[80];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm);
    return buffer;
}

std::string DataStorage::createFileName(const std::string& prefix) {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm* tm = std::localtime(&t);
    
    char buffer[80];
    std::strftime(buffer, sizeof(buffer), "%Y%m%d", tm);
    
    return storageDirectory + "/" + prefix + "_" + buffer + ".csv";
}

NetworkMonitor::NetworkMonitor() {
    packetQueue = std::make_shared<ThreadSafeQueue<Packet>>();
    alertManager = std::make_shared<AlertManager>();
    packetCapture = std::make_shared<PacketCapture>();
    packetAnalyzer = std::make_shared<PacketAnalyzer>(alertManager);
    dataStorage = std::make_shared<DataStorage>("./network_data");
    
    packetCapture->setPacketQueue(packetQueue);
    packetAnalyzer->setPacketQueue(packetQueue);
}

NetworkMonitor::~NetworkMonitor() {
    stopMonitoring();
}

bool NetworkMonitor::initialize() {
    bool success = true;
    
    success &= packetCapture->initialize();
    packetAnalyzer->initialize();
    alertManager->initialize();
    dataStorage->initialize();
    
    alertManager->setAlertCallback([this](const Alert& alert) {
        dataStorage->storeAlert(alert);
    });
    
    return success;
}

bool NetworkMonitor::startMonitoring(const std::string& interfaceName, const std::string& filter) {
    if (!packetCapture->startCapture(interfaceName, filter)) {
        return false;
    }
    
    packetAnalyzer->startAnalysis();
    return true;
}

void NetworkMonitor::stopMonitoring() {
    packetCapture->stopCapture();
    packetAnalyzer->stopAnalysis();
}

std::vector<NetworkInterface> NetworkMonitor::getNetworkInterfaces() {
    return packetCapture->getNetworkInterfaces();
}

std::vector<Alert> NetworkMonitor::getRecentAlerts(size_t count) {
    return alertManager->getAlerts(count);
}

void NetworkMonitor::registerAlertCallback(std::function<void(const Alert&)> callback) {
    alertManager->setAlertCallback(callback);
}

}