
#pragma once

#include <iostream>
#include <functional>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <fstream>
#include <algorithm>
#include <ctime>
#include <memory>
#include <queue>
#include <condition_variable>

#ifdef _WIN32
    #include <winsock2.h>
    #include <Ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "wpcap.lib")
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <pcap.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <netinet/if_ether.h>
    #include <arpa/inet.h>
    #include <sys/stat.h>
#endif

namespace NetMon {

class PacketCapture;
class PacketAnalyzer;
class AlertManager;
class DataStorage;
class NetworkInterface;

struct Packet {
    std::vector<uint8_t> data;
    size_t length;
    std::chrono::system_clock::time_point timestamp;
    std::string sourceIP;
    std::string destIP;
    uint16_t sourcePort;
    uint16_t destPort;
    uint8_t protocol;
};

struct FlowKey {
    std::string sourceIP;
    std::string destIP;
    uint16_t sourcePort;
    uint16_t destPort;
    uint8_t protocol;

    bool operator==(const FlowKey& other) const {
        return sourceIP == other.sourceIP &&
               destIP == other.destIP &&
               sourcePort == other.sourcePort &&
               destPort == other.destPort &&
               protocol == other.protocol;
    }
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const {
        return std::hash<std::string>()(k.sourceIP) ^
               std::hash<std::string>()(k.destIP) ^
               std::hash<uint16_t>()(k.sourcePort) ^
               std::hash<uint16_t>()(k.destPort) ^
               std::hash<uint8_t>()(k.protocol);
    }
};

struct FlowStats {
    size_t packetCount = 0;
    size_t byteCount = 0;
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastSeen;
    double bytesPerSecond = 0.0;
    double packetsPerSecond = 0.0;
};

enum class AlertLevel {
    INFO,
    WARNING,
    CRITICAL
};

struct Alert {
    AlertLevel level;
    std::string message;
    std::chrono::system_clock::time_point timestamp;
    FlowKey flow;
};

class NetworkInterface {
public:
    NetworkInterface(const std::string& name, const std::string& description, 
                     const std::string& address)
        : name(name), description(description), address(address) {}

    std::string getName() const { return name; }
    std::string getDescription() const { return description; }
    std::string getAddress() const { return address; }

private:
    std::string name;
    std::string description;
    std::string address;
};

template<typename T>
class ThreadSafeQueue {
public:
    void push(T item) {
        std::lock_guard<std::mutex> lock(mutex);
        queue.push(std::move(item));
        cv.notify_one();
    }

    bool pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait_for(lock, std::chrono::milliseconds(100), 
            [this] { return !queue.empty() || !running; });
        
        if (!running && queue.empty()) {
            return false;
        }
        
        if (!queue.empty()) {
            item = std::move(queue.front());
            queue.pop();
            return true;
        }
        return false;
    }

    void stop() {
        std::lock_guard<std::mutex> lock(mutex);
        running = false;
        cv.notify_all();
    }

    void start() {
        std::lock_guard<std::mutex> lock(mutex);
        running = true;
    }

    bool isEmpty() {
        std::lock_guard<std::mutex> lock(mutex);
        return queue.empty();
    }

private:
    std::queue<T> queue;
    std::mutex mutex;
    std::condition_variable cv;
    bool running = true;
};

class PacketCapture {
public:
    PacketCapture();
    ~PacketCapture();

    bool initialize();
    std::vector<NetworkInterface> getNetworkInterfaces();
    bool startCapture(const std::string& interfaceName, const std::string& filter = "");
    void stopCapture();
    
    void setPacketQueue(std::shared_ptr<ThreadSafeQueue<Packet>> queue) {
        packetQueue = queue;
    }

private:
    static void captureThread(PacketCapture* capture);
    static void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    
    pcap_t* handle = nullptr;
    std::thread captureThreadObj;
    std::atomic<bool> running{false};
    std::shared_ptr<ThreadSafeQueue<Packet>> packetQueue;
};

class PacketAnalyzer {
public:
    PacketAnalyzer(std::shared_ptr<AlertManager> alertManager);
    ~PacketAnalyzer();

    void initialize();
    void startAnalysis();
    void stopAnalysis();
    
    void setPacketQueue(std::shared_ptr<ThreadSafeQueue<Packet>> queue) {
        packetQueue = queue;
    }
    
    const std::unordered_map<FlowKey, FlowStats, FlowKeyHash>& getFlowStats() const {
        std::lock_guard<std::mutex> lock(flowStatsMutex);
        return flowStats;
    }

private:
    void analysisThread();
    void analyzePacket(const Packet& packet);
    void updateFlowStats(const Packet& packet);
    void checkForAnomalies(const FlowKey& flowKey, const FlowStats& stats);

    std::thread analysisThreadObj;
    std::atomic<bool> running{false};
    std::shared_ptr<ThreadSafeQueue<Packet>> packetQueue;
    std::shared_ptr<AlertManager> alertManager;
    
    std::unordered_map<FlowKey, FlowStats, FlowKeyHash> flowStats;
    mutable std::mutex flowStatsMutex;
    
    const double HIGH_TRAFFIC_THRESHOLD_BPS = 1000000.0; // 1 Mbps
    const double HIGH_TRAFFIC_THRESHOLD_PPS = 100.0;     // 100 packets per second
};

class AlertManager {
public:
    AlertManager();
    ~AlertManager();

    void initialize();
    void addAlert(AlertLevel level, const std::string& message, const FlowKey& flow);
    std::vector<Alert> getAlerts(size_t count = 10);
    
    void setAlertCallback(std::function<void(const Alert&)> callback) {
        alertCallback = callback;
    }

private:
    std::vector<Alert> alerts;
    std::mutex alertsMutex;
    std::function<void(const Alert&)> alertCallback;
};

class DataStorage {
public:
    DataStorage(const std::string& storageDirectory);
    ~DataStorage();

    void initialize();
    void storePacket(const Packet& packet);
    void storeAlert(const Alert& alert);
    void storePeriodic();

private:
    std::string formatTimestamp(const std::chrono::system_clock::time_point& time);
    std::string createFileName(const std::string& prefix);

    std::string storageDirectory;
    std::mutex storageMutex;
    std::thread periodicThread;
    std::atomic<bool> running{false};
};

class NetworkMonitor {
public:
    NetworkMonitor();
    ~NetworkMonitor();

    bool initialize();
    bool startMonitoring(const std::string& interfaceName, const std::string& filter = "");
    void stopMonitoring();

    std::unordered_map<FlowKey, FlowStats, FlowKeyHash> getFlowStatistics() const {
        return packetAnalyzer->getFlowStats();
    }
    
    std::vector<NetworkInterface> getNetworkInterfaces();
    std::vector<Alert> getRecentAlerts(size_t count = 10);
    
    void registerAlertCallback(std::function<void(const Alert&)> callback);

private:
    std::shared_ptr<PacketCapture> packetCapture;
    std::shared_ptr<PacketAnalyzer> packetAnalyzer;
    std::shared_ptr<AlertManager> alertManager;
    std::shared_ptr<DataStorage> dataStorage;
    std::shared_ptr<ThreadSafeQueue<Packet>> packetQueue;
};

}