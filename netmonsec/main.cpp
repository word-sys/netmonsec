#include "NetworkMonitor.h"
#include <iostream>
#include <iomanip>
#include <csignal>

using namespace NetMon;

std::shared_ptr<NetworkMonitor> g_monitor;

bool g_running = true;
void signalHandler(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down..." << std::endl;
    g_running = false;
}
void printAlert(const Alert& alert) {
    std::string levelStr;
    switch (alert.level) {
        case AlertLevel::INFO:
            levelStr = "INFO";
            break;
        case AlertLevel::WARNING:
            levelStr = "WARNING";
            break;
        case AlertLevel::CRITICAL:
            levelStr = "CRITICAL";
            break;
    }
    
    auto t = std::chrono::system_clock::to_time_t(alert.timestamp);
    std::tm* tm = std::localtime(&t);
    
    char buffer[80];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm);
    
    std::cout << "[" << buffer << "] " << levelStr << ": " << alert.message << std::endl;
}
int main() {
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    
    g_monitor = std::make_shared<NetworkMonitor>();
    
    if (!g_monitor->initialize()) {
        std::cerr << "Failed to initialize network monitor" << std::endl;
        return 1;
    }
    
    g_monitor->registerAlertCallback([](const Alert& alert) {
        printAlert(alert);
    });
    
    auto interfaces = g_monitor->getNetworkInterfaces();
    
    if (interfaces.empty()) {
        std::cerr << "No network interfaces found" << std::endl;
        return 1;
    }
    
    std::cout << "Available network interfaces:" << std::endl;
    for (size_t i = 0; i < interfaces.size(); ++i) {
        std::cout << i << ": " << interfaces[i].getName() << " - "
                  << interfaces[i].getDescription() << " ("
                  << interfaces[i].getAddress() << ")" << std::endl;
    }
    
    size_t selectedIdx = 0;
    std::cout << "\nSelect interface (0-" << interfaces.size() - 1 << "): ";
    std::cin >> selectedIdx;
    
    if (selectedIdx >= interfaces.size()) {
        std::cerr << "Invalid interface selection" << std::endl;
        return 1;
    }
    
    std::string filter;
    std::cout << "Enter packet filter (leave empty for no filter): ";
    std::cin.ignore();
    std::getline(std::cin, filter);
    
    std::cout << "Starting network monitoring on " << interfaces[selectedIdx].getName() << std::endl;
    
    if (!g_monitor->startMonitoring(interfaces[selectedIdx].getName(), filter)) {
        std::cerr << "Failed to start monitoring" << std::endl;
        return 1;
    }
    
    std::cout << "Network monitoring active. Press Ctrl+C to stop." << std::endl;
    
    // Main loop
    while (g_running) {
        auto alerts = g_monitor->getRecentAlerts(5);
        if (!alerts.empty()) {
            std::cout << "\nRecent alerts:" << std::endl;
            for (const auto& alert : alerts) {
                printAlert(alert);
            }
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        std::cout << "\nCurrent Network Statistics:" << std::endl;
        std::cout << "-------------------------" << std::endl;
        
        auto now = std::chrono::system_clock::now();
        auto now_t = std::chrono::system_clock::to_time_t(now);
        std::tm* now_tm = std::localtime(&now_t);
        
        char time_buffer[80];
        std::strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", now_tm);
        std::cout << "Time: " << time_buffer << std::endl;
        
        const auto& flowStats = g_monitor->getFlowStatistics();
        
        std::cout << "\nTop 5 flows by bandwidth:" << std::endl;
        std::cout << std::left 
                  << std::setw(20) << "Source" 
                  << std::setw(20) << "Destination" 
                  << std::setw(12) << "Protocol" 
                  << std::setw(12) << "Bandwidth" << std::endl;
        
        std::vector<std::pair<FlowKey, FlowStats>> sortedFlows;
        for (const auto& entry : flowStats) {
            sortedFlows.push_back(entry);
        }
        
        std::sort(sortedFlows.begin(), sortedFlows.end(), 
                 [](const auto& a, const auto& b) {
                     return a.second.bytesPerSecond > b.second.bytesPerSecond;
                 });
        
        size_t count = std::min(size_t(5), sortedFlows.size());
        for (size_t i = 0; i < count; ++i) {
            const auto& flow = sortedFlows[i].first;
            const auto& stats = sortedFlows[i].second;
            
            std::string protocol;
            switch (flow.protocol) {
                case IPPROTO_TCP: protocol = "TCP"; break;
                case IPPROTO_UDP: protocol = "UDP"; break;
                case IPPROTO_ICMP: protocol = "ICMP"; break;
                default: protocol = std::to_string(flow.protocol); break;
            }
            
            std::string source = flow.sourceIP + ":" + std::to_string(flow.sourcePort);
            std::string dest = flow.destIP + ":" + std::to_string(flow.destPort);
            
            std::cout << std::left 
                      << std::setw(20) << source 
                      << std::setw(20) << dest 
                      << std::setw(12) << protocol 
                      << std::setw(12) << std::fixed << std::setprecision(2) 
                      << (stats.bytesPerSecond / 1024) << " KB/s" << std::endl;
        }
        
        
        // user interactions
        std::cout << "\nCommands:" << std::endl;
        std::cout << "  q - Quit" << std::endl;
        std::cout << "  a - Show all recent alerts" << std::endl;
        std::cout << "  f - Apply new filter" << std::endl;
        std::cout << "Command: ";
        
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(0, &readfds); 
        
        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 0;
        
        if (select(1, &readfds, nullptr, nullptr, &timeout) > 0) {
            char cmd;
            std::cin >> cmd;
            
            switch (cmd) {
                case 'q':
                    g_running = false;
                    break;
                    
                case 'a':
                    {
                        auto allAlerts = g_monitor->getRecentAlerts(20);
                        std::cout << "\nAll recent alerts:" << std::endl;
                        for (const auto& alert : allAlerts) {
                            printAlert(alert);
                        }
                    }
                    break;
                    
                case 'f':
                    {
                        std::string newFilter;
                        std::cout << "Enter new packet filter: ";
                        std::cin.ignore();
                        std::getline(std::cin, newFilter);
                        
                        g_monitor->stopMonitoring();
                        
                        std::cout << "Restarting monitoring with new filter..." << std::endl;
                        if (!g_monitor->startMonitoring(interfaces[selectedIdx].getName(), newFilter)) {
                            std::cerr << "Failed to restart monitoring" << std::endl;
                            g_running = false;
                        }
                    }
                    break;
            }
        }
    }
    
    g_monitor->stopMonitoring();
    std::cout << "Network monitoring stopped." << std::endl;
    
    return 0;
}