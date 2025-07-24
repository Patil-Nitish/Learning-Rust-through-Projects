use pcap::{Device, Capture};
use std::io::{self, Write,stdin};
use std::time::{Duration,Instant};
use etherparse::{SlicedPacket,self};
use colored::*;


#[derive(Default)]
struct PacketStats{
    total:usize,
    ipv4:usize,
    ipv6:usize,
    tcp:usize,
    udp:usize,
    icmpv4:usize,
    icmpv6:usize,
    malformed:usize,
}


fn main() {
    println!("📡 PacketSpy – Device Scanner");

    let devices = Device::list().expect("Failed to list devices");

    for (i, device) in devices.iter().enumerate() {
        println!(
            "{}. {} ({:?})",
            i + 1,
            device.name,
            device.desc.as_deref()
        );
    }

    print!("Select a device number: ");
    io::stdout().flush().unwrap();

    let mut selection = String::new();
    io::stdin().read_line(&mut selection).unwrap();
    let selected_index: usize = selection.trim().parse().expect("Invalid number");

    if selected_index == 0 || selected_index > devices.len() {
        eprintln!("Invalid device number.");
        return;
    }

    let selected_device = &devices[selected_index - 1];

    println!("🧪 Opening device: {}", selected_device.name);

    let mut capture = Capture::from_device(selected_device.name.as_str())
        .unwrap()
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .open()
        .expect("Failed to open device for capture");

    let mut input=String::new();
    println!("Please enter duration in milliseconds: ");
    stdin().read_line(&mut input).expect("Failed to read input");
    let duration_millis:u64=input.trim().parse().unwrap_or(3000);
    let  duration=Duration::from_millis(duration_millis);
    let start_time=Instant::now();
    println!("📡 Capturing packets for {} miliseconds...", duration.as_millis());

    let mut stats=PacketStats{
        ..Default::default()
    };

    while start_time.elapsed()<duration{
        match capture.next_packet(){
            Ok(packet)=>{
                stats.total += 1;
                println!("📦 Packet captured: {} bytes", packet.data.len());
                
                match SlicedPacket::from_ethernet(&packet.data){
                    Ok(value)=>{
                        if let Some(ip)=value.ip{
                            match ip{
                                etherparse::InternetSlice::Ipv4(header,_)=>{
                                    stats.ipv4 += 1;
                                    print!(
                                        "🌐 IPv4: {} -> {} ",
                                        header.source_addr(),
                                        header.destination_addr()
                                    );
                                }

                                etherparse::InternetSlice::Ipv6(header,_)=>{
                                    stats.ipv6 += 1;
                                    print!(
                                        "🌐 IPv6: {} -> {} ",
                                        header.source_addr(),
                                        header.destination_addr()
                                    );
                                }

                            }

                            match value.transport{
                                Some(etherparse::TransportSlice::Tcp(tcp))=>{
                                    stats.tcp += 1;
                                    println!(
                                        "🚚 TCP: {} -> {}",
                                        tcp.source_port(),
                                        tcp.destination_port()
                                    );
                                }
                                Some(etherparse::TransportSlice::Udp(udp))=>{
                                    stats.udp += 1;
                                    println!(
                                        "🚚 UDP: {} -> {}",
                                        udp.source_port(),
                                        udp.destination_port()
                                    );
                                }
                                Some(etherparse::TransportSlice::Icmpv4(icmp)) => {
                                    stats.icmpv4 += 1;
                                    println!("  ICMPv4 packet: Type: ({:?})", 
                                             icmp.icmp_type());
                                },
                                Some(etherparse::TransportSlice::Icmpv6(icmp)) => {
                                    stats.icmpv6 += 1;
                                    println!("  ICMPv6 packet: Type: ({:?})", 
                                             icmp.icmp_type());
                                },
                                Some(etherparse::TransportSlice::Unknown(unknown)) => {
                                    println!("🚚 Unknown transport layer: {:?}", unknown);
                                }

                                None=>{
                                    stats.malformed += 1;
                                    println!("🚚 No transport layer information");
                                }
                            }
                        }
                        else{
                            stats.malformed += 1;
                            println!(" 🌐 No IP layer information");
                        }
                    }
                    Err(e)=>{
                        stats.malformed += 1;
                        eprintln!("Error parsing packet: {}", e);
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Timeout expired, continue capturing
                continue;
            }
            Err(e) => {
                eprintln!("Error capturing packet: {}", e);
                break;
            }
        }

    }

    
    println!("\n{}", "📊 Capture Summary".bold().underline().blue());
    println!("{}", "────────────────────────────".blue());
    println!("{} {}", "📦 Total Packets:      ".cyan(), stats.total.to_string().bold());
    println!("{} {}", "🌐 IPv4 Packets:       ".green(), stats.ipv4.to_string().bold());
    println!("{} {}", "🌍 IPv6 Packets:       ".green(), stats.ipv6.to_string().bold());
    println!("{} {}", "🔁 TCP Packets:        ".yellow(), stats.tcp.to_string().bold());
    println!("{} {}", "📨 UDP Packets:        ".magenta(), stats.udp.to_string().bold());
    println!("{} {}", "📢 ICMPv4 Packets:     ".bright_blue(), stats.icmpv4.to_string().bold());
    println!("{} {}", "📢 ICMPv6 Packets:     ".bright_blue(), stats.icmpv6.to_string().bold());
    println!("{} {}", "❗ Malformed Packets:  ".red(), stats.malformed.to_string().bold());
    println!("{}", "────────────────────────────\n".blue());


    println!("{}", "📥 Press Enter to exit...".bold());
    let _ = io::stdout().flush();
    let _ = io::stdin().read_line(&mut String::new());
}
